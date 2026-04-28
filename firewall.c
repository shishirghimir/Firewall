/*
 * ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗
 * ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║
 * █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║
 * ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║
 * ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
 * ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
 *
 * FireWall - A Lightweight Packet Filtering Firewall in C
 * Author  : Shishir
 * License : MIT
 *
 * Features:
 *   - Live packet capture via libpcap
 *   - Block by IP, port, protocol (TCP/UDP/ICMP)
 *   - CIDR subnet blocking
 *   - Rate limiting (per-IP packet/sec threshold)
 *   - Logging to file with timestamps
 *   - Interactive CLI rule manager
 *   - Statistics dashboard
 *   - Config file persistence (JSON-like format)
 *   - Graceful shutdown with Ctrl+C
 */

#include "firewall.h"

/* ─── Globals ────────────────────────────────────────────────── */
FirewallRule  rules[MAX_RULES];
int           ruleCount    = 0;
pcap_t       *handle       = NULL;
FirewallStats stats         = {0};
RateEntry     rateTable[MAX_RATE_ENTRIES];
int           rateCount    = 0;
FILE         *logFile       = NULL;
volatile int  running       = 1;

pthread_mutex_t ruleMutex  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t statMutex  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rateMutex  = PTHREAD_MUTEX_INITIALIZER;

/* ─── Signal handler ─────────────────────────────────────────── */
void handle_signal(int sig) {
    (void)sig;
    running = 0;
    if (handle) pcap_breakloop(handle);
}

/* ─── Logging ────────────────────────────────────────────────── */
void fw_log(LogLevel level, const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    const char *lvlstr[] = { "INFO ", "WARN ", "BLOCK", "ERROR", "STATS" };
    const char *colors[] = { COLOR_CYAN, COLOR_YELLOW, COLOR_RED, COLOR_RESET, COLOR_GREEN };

    va_list args;
    /* Console */
    va_start(args, fmt);
    fprintf(stderr, "%s[%s] [%s] ", colors[level], timebuf, lvlstr[level]);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "%s\n", COLOR_RESET);
    va_end(args);

    /* File */
    if (logFile) {
        va_start(args, fmt);
        fprintf(logFile, "[%s] [%s] ", timebuf, lvlstr[level]);
        vfprintf(logFile, fmt, args);
        fprintf(logFile, "\n");
        va_end(args);
        fflush(logFile);
    }
}

/* ─── CIDR matching ──────────────────────────────────────────── */
int cidr_match(const char *cidr, uint32_t pkt_ip) {
    char base[MAX_IP_LENGTH];
    int  prefix = 32;
    const char *slash = strchr(cidr, '/');
    if (slash) {
        size_t len = (size_t)(slash - cidr);
        if (len >= MAX_IP_LENGTH) return 0;
        strncpy(base, cidr, len);
        base[len] = '\0';
        prefix = atoi(slash + 1);
    } else {
        strncpy(base, cidr, MAX_IP_LENGTH - 1);
        base[MAX_IP_LENGTH - 1] = '\0';
    }
    struct in_addr addr;
    if (inet_aton(base, &addr) == 0) return 0;
    uint32_t mask    = prefix ? htonl(~((1u << (32 - prefix)) - 1)) : 0;
    uint32_t net_ip  = ntohl(addr.s_addr);
    uint32_t net_pkt = ntohl(pkt_ip);
    return (net_ip & ntohl(mask)) == (net_pkt & ntohl(mask));
}

/* ─── Rate limiter ───────────────────────────────────────────── */
int rate_check(uint32_t src_ip, int pps_limit) {
    if (pps_limit <= 0) return 0; /* disabled */
    time_t now = time(NULL);
    pthread_mutex_lock(&rateMutex);

    for (int i = 0; i < rateCount; i++) {
        if (rateTable[i].ip == src_ip) {
            if (now - rateTable[i].window_start >= 1) {
                rateTable[i].window_start = now;
                rateTable[i].count = 1;
                pthread_mutex_unlock(&rateMutex);
                return 0;
            }
            rateTable[i].count++;
            int blocked = (rateTable[i].count > pps_limit);
            pthread_mutex_unlock(&rateMutex);
            return blocked;
        }
    }
    /* New entry */
    if (rateCount < MAX_RATE_ENTRIES) {
        rateTable[rateCount].ip           = src_ip;
        rateTable[rateCount].window_start = now;
        rateTable[rateCount].count        = 1;
        rateCount++;
    }
    pthread_mutex_unlock(&rateMutex);
    return 0;
}

/* ─── Rule matching ──────────────────────────────────────────── */
int matches_rule(const FirewallRule *r, const char *proto,
                 uint32_t src_ip, uint32_t dst_ip,
                 int src_port, int dst_port) {

    /* Protocol check */
    if (r->protocol[0] != '\0' &&
        strcasecmp(r->protocol, "any") != 0 &&
        strcasecmp(r->protocol, proto)  != 0) return 0;

    /* Source IP / CIDR */
    if (r->srcIP[0] != '\0' &&
        strcmp(r->srcIP, "any") != 0) {
        struct in_addr a;
        if (strchr(r->srcIP, '/')) {
            if (!cidr_match(r->srcIP, src_ip)) return 0;
        } else if (inet_aton(r->srcIP, &a)) {
            if (a.s_addr != src_ip) return 0;
        }
    }

    /* Destination IP / CIDR */
    if (r->dstIP[0] != '\0' &&
        strcmp(r->dstIP, "any") != 0) {
        struct in_addr a;
        if (strchr(r->dstIP, '/')) {
            if (!cidr_match(r->dstIP, dst_ip)) return 0;
        } else if (inet_aton(r->dstIP, &a)) {
            if (a.s_addr != dst_ip) return 0;
        }
    }

    /* Src port */
    if (r->srcPort > 0 && r->srcPort != src_port) return 0;

    /* Dst port */
    if (r->dstPort > 0 && r->dstPort != dst_port) return 0;

    return 1;
}

/* ─── Packet callback ────────────────────────────────────────── */
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet) {
    (void)args;
    if (!running) return;

    pthread_mutex_lock(&statMutex);
    stats.total_packets++;
    stats.total_bytes += header->len;
    pthread_mutex_unlock(&statMutex);

    /* Skip Ethernet header (14 bytes) */
    if (header->caplen < 14 + sizeof(struct ip)) return;
    const struct ip *iph = (const struct ip *)(packet + 14);
    int ip_hlen = iph->ip_hl * 4;
    if (ip_hlen < 20) return;

    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst_ip, dst_str, sizeof(dst_str));

    char proto_str[16] = "OTHER";
    int  src_port = 0, dst_port = 0;

    if (iph->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcph =
            (const struct tcphdr *)((const u_char *)iph + ip_hlen);
        if ((const u_char *)tcph + sizeof(struct tcphdr) <= packet + header->caplen) {
            src_port = ntohs(tcph->th_sport);
            dst_port = ntohs(tcph->th_dport);
        }
        strcpy(proto_str, "TCP");
    } else if (iph->ip_p == IPPROTO_UDP) {
        const struct udphdr *udph =
            (const struct udphdr *)((const u_char *)iph + ip_hlen);
        if ((const u_char *)udph + sizeof(struct udphdr) <= packet + header->caplen) {
            src_port = ntohs(udph->uh_sport);
            dst_port = ntohs(udph->uh_dport);
        }
        strcpy(proto_str, "UDP");
    } else if (iph->ip_p == IPPROTO_ICMP) {
        strcpy(proto_str, "ICMP");
    }

    /* Evaluate rules */
    pthread_mutex_lock(&ruleMutex);
    int blocked = 0;
    for (int i = 0; i < ruleCount; i++) {
        if (!rules[i].enabled) continue;
        if (rules[i].action == ACTION_ALLOW &&
            matches_rule(&rules[i], proto_str, src_ip, dst_ip, src_port, dst_port)) {
            blocked = 0;
            break; /* explicit allow wins */
        }
        if (rules[i].action == ACTION_BLOCK &&
            matches_rule(&rules[i], proto_str, src_ip, dst_ip, src_port, dst_port)) {
            blocked = 1;
            pthread_mutex_lock(&statMutex);
            stats.blocked_packets++;
            stats.rule_hits[i]++;
            pthread_mutex_unlock(&statMutex);
            fw_log(LOG_BLOCK, "BLOCKED %s %s:%d -> %s:%d (rule #%d: %s)",
                   proto_str, src_str, src_port, dst_str, dst_port, i + 1,
                   rules[i].comment[0] ? rules[i].comment : "no comment");
            break;
        }
    }
    pthread_mutex_unlock(&ruleMutex);

    /* Rate limit check */
    if (!blocked) {
        for (int i = 0; i < ruleCount; i++) {
            if (!rules[i].enabled || rules[i].rate_limit <= 0) continue;
            if (matches_rule(&rules[i], proto_str, src_ip, dst_ip, src_port, dst_port)) {
                if (rate_check(src_ip, rules[i].rate_limit)) {
                    pthread_mutex_lock(&statMutex);
                    stats.rate_limited++;
                    pthread_mutex_unlock(&statMutex);
                    fw_log(LOG_WARN, "RATE-LIMITED %s %s:%d (>%d pps)",
                           proto_str, src_str, src_port, rules[i].rate_limit);
                    blocked = 1;
                    break;
                }
            }
        }
    }

    if (!blocked) {
        pthread_mutex_lock(&statMutex);
        stats.allowed_packets++;
        pthread_mutex_unlock(&statMutex);
    }
}

/* ─── Config persistence ─────────────────────────────────────── */
void save_rules(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) { fw_log(LOG_ERROR, "Cannot write config: %s", path); return; }
    fprintf(f, "# FireWall config — DO NOT EDIT MANUALLY\n");
    pthread_mutex_lock(&ruleMutex);
    for (int i = 0; i < ruleCount; i++) {
        const FirewallRule *r = &rules[i];
        fprintf(f, "RULE action=%s proto=%s src=%s srcport=%d dst=%s dstport=%d "
                   "rate=%d enabled=%d comment=%s\n",
                r->action == ACTION_BLOCK ? "BLOCK" : "ALLOW",
                r->protocol[0] ? r->protocol : "any",
                r->srcIP[0]    ? r->srcIP    : "any",
                r->srcPort,
                r->dstIP[0]    ? r->dstIP    : "any",
                r->dstPort,
                r->rate_limit,
                r->enabled,
                r->comment[0]  ? r->comment  : "-");
    }
    pthread_mutex_unlock(&ruleMutex);
    fclose(f);
    fw_log(LOG_INFO, "Rules saved to %s", path);
}

void load_rules(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fw_log(LOG_WARN, "No config file at %s (starting fresh)", path); return; }
    char line[512];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char act[8], proto[16], src[32], dst[32], comment[64];
        int srcport = 0, dstport = 0, rate = 0, enabled = 1;
        if (sscanf(line, "RULE action=%7s proto=%15s src=%31s srcport=%d dst=%31s dstport=%d "
                          "rate=%d enabled=%d comment=%63[^\n]",
                   act, proto, src, &srcport, dst, &dstport, &rate, &enabled, comment) >= 8) {
            if (ruleCount >= MAX_RULES) break;
            FirewallRule *r = &rules[ruleCount];
            r->action = (strcmp(act, "BLOCK") == 0) ? ACTION_BLOCK : ACTION_ALLOW;
            strncpy(r->protocol, strcmp(proto, "any") == 0 ? "" : proto, sizeof(r->protocol) - 1);
            strncpy(r->srcIP,    strcmp(src,   "any") == 0 ? "" : src,   sizeof(r->srcIP)    - 1);
            strncpy(r->dstIP,    strcmp(dst,   "any") == 0 ? "" : dst,   sizeof(r->dstIP)    - 1);
            strncpy(r->comment,  strcmp(comment, "-") == 0 ? "" : comment, sizeof(r->comment) - 1);
            r->srcPort   = srcport;
            r->dstPort   = dstport;
            r->rate_limit = rate;
            r->enabled   = enabled;
            ruleCount++;
            loaded++;
        }
    }
    fclose(f);
    fw_log(LOG_INFO, "Loaded %d rule(s) from %s", loaded, path);
}

/* ─── CLI helpers ────────────────────────────────────────────── */
static void print_banner(void) {
    printf(COLOR_CYAN
           "\n ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗\n"
           " ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║\n"
           " █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║\n"
           " ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║\n"
           " ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗\n"
           " ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝\n"
           COLOR_RESET
           "  Lightweight Packet-Filtering Firewall  |  Author: Shishir\n\n");
}

static void print_menu(void) {
    printf(COLOR_BOLD
           "\n┌─────────────────── FIREWALL MENU ───────────────────┐\n"
           "│  1) Add rule          2) List rules                 │\n"
           "│  3) Delete rule       4) Toggle rule on/off         │\n"
           "│  5) Show statistics   6) Save rules                 │\n"
           "│  7) Start capture     8) Set log file               │\n"
           "│  0) Exit                                            │\n"
           "└─────────────────────────────────────────────────────┘\n"
           COLOR_RESET);
}

static void print_rules(void) {
    pthread_mutex_lock(&ruleMutex);
    if (ruleCount == 0) {
        printf("  (no rules defined)\n");
        pthread_mutex_unlock(&ruleMutex);
        return;
    }
    printf(COLOR_BOLD
           "\n  %-3s %-6s %-8s %-18s %-6s %-18s %-6s %-5s %-5s  %s\n"
           COLOR_RESET,
           "#", "ACT", "PROTO", "SRC IP/CIDR", "SPORT",
           "DST IP/CIDR", "DPORT", "RATE", "ON?", "COMMENT");
    printf("  %s\n", "─────────────────────────────────────────────────────────────────────────────────");

    for (int i = 0; i < ruleCount; i++) {
        const FirewallRule *r = &rules[i];
        const char *actcolor = (r->action == ACTION_BLOCK) ? COLOR_RED : COLOR_GREEN;
        printf("  %s%-3d %-6s%s %-8s %-18s %-6d %-18s %-6d %-5d %-5s  %s\n",
               actcolor,
               i + 1,
               r->action == ACTION_BLOCK ? "BLOCK" : "ALLOW",
               COLOR_RESET,
               r->protocol[0] ? r->protocol : "any",
               r->srcIP[0]    ? r->srcIP    : "any",
               r->srcPort,
               r->dstIP[0]    ? r->dstIP    : "any",
               r->dstPort,
               r->rate_limit,
               r->enabled ? COLOR_GREEN "YES" COLOR_RESET : COLOR_RED "NO" COLOR_RESET,
               r->comment[0]  ? r->comment  : "-");
    }
    pthread_mutex_unlock(&ruleMutex);
}

static void print_stats(void) {
    pthread_mutex_lock(&statMutex);
    printf(COLOR_BOLD "\n  ── Statistics ──────────────────────────────\n" COLOR_RESET);
    printf("  Total packets   : %lu\n", stats.total_packets);
    printf("  Total bytes     : %lu (%.2f MB)\n",
           stats.total_bytes, (double)stats.total_bytes / (1024 * 1024));
    printf("  Allowed         : " COLOR_GREEN "%lu" COLOR_RESET "\n", stats.allowed_packets);
    printf("  Blocked         : " COLOR_RED   "%lu" COLOR_RESET "\n", stats.blocked_packets);
    printf("  Rate-limited    : " COLOR_YELLOW "%lu" COLOR_RESET "\n", stats.rate_limited);
    printf("  Rule hits       :\n");
    for (int i = 0; i < ruleCount; i++) {
        if (stats.rule_hits[i])
            printf("    Rule #%d : %lu hits\n", i + 1, stats.rule_hits[i]);
    }
    printf(COLOR_BOLD "  ────────────────────────────────────────────\n" COLOR_RESET);
    pthread_mutex_unlock(&statMutex);
}

/* ─── Add rule interactively ─────────────────────────────────── */
static void add_rule_interactive(void) {
    if (ruleCount >= MAX_RULES) {
        printf(COLOR_RED "  Max rules reached (%d).\n" COLOR_RESET, MAX_RULES);
        return;
    }
    FirewallRule r;
    memset(&r, 0, sizeof(r));
    char input[128];

    printf("  Action  [block/allow]: "); fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    r.action = (strncasecmp(input, "block", 5) == 0) ? ACTION_BLOCK : ACTION_ALLOW;

    printf("  Protocol [tcp/udp/icmp/any]: "); fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input, "\n")] = '\0';
    if (strcasecmp(input, "any") != 0)
        strncpy(r.protocol, input, sizeof(r.protocol) - 1);

    printf("  Src IP/CIDR [or 'any']: "); fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input, "\n")] = '\0';
    if (strcasecmp(input, "any") != 0)
        strncpy(r.srcIP, input, sizeof(r.srcIP) - 1);

    printf("  Src Port [0=any]: "); fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    r.srcPort = atoi(input);

    printf("  Dst IP/CIDR [or 'any']: "); fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input, "\n")] = '\0';
    if (strcasecmp(input, "any") != 0)
        strncpy(r.dstIP, input, sizeof(r.dstIP) - 1);

    printf("  Dst Port [0=any]: "); fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    r.dstPort = atoi(input);

    printf("  Rate limit pkt/s [0=off]: "); fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    r.rate_limit = atoi(input);

    printf("  Comment (optional): "); fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input, "\n")] = '\0';
    strncpy(r.comment, input, sizeof(r.comment) - 1);

    r.enabled = 1;
    pthread_mutex_lock(&ruleMutex);
    rules[ruleCount++] = r;
    pthread_mutex_unlock(&ruleMutex);
    fw_log(LOG_INFO, "Rule #%d added: %s %s src=%s:%d dst=%s:%d rate=%d",
           ruleCount,
           r.action == ACTION_BLOCK ? "BLOCK" : "ALLOW",
           r.protocol[0] ? r.protocol : "any",
           r.srcIP[0]    ? r.srcIP    : "any", r.srcPort,
           r.dstIP[0]    ? r.dstIP    : "any", r.dstPort,
           r.rate_limit);
}

/* ─── Capture thread ─────────────────────────────────────────── */
typedef struct { char iface[64]; char filter[256]; } CaptureArgs;

void *capture_thread(void *arg) {
    CaptureArgs *ca = (CaptureArgs *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(ca->iface, SNAP_LEN, 1, 1000, errbuf);
    if (!handle) { fw_log(LOG_ERROR, "pcap_open_live: %s", errbuf); free(ca); return NULL; }

    if (ca->filter[0]) {
        struct bpf_program fp;
        bpf_u_int32 net, mask;
        pcap_lookupnet(ca->iface, &net, &mask, errbuf);
        if (pcap_compile(handle, &fp, ca->filter, 0, net) == -1 ||
            pcap_setfilter(handle, &fp) == -1) {
            fw_log(LOG_WARN, "BPF filter error: %s — capturing all", pcap_geterr(handle));
        }
        pcap_freecode(&fp);
    }

    /* Only Ethernet (link type 1) */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fw_log(LOG_WARN, "Non-Ethernet link type — results may vary");
    }

    fw_log(LOG_INFO, "Capture started on %s%s%s",
           ca->iface,
           ca->filter[0] ? " filter: " : "",
           ca->filter[0] ? ca->filter  : "");

    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    handle = NULL;
    fw_log(LOG_INFO, "Capture stopped.");
    free(ca);
    return NULL;
}

/* ─── main ───────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* Default config */
    const char *cfg_path  = DEFAULT_CONFIG;
    const char *log_path  = NULL;
    char        iface[64] = {0};
    int         autostart = 0;

    /* Simple arg parsing */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) strncpy(iface, argv[++i], 63);
        else if (!strcmp(argv[i], "-c") && i + 1 < argc) cfg_path = argv[++i];
        else if (!strcmp(argv[i], "-l") && i + 1 < argc) log_path = argv[++i];
        else if (!strcmp(argv[i], "-s")) autostart = 1;
        else if (!strcmp(argv[i], "-h")) {
            printf("Usage: %s [-i iface] [-c config] [-l logfile] [-s]\n", argv[0]);
            printf("  -i  Network interface (default: auto-detect)\n");
            printf("  -c  Config file path  (default: %s)\n", DEFAULT_CONFIG);
            printf("  -l  Log file path\n");
            printf("  -s  Auto-start capture on launch\n");
            return 0;
        }
    }

    load_rules(cfg_path);

    if (log_path) {
        logFile = fopen(log_path, "a");
        if (!logFile) perror("Cannot open log file");
        else fw_log(LOG_INFO, "Logging to %s", log_path);
    }

    /* Auto-detect interface */
    if (!iface[0]) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devs = NULL;
        if (pcap_findalldevs(&devs, errbuf) == 0 && devs)
            strncpy(iface, devs->name, 63);
        else
            strncpy(iface, "eth0", 63);
        if (devs) pcap_freealldevs(devs);
    }

    print_banner();
    fw_log(LOG_INFO, "FireWall started. Interface: %s  Config: %s", iface, cfg_path);

    pthread_t cap_tid = 0;

    if (autostart) {
        CaptureArgs *ca = malloc(sizeof(CaptureArgs));
        strncpy(ca->iface, iface, 63);
        ca->filter[0] = '\0';
        pthread_create(&cap_tid, NULL, capture_thread, ca);
    }

    char input[256];
    while (running) {
        print_menu();
        printf(COLOR_BOLD "> " COLOR_RESET); fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) break;
        int choice = atoi(input);

        switch (choice) {
        case 1: add_rule_interactive(); break;
        case 2: print_rules();          break;
        case 3: {
            print_rules();
            printf("  Delete rule #: "); fflush(stdout);
            if (!fgets(input, sizeof(input), stdin)) break;
            int idx = atoi(input) - 1;
            pthread_mutex_lock(&ruleMutex);
            if (idx >= 0 && idx < ruleCount) {
                for (int i = idx; i < ruleCount - 1; i++) rules[i] = rules[i + 1];
                ruleCount--;
                fw_log(LOG_INFO, "Rule #%d deleted", idx + 1);
            } else printf(COLOR_RED "  Invalid rule #\n" COLOR_RESET);
            pthread_mutex_unlock(&ruleMutex);
            break;
        }
        case 4: {
            print_rules();
            printf("  Toggle rule #: "); fflush(stdout);
            if (!fgets(input, sizeof(input), stdin)) break;
            int idx = atoi(input) - 1;
            pthread_mutex_lock(&ruleMutex);
            if (idx >= 0 && idx < ruleCount) {
                rules[idx].enabled ^= 1;
                fw_log(LOG_INFO, "Rule #%d %s", idx + 1,
                       rules[idx].enabled ? "enabled" : "disabled");
            } else printf(COLOR_RED "  Invalid rule #\n" COLOR_RESET);
            pthread_mutex_unlock(&ruleMutex);
            break;
        }
        case 5: print_stats(); break;
        case 6: save_rules(cfg_path); break;
        case 7: {
            if (cap_tid) {
                printf("  Capture already running.\n");
                break;
            }
            CaptureArgs *ca = malloc(sizeof(CaptureArgs));
            strncpy(ca->iface, iface, 63);
            printf("  BPF filter (blank=all): "); fflush(stdout);
            if (!fgets(ca->filter, sizeof(ca->filter), stdin))
                ca->filter[0] = '\0';
            ca->filter[strcspn(ca->filter, "\n")] = '\0';
            pthread_create(&cap_tid, NULL, capture_thread, ca);
            printf(COLOR_GREEN "  Capture thread launched (Ctrl+C or menu option 0 to stop).\n" COLOR_RESET);
            break;
        }
        case 8: {
            if (logFile) { fclose(logFile); logFile = NULL; }
            printf("  Log file path (blank=disable): "); fflush(stdout);
            if (!fgets(input, sizeof(input), stdin)) break;
            input[strcspn(input, "\n")] = '\0';
            if (input[0]) {
                logFile = fopen(input, "a");
                if (logFile) fw_log(LOG_INFO, "Log file: %s", input);
                else perror("Cannot open log file");
            } else printf(COLOR_YELLOW "  File logging disabled.\n" COLOR_RESET);
            break;
        }
        case 0:
            running = 0;
            if (handle) pcap_breakloop(handle);
            printf(COLOR_CYAN "  Saving rules and exiting...\n" COLOR_RESET);
            save_rules(cfg_path);
            break;
        default:
            printf(COLOR_YELLOW "  Unknown option.\n" COLOR_RESET);
        }
    }

    if (cap_tid) pthread_join(cap_tid, NULL);
    if (logFile) fclose(logFile);
    fw_log(LOG_INFO, "FireWall exited cleanly.");
    return 0;
}
