/*
 * firewall.h — FireWall project header
 * Author: Shishir
 */

#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

/* ─── Tunables ──────────────────────────────────────────────── */
#define MAX_RULES         100
#define MAX_IP_LENGTH      48   /* big enough for CIDR notation   */
#define MAX_PROTOCOL_LENGTH 8
#define MAX_COMMENT_LEN    128
#define MAX_RATE_ENTRIES   4096
#define SNAP_LEN           65535
#define DEFAULT_CONFIG     "firewall.conf"

/* ─── ANSI colours ──────────────────────────────────────────── */
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_CYAN    "\033[0;36m"

/* ─── Rule action ───────────────────────────────────────────── */
typedef enum { ACTION_BLOCK = 0, ACTION_ALLOW = 1 } RuleAction;

/* ─── Firewall rule ─────────────────────────────────────────── */
typedef struct {
    RuleAction action;
    char       protocol[MAX_PROTOCOL_LENGTH];   /* tcp/udp/icmp/"" */
    char       srcIP[MAX_IP_LENGTH];            /* CIDR or single  */
    int        srcPort;                         /* 0 = any         */
    char       dstIP[MAX_IP_LENGTH];
    int        dstPort;
    int        rate_limit;                      /* pkt/s, 0=off    */
    int        enabled;
    char       comment[MAX_COMMENT_LEN];
} FirewallRule;

/* ─── Statistics ────────────────────────────────────────────── */
typedef struct {
    unsigned long total_packets;
    unsigned long total_bytes;
    unsigned long allowed_packets;
    unsigned long blocked_packets;
    unsigned long rate_limited;
    unsigned long rule_hits[MAX_RULES];
} FirewallStats;

/* ─── Per-IP rate-limit entry ───────────────────────────────── */
typedef struct {
    uint32_t ip;
    time_t   window_start;
    int      count;
} RateEntry;

/* ─── Log levels ────────────────────────────────────────────── */
typedef enum {
    LOG_INFO  = 0,
    LOG_WARN  = 1,
    LOG_BLOCK = 2,
    LOG_ERROR = 3,
    LOG_STATS = 4
} LogLevel;

/* ─── Globals (defined in firewall.c) ───────────────────────── */
extern FirewallRule  rules[MAX_RULES];
extern int           ruleCount;
extern pcap_t       *handle;
extern FirewallStats stats;
extern RateEntry     rateTable[MAX_RATE_ENTRIES];
extern int           rateCount;
extern FILE         *logFile;
extern volatile int  running;
extern pthread_mutex_t ruleMutex;
extern pthread_mutex_t statMutex;
extern pthread_mutex_t rateMutex;

/* ─── Function prototypes ───────────────────────────────────── */
void  handle_signal(int sig);
void  fw_log(LogLevel level, const char *fmt, ...);
int   cidr_match(const char *cidr, uint32_t pkt_ip);
int   rate_check(uint32_t src_ip, int pps_limit);
int   matches_rule(const FirewallRule *r, const char *proto,
                   uint32_t src_ip, uint32_t dst_ip,
                   int src_port, int dst_port);
void  packet_handler(u_char *args, const struct pcap_pkthdr *header,
                     const u_char *packet);
void  save_rules(const char *path);
void  load_rules(const char *path);
void *capture_thread(void *arg);

#endif /* FIREWALL_H */
