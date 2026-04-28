<div align="center">

```
███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗
██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║
█████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║
██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║
██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

**A lightweight, advanced packet-filtering firewall written in C**

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔒 **Block / Allow rules** | Filter by protocol, source IP, destination IP, source port, destination port |
| 🌐 **CIDR subnet matching** | Block or allow entire subnets, e.g. `10.0.0.0/8` |
| ⚡ **Rate limiting** | Auto-block IPs exceeding a configurable packets-per-second threshold |
| 📋 **Rule persistence** | Rules saved to and loaded from a human-readable config file |
| 📊 **Live statistics** | Packet counts, byte totals, per-rule hit counters |
| 🎨 **Color terminal UI** | Interactive menu with ANSI colors |
| 📁 **File logging** | Timestamped log of every blocked packet |
| 🧵 **Multi-threaded** | Packet capture runs in its own thread; the menu stays responsive |
| 🔌 **BPF filter support** | Pre-filter at the kernel level via libpcap BPF expressions |
| 🛡️ **ICMP / TCP / UDP** | Full awareness of the three main IP protocols |

---

## 📦 Requirements

| Dependency | Install (Ubuntu/Debian) | Install (Fedora/RHEL) | Install (Arch) |
|---|---|---|---|
| `libpcap` | `sudo apt install libpcap-dev` | `sudo dnf install libpcap-devel` | `sudo pacman -S libpcap` |
| `gcc` | `sudo apt install build-essential` | `sudo dnf install gcc` | `sudo pacman -S gcc` |
| `make` | included with `build-essential` | `sudo dnf install make` | `sudo pacman -S make` |

> **Root / CAP_NET_RAW is required** at runtime because libpcap needs raw socket access.

---

## 🚀 Building

```bash
git clone https://github.com/<your-username>/firewall.git
cd firewall
make
```

Optional targets:

```bash
make debug     # build with AddressSanitizer + debug symbols
make install   # install to /usr/local/bin  (needs sudo)
make clean     # remove compiled objects
```

---

## 🖥️ Usage

```
sudo ./firewall [OPTIONS]

Options:
  -i <iface>    Network interface to capture on  (default: auto-detect)
  -c <file>     Config file path                 (default: firewall.conf)
  -l <file>     Log file path
  -s            Auto-start capture on launch
  -h            Show this help
```

### Quickstart examples

```bash
# Interactive mode, auto-detect interface
sudo ./firewall

# Capture on eth0, log to file, start immediately
sudo ./firewall -i eth0 -l /var/log/firewall.log -s

# Use a custom config
sudo ./firewall -i wlan0 -c /etc/firewall.conf
```

---

## 📋 Interactive Menu

```
┌─────────────────── FIREWALL MENU ───────────────────┐
│  1) Add rule          2) List rules                 │
│  3) Delete rule       4) Toggle rule on/off         │
│  5) Show statistics   6) Save rules                 │
│  7) Start capture     8) Set log file               │
│  0) Exit                                            │
└─────────────────────────────────────────────────────┘
```

### Adding a rule (menu option 1)

You will be prompted interactively:

```
Action  [block/allow]:       block
Protocol [tcp/udp/icmp/any]: tcp
Src IP/CIDR [or 'any']:      any
Src Port [0=any]:            0
Dst IP/CIDR [or 'any']:      any
Dst Port [0=any]:            22
Rate limit pkt/s [0=off]:    10
Comment (optional):          SSH rate-limit
```

This creates a rule that **blocks** any TCP traffic destined for port 22 that exceeds **10 packets per second**.

---

## ⚙️ Config File Format

Rules are stored in a plain-text config file and can be edited manually:

```
# FireWall config
RULE action=BLOCK proto=tcp  src=any          srcport=0 dst=any dstport=22   rate=10 enabled=1 comment=SSH rate-limit
RULE action=BLOCK proto=any  src=203.0.113.0/24 srcport=0 dst=any dstport=0  rate=0  enabled=1 comment=Block bad subnet
RULE action=ALLOW proto=udp  src=192.168.1.1  srcport=0 dst=any dstport=53  rate=0  enabled=1 comment=Allow local DNS
RULE action=BLOCK proto=udp  src=any          srcport=0 dst=any dstport=53  rate=0  enabled=1 comment=Block other DNS
RULE action=BLOCK proto=icmp src=any          srcport=0 dst=any dstport=0   rate=0  enabled=0 comment=Block ICMP (disabled)
```

An example config is provided at `firewall.conf.example`.

---

## 📐 Architecture

```
main()
  ├── load_rules()           ← reads firewall.conf on startup
  ├── CLI menu loop          ← runs on main thread
  │     ├── add_rule_interactive()
  │     ├── print_rules()
  │     ├── print_stats()
  │     └── save_rules()
  └── capture_thread()       ← spawned on option 7 / -s flag
        └── packet_handler() ← called by pcap for every frame
              ├── IP header parse  (src/dst IP, protocol)
              ├── TCP/UDP header parse (src/dst port)
              ├── Rule evaluation  (matches_rule → ACTION_BLOCK/ALLOW)
              ├── Rate limiter     (rate_check per src IP)
              └── Statistics update
```

Rule evaluation is **first-match** with `ACTION_ALLOW` taking priority over `ACTION_BLOCK` when both match the same packet. Rules are evaluated in the order they appear in the list.

---

## 🔬 How It Works

1. **libpcap** opens the interface in promiscuous mode and delivers raw Ethernet frames.
2. The `packet_handler` callback strips the 14-byte Ethernet header to reach the IP header.
3. TCP and UDP headers are further parsed for port numbers.
4. Rules are evaluated in order. The first matching BLOCK rule triggers a log entry and increments the blocked counter.
5. For rate limiting, a fixed 1-second sliding window per source IP is maintained in an in-memory hash table.
6. All globals (rules, stats, rate table) are protected by separate `pthread_mutex_t` locks so the menu thread and capture thread can run concurrently without data races.

> **Note:** FireWall **observes** packets via libpcap — it does not drop them at the kernel level (that requires iptables/nftables or a kernel module). The project demonstrates packet inspection, rule matching, and logging logic. To enforce actual drops, integrate the rule engine with `iptables -j DROP` calls or use Linux `NFQUEUE` instead of pcap.

---

## 📊 Sample Output

```
[2025-04-28 14:32:01] [BLOCK] BLOCKED TCP 203.0.113.42:54321 -> 10.0.0.1:22 (rule #1: SSH rate-limit)
[2025-04-28 14:32:01] [WARN ] RATE-LIMITED TCP 192.168.1.50:45000 (>10 pps)

  ── Statistics ──────────────────────────────
  Total packets   : 12438
  Total bytes     : 9182640 (8.76 MB)
  Allowed         : 12105
  Blocked         : 301
  Rate-limited    : 32
  Rule hits       :
    Rule #1 : 301 hits
  ────────────────────────────────────────────
```

---

## 🛡️ Security Notes

- Always run as a **dedicated non-root user** with only `CAP_NET_RAW` granted where possible:
  ```bash
  sudo setcap cap_net_raw+ep ./firewall
  ./firewall -i eth0   # now runs without sudo
  ```
- The config file is stored in plain text — restrict permissions: `chmod 600 firewall.conf`.
- This tool is intended for **educational and monitoring** purposes. For production enforcement, combine with `iptables`/`nftables`.

---

## 📁 Project Structure

```
firewall/
├── firewall.c            ← main source (packet handler, CLI, capture thread)
├── firewall.h            ← types, constants, prototypes
├── Makefile              ← build system
├── firewall.conf.example ← sample config
├── LICENSE               ← MIT License
└── README.md             ← this file
```

---

## 🤝 Contributing

Pull requests are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes with clear messages
4. Open a pull request describing what changed and why

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<div align="center">
Made with ❤️ by <strong>Shishir</strong>
</div>
