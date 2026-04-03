<div align="center">

<h1>🛡️ NetGuard</h1>
<p><strong>Real-Time Network Packet Analyzer & Firewall Manager</strong></p>

<p>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Python-3.9%2B-yellow?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Capture-Scapy-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/Enforcement-netsh%20%7C%20iptables-red?style=flat-square" />
  <img src="https://img.shields.io/badge/UI-Browser%20%28Flask%29-lightblue?style=flat-square" />
</p>

<p>
A network packet analyzer and firewall manager with a live browser-based UI.<br/>
Captures traffic using <strong>Scapy</strong>, filters it with Wireshark-style expressions,<br/>
and enforces rules through <strong>Windows Firewall (netsh)</strong> on Windows or <strong>iptables</strong> on Linux.
</p>

</div>

---

## 📌 How It Works

```
Network Interface
      │
      ▼
 Scapy (passive copy)          ← reads a copy of every packet
      │
      ▼
 PacketCaptureEngine           ← parses IP / TCP / UDP / ICMP / ARP / DNS headers
      │
      ├──▶ FirewallEngine       ← checks packet against rules → ALLOW or DENY
      │          │
      │     if DENY:
      │          ├── Windows → subprocess calls netsh advfirewall
      │          └── Linux   → subprocess calls iptables
      │
      ├──▶ FilterEngine         ← applies display filter expression
      │
      ├──▶ StatsEngine          ← updates bandwidth / protocol counters
      │
      ▼
 Flask + Socket.IO              ← streams packets to browser via WebSocket
      │
      ▼
 Browser UI (localhost:5000)    ← live table, filter bar, rule panel, stats
```

> **Key distinction:** Scapy captures a *copy* of packets passively — it does not hold or intercept them. Firewall enforcement is handled by the OS: `netsh advfirewall` on Windows and `iptables` on Linux, called via Python's `subprocess` module.

---

## ✨ Features

- **Live packet capture** — real-time sniffing via Scapy across all network interfaces
- **Real-time browser UI** — packets pushed to the browser instantly via Socket.IO WebSocket
- **Wireshark-style display filters** — expression compiler supporting `&&`, `||`, `!`, and grouping
- **Firewall rule management** — create, toggle, and delete rules from the UI
- **OS-level enforcement** — DENY rules sync to `netsh` (Windows) or `iptables` (Linux) via `subprocess`
- **Direction-aware rules** — separate INBOUND / OUTBOUND / BOTH control
- **CIDR support** — match entire subnets like `192.168.1.0/24` in rules
- **Quick block** — one-click IP or port block from the packet detail view
- **Protocol detection** — TCP, UDP, ICMP, DNS, HTTP, HTTPS, SSH, RDP, FTP, ARP, Telnet
- **Statistics dashboard** — 60-second bandwidth graph, protocol distribution bars, top IPs and ports
- **Blocked packet log** — audit trail of every denied packet with timestamp and matching rule ID
- **PCAP export** — save captured packets for analysis in Wireshark
- **Simulation mode** — auto-activates when Scapy is unavailable; generates realistic fake traffic so the UI is fully testable without root

---

## 📁 Project Structure

```
netguard/
├── app.py                ← Flask app, REST API routes, Socket.IO events
├── packet_capture.py     ← Scapy sniffing engine, packet parser, PCAP export
├── firewall_engine.py    ← Rule management, netsh/iptables subprocess calls
├── filter_engine.py      ← Display filter expression compiler (pure Python re)
│── stats_engine.py       ← Rolling bandwidth, protocol, and IP statistics
├── frontend/
│   └── index.html            ← Single-file web UI — no build step required
├── exports/                  ← PCAP files saved here (auto-created)
├── requirements.txt
└── README.md
```

---

## 🔧 Tech Stack

| Layer | Library | Purpose |
|-------|---------|---------|
| Packet capture | `scapy` | Sniff raw packets, parse protocol headers, write PCAP |
| Web server | `flask` | REST API, serve frontend HTML |
| Real-time streaming | `flask-socketio`, `python-socketio` | Push packets to browser via WebSocket |
| Cross-origin | `flask-cors` | Allow browser to call API |
| Async I/O | `eventlet` | Threading mode for Socket.IO |
| Firewall (Windows) | `subprocess` → `netsh advfirewall` | Create/delete Windows Firewall rules |
| Firewall (Linux) | `subprocess` → `iptables` | Add/remove iptables DROP rules |
| IP matching | `ipaddress` (stdlib) | CIDR range checks in rule evaluation |
| Platform detection | `platform` (stdlib) | Choose netsh vs iptables at runtime |
| Filter compiler | `re` (stdlib) | Parse and evaluate filter expressions |
| Statistics | `collections.defaultdict`, `deque` | Rolling counters and bandwidth history |

**No WinDivert. No Npcap. No pydivert.** Just Scapy + Flask + the OS firewall CLI tools.

---

## 📋 Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.9+ | |
| Windows 10/11 or Linux | macOS supported for capture only (no iptables) |
| **Administrator** (Windows) | Required for Scapy capture + netsh enforcement |
| **root / sudo** (Linux) | Required for Scapy capture + iptables enforcement |
| Windows Firewall **enabled** | Must not be disabled by third-party antivirus |
| `iptables` installed | Linux only — `sudo apt install iptables` |

---

## ⚡ Quick Start

### 1. Clone

```bash
git clone https://github.com/yourusername/netguard.git
cd netguard
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

Linux — also install libpcap:
```bash
sudo apt install libpcap-dev    # Debian / Ubuntu
```

### 3. Run

**Windows** — open terminal as Administrator:
```cmd
python backend/app.py
```

**Linux:**
```bash
sudo python backend/app.py
```

> If Scapy is unavailable or you are not running as root/admin, NetGuard automatically enters **simulation mode** — the full UI works with generated fake traffic but no real packets are captured and no OS rules are created.

### 4. Open the UI

**[http://localhost:5000](http://localhost:5000)**

---

## 🔥 Firewall Rules

### Rule fields

| Field | Type | Options | Description |
|-------|------|---------|-------------|
| `name` | string | any | Human-readable label |
| `action` | string | `ALLOW` / `DENY` | Decision when rule matches |
| `direction` | string | `INBOUND` / `OUTBOUND` / `BOTH` | Traffic direction |
| `protocol` | string | `TCP` / `UDP` / `ICMP` / `ANY` | Layer 4 protocol |
| `src_ip` | string\|null | IP or CIDR | e.g. `10.0.0.5` or `192.168.1.0/24` |
| `dst_ip` | string\|null | IP or CIDR | `null` matches any |
| `src_port` | int\|null | 1–65535 | `null` matches any port |
| `dst_port` | int\|null | 1–65535 | `null` matches any port |
| `priority` | int | 1–999 | Lower = evaluated first |
| `enabled` | bool | `true` / `false` | Toggle without deleting |

### Rule evaluation order

Rules are sorted by `priority` (ascending). The **first matching rule wins**. If no rule matches, the default policy is **ALLOW**.

### What happens when a rule matches DENY

**On Windows** — NetGuard calls:
```cmd
netsh advfirewall firewall add rule
  name="NetGuard_<id>_<name>_in"
  protocol=icmpv4
  dir=in
  action=block
  enable=yes
```

**On Linux** — NetGuard calls:
```bash
iptables -A INPUT -p icmp -j DROP
```

When you **delete or disable** a rule in the UI, the corresponding `netsh` or `iptables` rule is automatically removed via another `subprocess` call.

### Example rules

```
# Block ping replies coming back to this machine
action=DENY  direction=INBOUND   protocol=ICMP

# Block unencrypted Telnet
action=DENY  direction=BOTH      protocol=TCP   dst_port=23

# Block outbound RDP
action=DENY  direction=OUTBOUND  protocol=TCP   dst_port=3389

# Block all traffic from a suspicious subnet
action=DENY  direction=INBOUND   protocol=ANY   src_ip=203.0.113.0/24

# Block outbound SMTP to prevent spam relay
action=DENY  direction=OUTBOUND  protocol=TCP   dst_port=25

# Allow internal HTTPS — evaluated before any broad deny (priority=1)
action=ALLOW direction=BOTH      protocol=TCP   dst_port=443  priority=1
```

---

## 🔍 Display Filters

Filters narrow what appears in the live packet table. They do **not** affect capture, firewall enforcement, or statistics.

### Syntax

```
field  operator  value
```

Combine with: `&&` (AND) · `||` (OR) · `!` or `not` (NOT) · `( )` grouping

**Operators:** `==` `!=` `>` `<` `>=` `<=` `contains`

### Field reference

| Field | Matches |
|-------|---------|
| `ip.src` | Source IP address |
| `ip.dst` | Destination IP address |
| `ip` | Source **or** destination IP |
| `protocol` / `proto` | Protocol name (TCP, UDP, ICMP, DNS…) |
| `port` | Source **or** destination port |
| `src.port` | Source port only |
| `dst.port` | Destination port only |
| `size` / `length` | Packet size in bytes |
| `ttl` | IP Time To Live |
| `flags` | TCP flags (SYN, ACK, FIN, RST…) |
| `blocked` | `true` or `false` |
| `info` | Info string (text search) |

### Examples

```bash
# Only ICMP
protocol == ICMP

# Traffic to/from a specific IP
ip == 8.8.8.8

# All packets blocked by a firewall rule
blocked == true

# Large TCP packets (file transfers)
protocol == TCP && size > 1000

# DNS or ICMP only
protocol == DNS || protocol == ICMP

# HTTPS from internal subnet
ip.src == 192.168.0.0/24 && dst.port == 443

# Hide loopback
!(ip.src == 127.0.0.1 || ip.dst == 127.0.0.1)

# TCP SYN — new connection attempts
flags == SYN
```

**Shortcuts:** `Ctrl+K` to focus filter · `Escape` to clear

---

## 🌐 REST API

### Capture control

```http
GET  /api/interfaces
POST /api/capture/start      { "interface": "eth0" }
POST /api/capture/stop
GET  /api/capture/status
POST /api/capture/export     { "filename": "capture.pcap" }
```

### Firewall

```http
GET    /api/firewall/rules
POST   /api/firewall/rules                 Add rule (JSON body — see schema above)
DELETE /api/firewall/rules/:id
POST   /api/firewall/rules/:id/toggle
POST   /api/firewall/block-ip              { "ip": "1.2.3.4", "direction": "BOTH" }
POST   /api/firewall/block-port            { "port": 23, "protocol": "TCP" }
GET    /api/firewall/blocked-log           ?limit=100
```

### Filter & Stats

```http
POST /api/filter          { "expression": "protocol == ICMP" }
GET  /api/filter
POST /api/filter/clear
GET  /api/stats
POST /api/stats/reset
```

### WebSocket (Socket.IO)

| Event | Direction | Sent when |
|-------|-----------|-----------|
| `packet` | Server → Browser | Every captured packet that passes the display filter |
| `stats` | Server → Browser | Every 10 packets |
| `status` | Server → Browser | Capture started or stopped |

---

## ⚠️ Limitations

| Limitation | Detail |
|------------|--------|
| Passive capture | Scapy reads a copy — it cannot hold or drop packets itself |
| OS firewall required | Enforcement depends on `netsh` (Windows) or `iptables` (Linux) being active |
| Antivirus conflicts | Tools like Avast or Kaspersky may replace Windows Firewall, making `netsh` ineffective |
| Admin/root required | Both Scapy capture and OS firewall modification need elevated privileges |
| No packet reassembly | TCP shown per-packet, not as reassembled streams |
| No TLS decryption | HTTPS payload is not inspectable |
| No persistent rules | Rules are stored in memory and reset on restart |
| Display buffer | UI shows last 500 packets (change `MAX_DISPLAY` in `index.html`) |

---

## 🛠️ Troubleshooting

**Packets captured but firewall rules have no effect on Windows:**
```cmd
# 1. Confirm running as Administrator
# 2. Check Windows Firewall is ON
netsh advfirewall show allprofiles state

# 3. Verify rules were created
netsh advfirewall firewall show rule name=all | findstr NetGuard

# 4. Check netguard.log for errors
```

**No packets showing (Linux):**
```bash
# Confirm libpcap is installed
sudo apt install libpcap-dev

# Confirm running with sudo
sudo python backend/app.py
```

**Red import underlines in VS Code:**
```bash
# Open using the workspace file — not just the folder
code NetGuard.code-workspace
# Then: Ctrl+Shift+P → Python: Select Interpreter
```

---

## 🗺️ Roadmap

- [ ] Persistent rules via SQLite
- [ ] GeoIP country lookup per IP
- [ ] Threat intelligence blocklist integration
- [ ] TCP stream / session reassembly
- [ ] Rate-based rules (block source if > N pps)
- [ ] Alert notifications (desktop + webhook)
- [ ] Standalone `.exe` via PyInstaller

---

## 🙏 Acknowledgements

- [Scapy](https://scapy.net/) — Packet capture and protocol dissection
- [Flask](https://flask.palletsprojects.com/) — Web framework
- [Flask-SocketIO](https://flask-socketio.readthedocs.io/) — WebSocket integration

---

<div align="center">
<sub>Python · Scapy · Flask · Socket.IO · netsh · iptables</sub>
</div>
