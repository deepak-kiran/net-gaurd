# NetGuard 🛡️

**A standalone, real-time packet analyzer and firewall for Windows.**  
No Windows Firewall. No Npcap. No external drivers. Just Python + one command.

NetGuard intercepts every network packet at the **kernel level** using WinDivert — before any application on your machine sees it. Rules you create actually drop packets. Blocked means gone.

---

## What It Does

| Feature | Description |
|---------|-------------|
| 📡 **Live Packet Capture** | Intercepts all inbound and outbound traffic in real time |
| 🔥 **Real Firewall Enforcement** | Blocked packets are dropped at the driver level — not just labeled |
| 🔍 **Wireshark-style Filters** | Filter display by IP, protocol, port, direction, size, and more |
| 📊 **Statistics Dashboard** | Protocol distribution, bandwidth sparkline, top talkers |
| 📋 **Blocked Packet Log** | Full history of every packet denied by a rule |
| 💾 **PCAP Export** | Save captured traffic to `.pcap` for analysis in Wireshark |
| 🌐 **Web UI** | Clean browser-based interface served from the `frontend/` folder |

---

## How It Actually Works

Most Python "firewalls" are just Wireshark clones — they observe a copy of traffic but can't block anything. NetGuard is different.

```
Traditional approach (observe only):
  NIC → OS Kernel → App gets packet  ← already delivered
                ↘ Scapy reads a copy → labels it "BLOCKED" (too late)

NetGuard approach (true enforcement):
  NIC → WinDivert Driver → NetGuard holds packet
                              ↓
                         Firewall check
                              ↓
              ALLOW → re-inject → App receives packet normally
              DENY  → do nothing → Packet is gone. App never sees it.
```

WinDivert sits **between the NIC and the Windows TCP/IP stack**. Every packet passes through our Python code before the OS delivers it. If we don't re-inject it, it ceases to exist — no `netsh`, no Windows Firewall service, no iptables needed.

---

## Screenshots

> **Live packet capture with ICMP blocked in real time**

```
#     Time      Source           Destination      Proto  S.Port  D.Port  Dir  Size   FW     Info
1483  09:04:54  192.168.0.75    142.250.66.14    ICMP   —       —       O    74B    DENY   Echo Request
1484  09:04:54  142.250.66.14   192.168.0.75     ICMP   —       —       I    74B    DENY   Echo Reply
1485  09:04:55  192.168.0.75    142.250.66.14    ICMP   —       —       O    74B    DENY   Echo Request
```

> **Result in CMD:** `Packets: Sent = 4, Received = 0, Lost = 4 (100% loss)` ✅

---

## Requirements

| Requirement | Detail |
|-------------|--------|
| **OS** | Windows 7 x64 or later (Windows 10/11 recommended) |
| **Python** | 3.9 or higher |
| **Privileges** | Administrator (required for WinDivert kernel driver) |
| **Browser** | Any modern browser (Chrome, Firefox, Edge) |

> **No Npcap. No WinPcap. No Visual C++. No driver installer.**  
> WinDivert ships inside the `pydivert` Python package automatically.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/netguard.git
cd netguard
```

### 2. Create a virtual environment

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` installs:
- `flask` + `flask-socketio` + `flask-cors` — web server and real-time WebSocket
- `eventlet` — async support for Socket.IO
- `pydivert` — Python bindings for WinDivert (bundles `WinDivert.dll` + `WinDivert64.sys`)

### 4. Run as Administrator

**Option A — Right-click `run.bat` → Run as administrator** (auto-handles elevation)

**Option B — From an Administrator terminal:**
```cmd
python app.py
```

### 5. Open the UI

```
http://localhost:5000
```

---

## Project Structure

```
Fire_analyzer/                        ← root folder (VS Code workspace)
│
├── app.py                            ← Flask server, REST API, WebSocket hub, entry point
├── packet_capture.py                 ← WinDivert packet interception and PCAP export
├── firewall_engine.py                ← Rule storage, evaluation, enforcement logic
├── filter_engine.py                  ← Wireshark-style display filter compiler
├── stats_engine.py                   ← Bandwidth tracking, protocol distribution, top talkers
│
├── frontend/
│   └── index.html                    ← Complete web UI (single file, no build step)
│
├── exports/                          ← PCAP export files saved here (auto-created)
│
├── example_rules.json                ← Sample firewall rules you can import/reference
├── requirements.txt                  ← Python dependencies
├── Fire_analyzer.code-workspace      ← VS Code workspace settings
│
├── .venv/                            ← Python virtual environment (not committed to git)
└── __pycache__/                      ← Python bytecode cache (not committed to git)
```

> **Important:** `app.py` must be run from the root folder (`Fire_analyzer/`) so it can find all sibling modules and the `frontend/` directory.

---

## Module Architecture

```
┌─────────────────────────────────────────────────────────┐
│             Browser  (frontend/index.html)              │
│      WebSocket live packets + REST API for rules        │
└────────────────────────┬────────────────────────────────┘
                         │ Flask + Socket.IO
┌────────────────────────▼────────────────────────────────┐
│                       app.py                            │
│    Routes · WebSocket events · Engine orchestration     │
└──┬──────────────┬──────────────┬───────────────┬────────┘
   │              │              │               │
   ▼              ▼              ▼               ▼
packet_       firewall_      filter_         stats_
capture.py    engine.py      engine.py       engine.py
   │              │
   │  evaluate()  │ ◄── called for EVERY intercepted packet
   │              │
   ▼   DENY       │
  drop ◄──────────┘
   │
   ▼   ALLOW
  send() → re-inject into OS network stack → app receives normally
```

### `app.py` — Entry Point & API Server
- Initialises all four engine modules
- Serves `frontend/index.html` via Flask
- Exposes the full REST API (`/api/...`)
- Broadcasts packets and stats to the browser via Socket.IO WebSocket
- Checks for Administrator privileges on startup

### `packet_capture.py` — WinDivert Capture Engine
- Opens a WinDivert handle that intercepts all non-loopback packets
- Runs a background thread: `recv()` → parse → firewall check → `send()` or drop
- Parses IP, TCP, UDP, ICMP headers and resolves well-known port names (HTTP, HTTPS, SSH, DNS, RDP, etc.)
- Stores raw packets for accurate PCAP export via `wrpcap`
- Falls back to **simulation mode** (realistic fake traffic) if not running as Administrator or if `pydivert` is not installed

### `firewall_engine.py` — Rule Engine
- Thread-safe rule list sorted by priority (lower number = evaluated first)
- `evaluate(packet)` → returns `{action, rule_id}` in O(n_rules) with short-circuit exit
- Supports CIDR notation for IP matching (`192.168.1.0/24`)
- Application-layer protocols (HTTP, HTTPS, SSH, DNS) correctly match their parent transport rules (TCP, UDP)
- Default policy: **ALLOW** (fail-open)
- Ships with built-in default rules: Allow DNS, Allow HTTPS, Block Telnet

### `filter_engine.py` — Display Filter Compiler
- Compiles filter expressions into Python callables — O(1) per packet after compile
- Supports `&&`, `||`, `!`, parentheses, and 7 comparison operators
- Display filter only — controls what you **see**, does not affect firewall enforcement

### `stats_engine.py` — Statistics Aggregator
- Rolling 60-second bandwidth history (one bucket per second) for the sparkline chart
- Protocol distribution counters
- Top-10 source IPs, destination IPs, and destination ports by byte volume

---

## Usage Guide

### Starting a Capture

1. Open an **Administrator** terminal in the project folder
2. Run `python app.py` (or double-click `run.bat`)
3. Open `http://localhost:5000` in your browser
4. Click **▶ Start** — live packets appear immediately
5. Click any row to see full packet details in the right panel
6. Click **■ Stop** to pause, **↓ PCAP** to export captured traffic

---

### Display Filters

Type any expression in the filter bar. Applied in real time to the packet list.  
**Does not stop capture** — only controls what rows are shown.

**Syntax:** `field operator value`

#### Supported Fields

| Field | Matches |
|-------|---------|
| `ip.src` | Source IP address |
| `ip.dst` | Destination IP address |
| `ip` | Source **or** destination IP |
| `port` | Source **or** destination port |
| `src.port` | Source port only |
| `dst.port` | Destination port only |
| `tcp.port` | Either port (TCP packets) |
| `udp.port` | Either port (UDP packets) |
| `protocol` / `proto` | Protocol name: `TCP`, `UDP`, `ICMP`, `DNS`, `HTTP`, `HTTPS`, `SSH`, `RDP`… |
| `direction` | `INBOUND` or `OUTBOUND` |
| `size` / `length` | Packet size in bytes |
| `ttl` | IP time-to-live value |
| `flags` | TCP flags: `SYN`, `ACK`, `FIN`, `RST`, `PSH`… |
| `info` | Info string (free text search) |
| `blocked` | `true` or `false` |

#### Operators

| Operator | Meaning |
|----------|---------|
| `==` | Equals (substring match for strings) |
| `!=` | Not equals |
| `>` `<` `>=` `<=` | Numeric comparison (useful for `size`, `ttl`, `port`) |
| `contains` | Substring match |

#### Logical Operators

```
&&  or  and     — both conditions must be true
||  or  or      — either condition must be true
!   or  not     — negate a condition
( )             — grouping / precedence
```

#### Filter Examples

```bash
# Show only ICMP traffic
protocol == ICMP

# Show all packets that were blocked by a firewall rule
blocked == true

# Show traffic to or from a specific IP
ip == 142.250.66.14

# Show large TCP packets only
size > 1000 && protocol == TCP

# Show inbound blocked traffic
direction == INBOUND && blocked == true

# Show web traffic (HTTP and HTTPS)
dst.port == 80 || dst.port == 443

# Hide DNS noise
!(protocol == DNS)

# Show SSH or RDP connections
protocol == SSH || protocol == RDP

# Show traffic from an entire subnet
ip.src == 192.168.0.0/24

# Show packets with SYN flag set
flags == SYN

# Show non-standard HTTP
protocol == HTTP && dst.port != 80
```

---

### Firewall Rules

Rules are evaluated in **priority order** (lower number = first).  
**First matching rule wins.** If no rule matches, the packet is ALLOWED (default policy).

#### Quick Block (fastest)

Open the **Firewall** tab on the right panel:

| Action | How |
|--------|-----|
| Block an IP address | Enter IP or CIDR → click **Block IP** |
| Block a port | Enter port number → click **Block Port** |
| Block from a captured packet | Click any packet row → click **Block Source IP** or **Block Dest IP** |

#### Custom Rules

Click **+ Add Firewall Rule** and configure:

| Field | Options | Notes |
|-------|---------|-------|
| **Action** | `ALLOW` / `DENY` | What to do when the rule matches |
| **Direction** | `INBOUND` / `OUTBOUND` / `BOTH` | From the perspective of your machine |
| **Protocol** | `TCP` / `UDP` / `ICMP` / `ANY` | Transport-layer protocol |
| **Priority** | 1–999 | Lower = evaluated first |
| **Source IP** | IP or CIDR | Leave blank = any source |
| **Dest IP** | IP or CIDR | Leave blank = any destination |
| **Source Port** | 1–65535 | Leave blank = any |
| **Dest Port** | 1–65535 | Leave blank = any |

> **Protocol inheritance:** A `TCP` rule also matches `HTTP`, `HTTPS`, `SSH`, `FTP`, `RDP`, `SMTP`, `Telnet`, etc.  
> A `UDP` rule also matches `DNS`. You don't need separate rules per application protocol.

#### Example Rules

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Block all ICMP (disable ping completely)
  Action: DENY | Direction: BOTH | Protocol: ICMP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Block RDP from internet (prevent brute force)
  Action: DENY | Direction: INBOUND | Protocol: TCP | Dst Port: 3389
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Block outbound SMTP (prevent spam relay)
  Action: DENY | Direction: OUTBOUND | Protocol: TCP | Dst Port: 25
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Block a specific malicious IP
  Action: DENY | Direction: BOTH | Protocol: ANY
  Src IP: 203.0.113.42
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Block an entire subnet
  Action: DENY | Direction: INBOUND | Protocol: ANY
  Src IP: 198.51.100.0/24
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Allow one IP through SSH, block everyone else
  Priority 1:  ALLOW | INBOUND | TCP | Src: 10.0.0.5 | Dst Port: 22
  Priority 10: DENY  | INBOUND | TCP | Dst Port: 22
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### Rule Priority System

```
Priority 1   ← checked first  (use for ALLOW exceptions / whitelist)
Priority 2–9
Priority 10  ← recommended for general DENY rules
...
Priority 100 ← default for new custom rules
...
Priority 999 ← checked last   (use for catch-all / default deny)
```

---

### Example Rules File (`example_rules.json`)

The repo includes `example_rules.json` with ready-to-use rule templates covering common security scenarios:

```json
{
  "example_rules": [
    { "name": "Block Telnet",         "action": "DENY",  "protocol": "TCP", "dst_port": 23   },
    { "name": "Block RDP",            "action": "DENY",  "protocol": "TCP", "dst_port": 3389 },
    { "name": "Block outbound SMTP",  "action": "DENY",  "direction": "OUTBOUND", "protocol": "TCP", "dst_port": 25 },
    { "name": "Block all ICMP",       "action": "DENY",  "protocol": "ICMP" },
    { "name": "Block SMB (WannaCry)", "action": "DENY",  "protocol": "TCP", "dst_port": 445  },
    { "name": "Allow HTTPS",          "action": "ALLOW", "protocol": "TCP", "dst_port": 443  },
    { "name": "Allow DNS",            "action": "ALLOW", "protocol": "UDP", "dst_port": 53   }
  ]
}
```

Use these as a reference when creating rules through the UI.

---

### REST API Reference

All endpoints return JSON. Base URL: `http://localhost:5000`

#### Capture

```http
GET  /api/capture/status
     → { running, interface, packet_count, blocked_count }

POST /api/capture/start
     → { status: "started", interface }

POST /api/capture/stop
     → { status: "stopped" }

POST /api/capture/export
     body: { "filename": "capture.pcap" }
     → { status, file, packets }
     Saves to: exports/capture.pcap
```

#### Firewall Rules

```http
GET    /api/firewall/rules
       → { rules: [ {id, name, action, direction, protocol, src_ip, dst_ip,
                     src_port, dst_port, priority, enabled, hit_count, ...} ] }

POST   /api/firewall/rules
       body: { name, action, direction, protocol, src_ip, dst_ip,
               src_port, dst_port, priority, description }
       → { status: "added", rule }

DELETE /api/firewall/rules/{id}
       → { status: "deleted" }

POST   /api/firewall/rules/{id}/toggle
       → { status: "toggled", rule }

POST   /api/firewall/block-ip
       body: { "ip": "1.2.3.4", "direction": "BOTH" }
       → { status: "blocked", rule }

POST   /api/firewall/block-port
       body: { "port": 3389, "protocol": "TCP" }
       → { status: "blocked", rule }

GET    /api/firewall/blocked-log?limit=200
       → { log: [ {timestamp, src_ip, dst_ip, protocol, direction, rule_id, ...} ] }
```

#### Display Filter

```http
POST /api/filter
     body: { "expression": "protocol == ICMP && direction == INBOUND" }
     → { status: "ok", expression }  |  { status: "error", error }

GET  /api/filter
     → { expression }

POST /api/filter/clear
     → { status: "cleared" }
```

#### Statistics

```http
GET  /api/stats
     → { packet_count, blocked_count, allowed_count,
         total_mb, avg_kbps, elapsed_sec,
         proto_distribution, top_src_ips, top_dst_ips,
         top_ports, bw_history, timestamp }

POST /api/stats/reset
     → { status: "reset" }
```

#### WebSocket Events (Socket.IO on `http://localhost:5000`)

```javascript
// Server pushes to browser:
socket.on('packet', (pkt) => { /* new packet */ })   // every captured packet
socket.on('stats',  (s)   => { /* stats update */ }) // every 20 packets
socket.on('status', (s)   => { /* capture state */ }) // on connect / state change

// Packet object shape:
{
  id,           // sequential integer
  timestamp,    // ISO 8601 UTC string
  epoch,        // Unix timestamp float
  src_ip,       // "192.168.0.75"
  dst_ip,       // "142.250.66.14"
  src_port,     // integer or null
  dst_port,     // integer or null
  protocol,     // "TCP" | "UDP" | "ICMP" | "HTTP" | "HTTPS" | "DNS" | "SSH" | ...
  size,         // bytes (integer)
  ttl,          // integer or null
  flags,        // "SYN" | "ACK" | "SYN-ACK" | "FIN" | null
  direction,    // "INBOUND" | "OUTBOUND"
  info,         // human-readable summary string
  layers,       // ["IPv4", "TCP"]
  raw_summary,  // full one-line summary
  blocked,      // boolean
  fw_action,    // "ALLOW" | "DENY"
  fw_rule       // matched rule id (integer) or null
}
```

---

## Simulation Mode

If NetGuard is not running as Administrator, or `pydivert` is not installed, it automatically starts in **simulation mode**. Realistic fake traffic is generated so you can:

- Explore the full UI without a live network
- Test all firewall rules and see DENY labels applied
- Test all display filter expressions
- Demo the application on any machine

All firewall logic runs identically — the only difference is packets are not real.

Check the terminal on startup to confirm which mode is active:
```
✅ Running as Administrator — WinDivert enforcement active
```
or
```
⚠  WARNING: Not running as Administrator → simulation mode (fake traffic)
```

---

## Troubleshooting

### Rules show DENY in the UI but ping still works

**You are not running as Administrator.** WinDivert cannot load its kernel driver without elevated privileges. Without the driver, NetGuard can only label packets — it cannot drop them.

```cmd
:: Confirm admin status — must print 1
python -c "import ctypes; print(ctypes.windll.shell32.IsUserAnAdmin())"
```

Fix: Close your terminal → right-click → **Run as administrator** → run `python app.py` again.

---

### `pip install pydivert` fails

```cmd
:: Try the pre-release version
pip install pydivert --pre

:: Or force no build isolation (Python 3.11+)
pip install pydivert --no-build-isolation
```

---

### Port 5000 is already in use

```
OSError: [Errno 98] Address already in use
```

Either kill the existing process or change the port in `app.py`:
```python
socketio.run(app, host="0.0.0.0", port=5001, ...)  # change 5000 → 5001
```

---

### Browser shows "Cannot reach backend"

The Flask server is not running. Check the terminal for error output and `netguard.log` for details.

---

### WinDivert breaks internet connection after a crash

If NetGuard crashes while intercepting packets, the driver may hold packets in its queue. Fix:
```cmd
taskkill /f /im python.exe
sc stop WinDivert
```
Then restart NetGuard normally.

---

### Ping blocks INBOUND but packets still arrive

Check that your rule direction is set to **BOTH**, not just `INBOUND`.

A ping to `google.com` generates two packet types:
- `OUTBOUND` — Echo Request (your machine → Google)
- `INBOUND` — Echo Reply (Google → your machine)

To fully block ping in both directions, set direction to `BOTH` in your ICMP DENY rule.

---

## Limitations

- **Windows only** — WinDivert is a Windows kernel driver. Linux/macOS would need a different enforcement mechanism (nftables, BPF, etc.)
- **No rule persistence** — firewall rules reset when the app restarts. A planned feature is save/load from `example_rules.json`
- **IPv4 focus** — IPv6 packets are captured and displayed but firewall rules currently apply to IPv4 addresses only
- **No TCP stream reassembly** — each packet is shown individually, not grouped into flows or connections
- **No payload inspection** — rules operate on headers only (IP, port, protocol). Deep packet inspection is not implemented
- **No TLS decryption** — HTTPS traffic is visible as `HTTPS/TCP` but content is encrypted

---

## Planned Improvements

- [ ] Save and load firewall rules to/from `example_rules.json`
- [ ] IPv6 firewall rule support
- [ ] GeoIP lookup — show country next to each IP address
- [ ] Threat intelligence — check IPs against AbuseIPDB / known blocklists
- [ ] TCP flow grouping — group packets into connection streams
- [ ] Rate-limit detection — alert when a single IP sends abnormal traffic volume
- [ ] Alert / notification system when a high-priority rule is triggered
- [ ] Single `.exe` distribution via PyInstaller (no Python install needed on target machine)
- [ ] Scheduled rules — automatically enable/disable rules at set times

---

## Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Packet interception | **WinDivert** via `pydivert` | Only Python-accessible library providing true kernel-level packet interception AND dropping on Windows — no Npcap, no WinPcap needed |
| Web server | **Flask** + **Flask-SocketIO** | Lightweight, built-in WebSocket support for real-time packet streaming to the browser |
| Real-time UI | **Socket.IO** | Bi-directional event push — server streams packets to browser without polling |
| Frontend | **Vanilla HTML/CSS/JS** | Zero build step, single `index.html` file, works in any browser |
| Async | **eventlet** | Green-thread concurrency so Socket.IO and the capture thread don't block each other |

---

## Security Notes

- NetGuard requires **Administrator privileges** to load the WinDivert kernel driver. This is unavoidable — kernel-level packet interception requires elevated access on every OS.
- The web UI binds to `0.0.0.0:5000` by default — accessible from any machine on the network. For local-only access, change to `host="127.0.0.1"` in `app.py`.
- The web UI has **no authentication**. Do not expose port 5000 on a public or untrusted network.
- `netguard.log` and the blocked packet log may contain sensitive IP addresses and traffic metadata. Secure or rotate log files as appropriate.
- Firewall rules reset on restart — critical rules are not persistent across sessions.

---

## .gitignore

Add this to `.gitignore` to keep the repository clean:

```gitignore
.venv/
__pycache__/
*.pyc
exports/
netguard.log
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Pull requests are welcome. For significant changes please open an issue first.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/rule-persistence`
3. Commit your changes: `git commit -m 'Add rule save/load to JSON'`
4. Push: `git push origin feature/rule-persistence`
5. Open a Pull Request

---

<div align="center">
Built with Python · WinDivert · Flask · Socket.IO
</div>
