"""
NetGuard — Firewall Rule Engine

Manages firewall rules in two layers:
  1. Software layer: evaluates rules in-process against every packet
  2. System layer (optional): syncs rules to iptables on Linux

Rule Schema:
  {
    "id": int,
    "name": str,
    "action": "ALLOW" | "DENY",
    "direction": "INBOUND" | "OUTBOUND" | "BOTH",
    "protocol": "TCP" | "UDP" | "ICMP" | "ANY",
    "src_ip": str | None,        # CIDR or exact IP, e.g. "192.168.1.0/24"
    "dst_ip": str | None,
    "src_port": int | None,
    "dst_port": int | None,
    "enabled": bool,
    "created_at": str,
    "hit_count": int,
    "priority": int              # lower = evaluated first
  }

Rule evaluation is short-circuit: first matching rule wins.
Default policy: ALLOW (fail-open for monitoring).
"""

import ipaddress
import platform
import subprocess
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger("NetGuard.Firewall")


class FirewallEngine:

    DEFAULT_RULES = [
        {
            "name": "Block Telnet",
            "action": "DENY",
            "direction": "BOTH",
            "protocol": "TCP",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": 23,
            "enabled": True,
            "priority": 10,
            "description": "Block unencrypted Telnet traffic",
        },
        {
            "name": "Allow DNS",
            "action": "ALLOW",
            "direction": "BOTH",
            "protocol": "UDP",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": 53,
            "enabled": True,
            "priority": 5,
            "description": "Allow DNS queries",
        },
        {
            "name": "Allow HTTPS",
            "action": "ALLOW",
            "direction": "BOTH",
            "protocol": "TCP",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": 443,
            "enabled": True,
            "priority": 5,
            "description": "Allow HTTPS traffic",
        },
    ]

    def __init__(self, use_iptables: bool = False):
        self._rules: List[Dict] = []
        self._blocked_log: List[Dict] = []
        self._lock = threading.RLock()
        self._next_id = 1
        self._use_iptables = use_iptables and self._check_iptables()
        self._use_winfw = platform.system() == "Windows"   # ← auto-enabled on Windows

        # Load default rules
        for r in self.DEFAULT_RULES:
            self.add_rule(r)

        logger.info(f"FirewallEngine initialized (iptables={'on' if self._use_iptables else 'off'}, winfw={'on' if self._use_winfw else 'off'})")

    # ──────────────────────────────────────────
    # Rule Management
    # ──────────────────────────────────────────
    def add_rule(self, data: Dict) -> Dict:
        """Validate and add a new firewall rule. Returns the created rule."""
        action = data.get("action", "DENY").upper()
        if action not in ("ALLOW", "DENY"):
            raise ValueError(f"Invalid action: {action!r}. Must be ALLOW or DENY.")

        direction = data.get("direction", "BOTH").upper()
        if direction not in ("INBOUND", "OUTBOUND", "BOTH"):
            raise ValueError(f"Invalid direction: {direction!r}")

        protocol = data.get("protocol", "ANY").upper()
        if protocol not in ("TCP", "UDP", "ICMP", "ANY"):
            raise ValueError(f"Invalid protocol: {protocol!r}")

        # Validate IP addresses if provided
        for field in ("src_ip", "dst_ip"):
            ip_val = data.get(field)
            if ip_val:
                try:
                    ipaddress.ip_network(ip_val, strict=False)
                except ValueError:
                    try:
                        ipaddress.ip_address(ip_val)
                    except ValueError:
                        raise ValueError(f"Invalid IP/CIDR for {field}: {ip_val!r}")

        # Validate ports
        for field in ("src_port", "dst_port"):
            port = data.get(field)
            if port is not None:
                port = int(port)
                if not (0 <= port <= 65535):
                    raise ValueError(f"Invalid port {port}")

        with self._lock:
            rule = {
                "id": self._next_id,
                "name": data.get("name", f"Rule #{self._next_id}"),
                "description": data.get("description", ""),
                "action": action,
                "direction": direction,
                "protocol": protocol,
                "src_ip": data.get("src_ip") or None,
                "dst_ip": data.get("dst_ip") or None,
                "src_port": int(data["src_port"]) if data.get("src_port") is not None else None,
                "dst_port": int(data["dst_port"]) if data.get("dst_port") is not None else None,
                "enabled": data.get("enabled", True),
                "priority": int(data.get("priority", 100)),
                "created_at": datetime.utcnow().isoformat() + "Z",
                "hit_count": 0,
            }
            self._next_id += 1
            self._rules.append(rule)
            self._rules.sort(key=lambda r: r["priority"])

        if self._use_iptables and rule["enabled"] and rule["action"] == "DENY":
            self._apply_iptables(rule, add=True)

        if self._use_winfw and rule["enabled"] and rule["action"] == "DENY":
            self._apply_windows_firewall(rule, add=True)

        return rule

    def delete_rule(self, rule_id: int) -> bool:
        with self._lock:
            for i, r in enumerate(self._rules):
                if r["id"] == rule_id:
                    rule = self._rules.pop(i)
                    if self._use_iptables and rule["action"] == "DENY":
                        self._apply_iptables(rule, add=False)
                    if self._use_winfw and rule["action"] == "DENY":
                        self._apply_windows_firewall(rule, add=False)
                    return True
        return False

    def toggle_rule(self, rule_id: int) -> Optional[Dict]:
        with self._lock:
            for r in self._rules:
                if r["id"] == rule_id:
                    r["enabled"] = not r["enabled"]
                    return dict(r)
        return None

    def get_rules(self) -> List[Dict]:
        with self._lock:
            return [dict(r) for r in self._rules]

    # ──────────────────────────────────────────
    # Quick-Block Helpers
    # ──────────────────────────────────────────
    def quick_block_ip(self, ip: str, direction: str = "both") -> Dict:
        return self.add_rule({
            "name": f"Block {ip}",
            "action": "DENY",
            "direction": direction.upper() if direction.upper() in ("INBOUND", "OUTBOUND") else "BOTH",
            "protocol": "ANY",
            "src_ip": ip if direction in ("inbound", "both") else None,
            "dst_ip": ip if direction in ("outbound", "both") else None,
            "priority": 1,
            "description": f"Quick block for IP {ip}",
        })

    def quick_block_port(self, port: int, protocol: str = "both") -> Dict:
        proto = "ANY" if protocol == "both" else protocol.upper()
        return self.add_rule({
            "name": f"Block port {port}",
            "action": "DENY",
            "direction": "BOTH",
            "protocol": proto,
            "dst_port": port,
            "priority": 1,
            "description": f"Quick block for port {port}/{protocol}",
        })

    # ──────────────────────────────────────────
    # Packet Evaluation
    # ──────────────────────────────────────────
    def evaluate(self, packet: Dict[str, Any]) -> Dict:
        """
        Evaluate a packet against all enabled rules in priority order.
        Returns {"action": "ALLOW"|"DENY", "rule_id": int|None}
        """
        with self._lock:
            rules = [r for r in self._rules if r["enabled"]]

        for rule in rules:
            if self._matches_rule(packet, rule):
                with self._lock:
                    rule["hit_count"] += 1
                return {"action": rule["action"], "rule_id": rule["id"]}

        # Default policy: ALLOW
        return {"action": "ALLOW", "rule_id": None}

    def _matches_rule(self, pkt: Dict, rule: Dict) -> bool:
        """Check if a packet matches a rule's conditions."""
        proto = (pkt.get("protocol") or "").upper()

        # Protocol check
        if rule["protocol"] != "ANY" and proto != rule["protocol"]:
            # Allow TCP-based application protocols (HTTP, HTTPS, SSH) to match TCP rules
            tcp_app = {"HTTP", "HTTPS", "SSH", "FTP", "SMTP", "MYSQL", "POSTGRESQL"}
            udp_app = {"DNS"}
            if rule["protocol"] == "TCP" and proto not in tcp_app:
                return False
            if rule["protocol"] == "UDP" and proto not in udp_app:
                return False
            if rule["protocol"] not in ("TCP", "UDP") and rule["protocol"] != proto:
                return False

        # IP checks (CIDR-aware)
        if rule["src_ip"] and pkt.get("src_ip"):
            if not self._ip_matches(pkt["src_ip"], rule["src_ip"]):
                return False
        if rule["dst_ip"] and pkt.get("dst_ip"):
            if not self._ip_matches(pkt["dst_ip"], rule["dst_ip"]):
                return False

        # Port checks
        if rule["src_port"] is not None:
            if pkt.get("src_port") != rule["src_port"]:
                return False
        if rule["dst_port"] is not None:
            if pkt.get("dst_port") != rule["dst_port"]:
                return False

        return True

    def _ip_matches(self, packet_ip: str, rule_ip: str) -> bool:
        """Check if packet_ip matches a rule IP (exact or CIDR)."""
        try:
            network = ipaddress.ip_network(rule_ip, strict=False)
            return ipaddress.ip_address(packet_ip) in network
        except ValueError:
            return packet_ip == rule_ip

    # ──────────────────────────────────────────
    # Blocked Packet Log
    # ──────────────────────────────────────────
    def log_blocked(self, packet: Dict):
        entry = {
            "timestamp": packet.get("timestamp"),
            "src_ip": packet.get("src_ip"),
            "dst_ip": packet.get("dst_ip"),
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "protocol": packet.get("protocol"),
            "rule_id": packet.get("fw_rule"),
            "size": packet.get("size"),
        }
        with self._lock:
            self._blocked_log.append(entry)
            if len(self._blocked_log) > 5000:
                self._blocked_log = self._blocked_log[-5000:]

    def get_blocked_log(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            return list(reversed(self._blocked_log[-limit:]))

    # ──────────────────────────────────────────
    # iptables Integration (Linux only)
    # ──────────────────────────────────────────
    def _check_iptables(self) -> bool:
        try:
            subprocess.run(["iptables", "--version"], capture_output=True, check=True)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def _apply_iptables(self, rule: Dict, add: bool = True):
        """Translate a rule to an iptables command and execute it."""
        cmd_base = ["iptables"]
        action_flag = "-A" if add else "-D"

        chains = []
        if rule["direction"] in ("INBOUND", "BOTH"):
            chains.append("INPUT")
        if rule["direction"] in ("OUTBOUND", "BOTH"):
            chains.append("OUTPUT")

        for chain in chains:
            cmd = cmd_base + [action_flag, chain]

            if rule["protocol"] != "ANY":
                cmd += ["-p", rule["protocol"].lower()]

            if rule["src_ip"]:
                cmd += ["-s", rule["src_ip"]]
            if rule["dst_ip"]:
                cmd += ["-d", rule["dst_ip"]]
            if rule["src_port"]:
                cmd += ["--sport", str(rule["src_port"])]
            if rule["dst_port"]:
                cmd += ["--dport", str(rule["dst_port"])]

            target = "DROP" if rule["action"] == "DENY" else "ACCEPT"
            cmd += ["-j", target]

            try:
                subprocess.run(cmd, check=True, capture_output=True)
                logger.info(f"iptables: {' '.join(cmd)}")
            except subprocess.CalledProcessError as e:
                logger.error(f"iptables failed: {e.stderr.decode()}")

    # ──────────────────────────────────────────
    # Windows Firewall Integration
    # ──────────────────────────────────────────
    def _check_admin_windows(self) -> bool:
        """Return True if the current process has Administrator privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _apply_windows_firewall(self, rule: Dict, add: bool = True):
        """
        Sync a DENY rule to Windows Firewall via netsh.
        Must be run as Administrator for this to take effect.

        Direction-aware IP mapping:
          INBOUND  rule: remote machine is the SOURCE  → remoteip = src_ip
          OUTBOUND rule: remote machine is the DEST    → remoteip = dst_ip

        netsh direction meanings:
          dir=in  → traffic coming INTO this machine   (Echo Reply from Google)
          dir=out → traffic going  OUT of this machine (Echo Request to Google)
        """

        # ── Admin check — fail loudly so user knows why it didn't work ──
        if not self._check_admin_windows():
            logger.error(
                "Windows Firewall enforcement SKIPPED — "
                "NetGuard must be run as Administrator. "
                "Right-click your terminal → 'Run as administrator' and restart."
            )
            return

        # Unique name per rule+direction so delete works precisely
        rule_name = f"NetGuard_{rule['id']}_{rule['name'].replace(' ', '_')}"

        # Map protocol names to netsh values
        proto_map = {
            "TCP":  "TCP",
            "UDP":  "UDP",
            "ICMP": "icmpv4",  # icmpv4 covers standard IPv4 ping
            "ANY":  "any",
        }
        proto = proto_map.get(rule["protocol"], "any")

        # Build one netsh command per direction
        directions = []
        if rule["direction"] in ("INBOUND", "BOTH"):
            directions.append("in")
        if rule["direction"] in ("OUTBOUND", "BOTH"):
            directions.append("out")

        for direction in directions:
            if add:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_{direction}",
                    f"protocol={proto}",
                    f"dir={direction}",
                    "action=block",
                    "enable=yes",
                ]

                # ── Direction-aware IP assignment ──────────────────────────
                # For INBOUND (dir=in):
                #   "remoteip" = who is SENDING to us = src_ip in our rule
                #   "localip"  = our own machine      = dst_ip in our rule
                # For OUTBOUND (dir=out):
                #   "remoteip" = who we are SENDING to = dst_ip in our rule
                #   "localip"  = our own machine       = src_ip in our rule
                if direction == "in":
                    if rule.get("src_ip"):   # e.g. only block ICMP from 8.8.8.8
                        cmd += [f"remoteip={rule['src_ip']}"]
                    if rule.get("dst_ip"):   # e.g. only when destined to our specific IP
                        cmd += [f"localip={rule['dst_ip']}"]
                else:  # direction == "out"
                    if rule.get("dst_ip"):   # e.g. only block traffic going to 8.8.8.8
                        cmd += [f"remoteip={rule['dst_ip']}"]
                    if rule.get("src_ip"):   # e.g. only when sourced from our specific IP
                        cmd += [f"localip={rule['src_ip']}"]

                # Ports only apply to TCP/UDP — netsh rejects them for ICMP/any
                if proto in ("TCP", "UDP"):
                    if rule.get("dst_port"):
                        # localport = port on THIS machine
                        # For outbound that's the source port; for inbound it's dest
                        if direction == "in":
                            cmd += [f"localport={rule['dst_port']}"]
                        else:
                            cmd += [f"remoteport={rule['dst_port']}"]
                    if rule.get("src_port"):
                        if direction == "in":
                            cmd += [f"remoteport={rule['src_port']}"]
                        else:
                            cmd += [f"localport={rule['src_port']}"]

            else:
                # Delete rule by exact name
                cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}_{direction}",
                ]

            try:
                result = subprocess.run(
                    cmd, check=True, capture_output=True, text=True
                )
                logger.info(f"Windows Firewall {'added' if add else 'removed'}: "
                            f"[{direction.upper()}] {rule['name']} | cmd: {' '.join(cmd)}")
            except subprocess.CalledProcessError as e:
                logger.error(
                    f"Windows Firewall command failed:\n"
                    f"  CMD : {' '.join(cmd)}\n"
                    f"  ERR : {e.stderr or e.stdout}"
                )