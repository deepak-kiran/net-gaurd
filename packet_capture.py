"""
NetGuard — Packet Capture Engine
Handles raw packet sniffing via Scapy with thread-safe operation.
Supports multiple interfaces, PCAP export, and packet normalization.
"""

import threading
import time
import logging
from datetime import datetime
from typing import Callable, Optional, List, Dict, Any

try:
    from scapy.all import (
        sniff, get_if_list, wrpcap,
        Raw, conf
    )
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available — running in simulation mode")

logger = logging.getLogger("NetGuard.Capture")


class PacketCaptureEngine:
    """
    Core packet sniffing module.
    
    Uses Scapy's AsyncSniffer for non-blocking capture.
    Each captured packet is:
      1. Parsed into a normalized dict
      2. Checked against firewall rules
      3. Checked against active display filters
      4. Broadcast to the UI via callback
    """

    def __init__(self, filter_engine, firewall_engine, stats_engine, packet_callback: Optional[Callable] = None):
        self.filter_engine = filter_engine
        self.firewall_engine = firewall_engine
        self.stats_engine = stats_engine
        self.packet_callback = packet_callback

        self.is_running = False
        self.current_interface = None
        self.total_captured = 0
        self._sniffer = None
        self._lock = threading.Lock()
        self._packet_buffer: List[Dict] = []  # in-memory buffer for PCAP export
        self._raw_buffer = []                  # raw Scapy packets for wrpcap
        self._buffer_limit = 10_000            # max packets kept in memory
        self._packet_id = 0

    # ──────────────────────────────────────────
    # Interface Discovery
    # ──────────────────────────────────────────
    def list_interfaces(self) -> List[str]:
        """Return all available network interfaces."""
        if not SCAPY_AVAILABLE:
            return ["eth0", "lo", "wlan0"]  # simulated
        try:
            ifaces = get_if_list()
            # Filter out obviously non-useful ones but keep loopback for testing
            return ifaces if ifaces else ["any"]
        except Exception as e:
            logger.error(f"Failed to list interfaces: {e}")
            return ["any"]

    # ──────────────────────────────────────────
    # Capture Lifecycle
    # ──────────────────────────────────────────
    def start(self, interface: str = "any"):
        """Start packet capture on the specified interface."""
        with self._lock:
            if self.is_running:
                self.stop()

            self.current_interface = interface
            self.is_running = True
            logger.info(f"Starting capture on: {interface}")

            if not SCAPY_AVAILABLE:
                # Simulation mode — generate fake packets for demo
                self._sim_thread = threading.Thread(target=self._simulate_packets, daemon=True)
                self._sim_thread.start()
                return

            try:
                # store=False means don't accumulate in memory inside scapy
                # prn=callback means process each packet immediately
                self._sniffer = AsyncSniffer(
                    iface=interface if interface != "any" else None,
                    prn=self._process_packet,
                    store=False,
                    filter="",  # capture everything; filter in software
                )
                self._sniffer.start()
            except Exception as e:
                self.is_running = False
                raise RuntimeError(f"Capture failed to start: {e}")

    def stop(self):
        """Stop packet capture gracefully."""
        with self._lock:
            self.is_running = False
            if self._sniffer and SCAPY_AVAILABLE:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
                self._sniffer = None
            logger.info("Capture stopped")

    # ──────────────────────────────────────────
    # Packet Processing Pipeline
    # ──────────────────────────────────────────
    def _process_packet(self, pkt):
        """
        Main packet processing pipeline:
        parse → firewall check → filter check → broadcast
        """
        try:
            parsed = self._parse_packet(pkt)
            if parsed is None:
                return

            self.total_captured += 1

            # ── Firewall check ──────────────────
            fw_result = self.firewall_engine.evaluate(parsed)
            parsed["fw_action"] = fw_result["action"]
            parsed["fw_rule"] = fw_result.get("rule_id")
            if fw_result["action"] == "DENY":
                parsed["blocked"] = True
                self.firewall_engine.log_blocked(parsed)
            else:
                parsed["blocked"] = False

            # ── Buffer for PCAP export ──────────
            if len(self._packet_buffer) >= self._buffer_limit:
                self._packet_buffer.pop(0)
                if self._raw_buffer:
                    self._raw_buffer.pop(0)
            self._packet_buffer.append(parsed)
            if SCAPY_AVAILABLE:
                self._raw_buffer.append(pkt)

            # ── Display filter check ────────────
            if not self.filter_engine.matches(parsed):
                return  # don't broadcast if filtered out

            # ── Broadcast to UI ─────────────────
            if self.packet_callback:
                self.packet_callback(parsed)

        except Exception as e:
            logger.debug(f"Packet parse error (likely malformed): {e}")

    def _parse_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """
        Normalize a Scapy packet into a serializable dictionary.
        Handles IP, IPv6, TCP, UDP, ICMP, ARP, DNS layers.
        """
        with self._lock:
            self._packet_id += 1
            pid = self._packet_id

        record = {
            "id": pid,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "epoch": time.time(),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": "UNKNOWN",
            "size": len(bytes(pkt)),
            "ttl": None,
            "flags": None,
            "info": "",
            "layers": [],
            "raw_summary": pkt.summary() if SCAPY_AVAILABLE else "",
        }

        if not SCAPY_AVAILABLE:
            return record

        # ── Ethernet ───────────────────────────
        if pkt.haslayer(Ether):
            record["layers"].append("Ethernet")
            record["src_mac"] = pkt[Ether].src
            record["dst_mac"] = pkt[Ether].dst

        # ── IP (v4) ────────────────────────────
        if pkt.haslayer(IP):
            ip = pkt[IP]
            record["src_ip"] = ip.src
            record["dst_ip"] = ip.dst
            record["ttl"] = ip.ttl
            record["layers"].append("IP")

        # ── IPv6 ───────────────────────────────
        elif pkt.haslayer(IPv6):
            ipv6 = pkt[IPv6]
            record["src_ip"] = ipv6.src
            record["dst_ip"] = ipv6.dst
            record["layers"].append("IPv6")

        # ── ARP ────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            record["protocol"] = "ARP"
            record["src_ip"] = arp.psrc
            record["dst_ip"] = arp.pdst
            record["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"
            record["layers"].append("ARP")
            return record

        # ── TCP ────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            record["protocol"] = "TCP"
            record["src_port"] = tcp.sport
            record["dst_port"] = tcp.dport
            record["flags"] = str(tcp.flags)
            record["layers"].append("TCP")

            # Detect common application protocols by port
            well_known = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                          25: "SMTP", 53: "DNS", 3306: "MySQL", 5432: "PostgreSQL",
                          6379: "Redis", 27017: "MongoDB", 8080: "HTTP-Alt"}
            for port in [tcp.dport, tcp.sport]:
                if port in well_known:
                    record["protocol"] = well_known[port]
                    break

            flag_map = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST",
                        "P": "PSH", "U": "URG", "SA": "SYN-ACK", "FA": "FIN-ACK"}
            flag_str = flag_map.get(str(tcp.flags), str(tcp.flags))
            record["info"] = f"{tcp.sport} → {tcp.dport} [{flag_str}]"

        # ── UDP ────────────────────────────────
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            record["protocol"] = "UDP"
            record["src_port"] = udp.sport
            record["dst_port"] = udp.dport
            record["layers"].append("UDP")

            if udp.dport == 53 or udp.sport == 53:
                record["protocol"] = "DNS"
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    if dns.qr == 0 and dns.qdcount > 0:
                        record["info"] = f"Query: {dns.qd.qname.decode()}"
                    else:
                        record["info"] = f"Response ({dns.ancount} answers)"
            record["info"] = record["info"] or f"{udp.sport} → {udp.dport}"

        # ── ICMP ───────────────────────────────
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            record["protocol"] = "ICMP"
            type_map = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                        11: "Time Exceeded", 5: "Redirect"}
            record["info"] = type_map.get(icmp.type, f"Type {icmp.type}")
            record["layers"].append("ICMP")

        # ── Raw payload size ───────────────────
        if pkt.haslayer(Raw):
            record["payload_size"] = len(pkt[Raw].load)

        return record

    # ──────────────────────────────────────────
    # PCAP Export
    # ──────────────────────────────────────────
    def export_pcap(self, filepath: str) -> int:
        """Export buffered raw packets to a PCAP file."""
        if not SCAPY_AVAILABLE or not self._raw_buffer:
            # Write a dummy file for demo mode
            with open(filepath, "wb") as f:
                f.write(b"")  # empty file in demo mode
            return 0
        pkts = list(self._raw_buffer)
        wrpcap(filepath, pkts)
        logger.info(f"Exported {len(pkts)} packets to {filepath}")
        return len(pkts)

    # ──────────────────────────────────────────
    # Simulation Mode (no root / no scapy)
    # ──────────────────────────────────────────
    def _simulate_packets(self):
        """Generate realistic fake packets for demo/testing purposes."""
        import random
        protocols = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SSH", "ARP"]
        ips_src = ["192.168.1.10", "10.0.0.5", "172.16.0.3", "8.8.8.8",
                   "1.1.1.1", "192.168.1.100", "203.0.113.42", "198.51.100.7"]
        ips_dst = ["192.168.1.1", "8.8.8.8", "1.1.1.1", "10.0.0.1",
                   "172.217.14.206", "151.101.1.140", "192.168.1.255"]
        ports_common = [80, 443, 22, 53, 8080, 3306, 6379, 25, 21, 3389]

        tcp_flags = ["SYN", "ACK", "SYN-ACK", "FIN", "RST", "PSH"]

        while self.is_running:
            proto = random.choice(protocols)
            src_ip = random.choice(ips_src)
            dst_ip = random.choice(ips_dst)
            src_port = random.choice(ports_common) if proto in ("TCP", "UDP") else None
            dst_port = random.choice(ports_common) if proto in ("TCP", "UDP") else None

            pkt = {
                "id": self._packet_id + 1,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "epoch": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "size": random.randint(64, 1500),
                "ttl": random.randint(32, 128),
                "flags": random.choice(tcp_flags) if proto == "TCP" else None,
                "info": f"{src_port} → {dst_port}" if src_port else f"{proto} packet",
                "layers": ["Ethernet", "IP", proto],
                "raw_summary": f"{src_ip}:{src_port} → {dst_ip}:{dst_port} [{proto}]",
                "blocked": False,
                "fw_action": "ALLOW",
                "fw_rule": None,
            }

            with self._lock:
                self._packet_id += 1
                pkt["id"] = self._packet_id
            self.total_captured += 1

            fw_result = self.firewall_engine.evaluate(pkt)
            pkt["fw_action"] = fw_result["action"]
            pkt["fw_rule"] = fw_result.get("rule_id")
            pkt["blocked"] = fw_result["action"] == "DENY"
            if pkt["blocked"]:
                self.firewall_engine.log_blocked(pkt)

            if len(self._packet_buffer) >= self._buffer_limit:
                self._packet_buffer.pop(0)
            self._packet_buffer.append(pkt)

            if self.filter_engine.matches(pkt):
                if self.packet_callback:
                    self.packet_callback(pkt)

            # Simulate realistic traffic bursts (5–30 packets/sec)
            time.sleep(random.uniform(0.03, 0.2))


# ──────────────────────────────────────────────
# AsyncSniffer shim (graceful fallback)
# ──────────────────────────────────────────────
class _AsyncSnifferFallback:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.thread = None
        self._running = False

    def start(self):
        self._running = True
        # Ensure 'sniff' is imported/available here
        self.thread = threading.Thread(
            target=lambda: sniff(**self.kwargs),
            daemon=True
        )
        self.thread.start()

    def stop(self):
        self._running = False

if SCAPY_AVAILABLE:
    try:
        from scapy.all import AsyncSniffer as ScapyAsyncSniffer
        AsyncSniffer = ScapyAsyncSniffer  # No collision!
    except (ImportError, AttributeError):
        AsyncSniffer = _AsyncSnifferFallback
else:
    AsyncSniffer = _AsyncSnifferFallback