"""
NetGuard — Statistics Engine
Tracks bandwidth usage, protocol distribution, top talkers,
and time-series data for the dashboard.
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Any


class StatsEngine:
    """
    Maintains rolling statistics with minimal lock contention.
    Updates happen per-packet; reads happen every few seconds from UI.
    """

    HISTORY_WINDOW = 60  # seconds of bandwidth history

    def __init__(self):
        self._lock = threading.Lock()
        self.packet_count = 0
        self.blocked_count = 0
        self.total_bytes = 0
        self.start_time = time.time()

        # Protocol distribution counter
        self._proto_counts: Dict[str, int] = defaultdict(int)

        # Top talkers: src_ip → bytes
        self._src_ip_bytes: Dict[str, int] = defaultdict(int)
        self._dst_ip_bytes: Dict[str, int] = defaultdict(int)

        # Bandwidth time-series: list of (timestamp, bytes_in_interval)
        # One bucket per second for the last HISTORY_WINDOW seconds
        self._bw_history: deque = deque(maxlen=self.HISTORY_WINDOW)
        self._current_bucket_time = int(time.time())
        self._current_bucket_bytes = 0

        # Port stats
        self._port_counts: Dict[int, int] = defaultdict(int)

    def update(self, packet: Dict[str, Any]):
        """Called for every packet that passes through (blocked or not)."""
        with self._lock:
            self.packet_count += 1
            size = packet.get("size", 0)
            self.total_bytes += size

            proto = (packet.get("protocol") or "UNKNOWN").upper()
            self._proto_counts[proto] += 1

            if packet.get("blocked"):
                self.blocked_count += 1

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            if src_ip:
                self._src_ip_bytes[src_ip] += size
            if dst_ip:
                self._dst_ip_bytes[dst_ip] += size

            dst_port = packet.get("dst_port")
            if dst_port:
                self._port_counts[dst_port] += 1

            # Bandwidth bucket
            now_bucket = int(time.time())
            if now_bucket != self._current_bucket_time:
                self._bw_history.append({
                    "t": self._current_bucket_time,
                    "bytes": self._current_bucket_bytes,
                })
                self._current_bucket_time = now_bucket
                self._current_bucket_bytes = size
            else:
                self._current_bucket_bytes += size

    def get_stats(self) -> Dict:
        with self._lock:
            elapsed = max(1, time.time() - self.start_time)
            avg_bps = self.total_bytes / elapsed

            # Top 10 source IPs by bytes
            top_src = sorted(self._src_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
            top_dst = sorted(self._dst_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
            top_ports = sorted(self._port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            # Protocol percentages
            total_p = max(1, self.packet_count)
            proto_dist = [
                {"protocol": k, "count": v, "pct": round(v / total_p * 100, 1)}
                for k, v in sorted(self._proto_counts.items(), key=lambda x: x[1], reverse=True)
            ]

            # Bandwidth history (last 60s)
            bw_history = list(self._bw_history)

            return {
                "packet_count": self.packet_count,
                "blocked_count": self.blocked_count,
                "allowed_count": self.packet_count - self.blocked_count,
                "total_bytes": self.total_bytes,
                "total_mb": round(self.total_bytes / 1024 / 1024, 2),
                "avg_bps": round(avg_bps, 0),
                "avg_kbps": round(avg_bps / 1024, 2),
                "elapsed_sec": round(elapsed, 1),
                "proto_distribution": proto_dist,
                "top_src_ips": [{"ip": ip, "bytes": b, "mb": round(b/1024/1024, 3)} for ip, b in top_src],
                "top_dst_ips": [{"ip": ip, "bytes": b, "mb": round(b/1024/1024, 3)} for ip, b in top_dst],
                "top_ports": [{"port": p, "count": c} for p, c in top_ports],
                "bw_history": bw_history,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

    def reset(self):
        with self._lock:
            self.packet_count = 0
            self.blocked_count = 0
            self.total_bytes = 0
            self.start_time = time.time()
            self._proto_counts.clear()
            self._src_ip_bytes.clear()
            self._dst_ip_bytes.clear()
            self._port_counts.clear()
            self._bw_history.clear()
            self._current_bucket_bytes = 0
            self._current_bucket_time = int(time.time())
