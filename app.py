"""
NetGuard - Main Flask Application Server
Provides REST API and WebSocket endpoints for the frontend.
Acts as the orchestration layer between all modules.
"""

import os
import sys
import json
import time
import threading
import logging
from datetime import datetime
from flask import Flask, jsonify, send_from_directory, request
from flask import request as flask_request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Internal modules
from packet_capture import PacketCaptureEngine
from filter_engine import FilterEngine
from firewall_engine import FirewallEngine
from stats_engine import StatsEngine

# ──────────────────────────────────────────────
# App Initialization
# ──────────────────────────────────────────────
app = Flask(__name__, static_folder="../frontend", static_url_path="")
app.config["SECRET_KEY"] = "netguard-secret-2024"
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("netguard.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("NetGuard")

# ──────────────────────────────────────────────
# Engine Instances (shared singletons)
# ──────────────────────────────────────────────
filter_engine = FilterEngine()
firewall_engine = FirewallEngine(use_iptables=True)
stats_engine = StatsEngine()
capture_engine = PacketCaptureEngine(
    filter_engine=filter_engine,
    firewall_engine=firewall_engine,
    stats_engine=stats_engine,
    packet_callback=None,  # set after socketio is ready
)


def broadcast_packet(packet_data: dict):
    """Called by capture engine when a new packet is processed."""
    socketio.emit("packet", packet_data)
    stats_engine.update(packet_data)
    # Broadcast updated stats every 10 packets
    if stats_engine.packet_count % 10 == 0:
        socketio.emit("stats", stats_engine.get_stats())


capture_engine.packet_callback = broadcast_packet

# ──────────────────────────────────────────────
# Serve Frontend
# ──────────────────────────────────────────────
import os

# Get the directory where app.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


# ──────────────────────────────────────────────
# REST API — Interfaces
# ──────────────────────────────────────────────
@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """Return available network interfaces."""
    interfaces = capture_engine.list_interfaces()
    return jsonify({"interfaces": interfaces})


# ──────────────────────────────────────────────
# REST API — Capture Control
# ──────────────────────────────────────────────
@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    data = flask_request.json or {}
    iface = data.get("interface", "any")
    try:
        capture_engine.start(interface=iface)
        logger.info(f"Capture started on interface: {iface}")
        return jsonify({"status": "started", "interface": iface})
    except Exception as e:
        logger.error(f"Failed to start capture: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    capture_engine.stop()
    logger.info("Capture stopped")
    return jsonify({"status": "stopped"})


@app.route("/api/capture/status", methods=["GET"])
def capture_status():
    return jsonify({
        "running": capture_engine.is_running,
        "interface": capture_engine.current_interface,
        "packet_count": capture_engine.total_captured,
    })


# ──────────────────────────────────────────────
# REST API — Export
# ──────────────────────────────────────────────
@app.route("/api/capture/export", methods=["POST"])
def export_capture():
    """Export captured packets to PCAP file."""
    data = flask_request.json or {}
    filename = data.get("filename", f"capture_{int(time.time())}.pcap")
    filepath = os.path.join("exports", filename)
    os.makedirs("exports", exist_ok=True)
    try:
        count = capture_engine.export_pcap(filepath)
        return jsonify({"status": "exported", "file": filepath, "packets": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────
# REST API — Filter Engine
# ──────────────────────────────────────────────
@app.route("/api/filter", methods=["POST"])
def set_filter():
    data = flask_request.json or {}
    expression = data.get("expression", "")
    result = filter_engine.set_filter(expression)
    return jsonify(result)


@app.route("/api/filter", methods=["GET"])
def get_filter():
    return jsonify({"expression": filter_engine.current_expression})


@app.route("/api/filter/clear", methods=["POST"])
def clear_filter():
    filter_engine.clear()
    return jsonify({"status": "cleared"})


# ──────────────────────────────────────────────
# REST API — Firewall Rules
# ──────────────────────────────────────────────
@app.route("/api/firewall/rules", methods=["GET"])
def get_rules():
    return jsonify({"rules": firewall_engine.get_rules()})


@app.route("/api/firewall/rules", methods=["POST"])
def add_rule():
    data = flask_request.json or {}
    try:
        rule = firewall_engine.add_rule(data)
        logger.info(f"Firewall rule added: {rule}")
        return jsonify({"status": "added", "rule": rule})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/firewall/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    success = firewall_engine.delete_rule(rule_id)
    if success:
        logger.info(f"Firewall rule deleted: {rule_id}")
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/firewall/rules/<int:rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    rule = firewall_engine.toggle_rule(rule_id)
    if rule:
        return jsonify({"status": "toggled", "rule": rule})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/firewall/block-ip", methods=["POST"])
def block_ip():
    """Quick-block an IP address."""
    data = flask_request.json or {}
    ip = data.get("ip")
    direction = data.get("direction", "both")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    rule = firewall_engine.quick_block_ip(ip, direction)
    return jsonify({"status": "blocked", "rule": rule})


@app.route("/api/firewall/block-port", methods=["POST"])
def block_port():
    """Quick-block a port."""
    data = flask_request.json or {}
    port = data.get("port")
    protocol = data.get("protocol", "both")
    if not port:
        return jsonify({"error": "Port required"}), 400
    rule = firewall_engine.quick_block_port(int(port), protocol)
    return jsonify({"status": "blocked", "rule": rule})


@app.route("/api/firewall/blocked-log", methods=["GET"])
def get_blocked_log():
    limit = int(flask_request.args.get("limit", 100))
    return jsonify({"log": firewall_engine.get_blocked_log(limit)})


# ──────────────────────────────────────────────
# REST API — Statistics
# ──────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify(stats_engine.get_stats())


@app.route("/api/stats/reset", methods=["POST"])
def reset_stats():
    stats_engine.reset()
    return jsonify({"status": "reset"})


# ──────────────────────────────────────────────
# WebSocket Events
# ──────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    logger.info(f"Client connected: {flask_request.sid}") # type: ignore
    emit("status", {
        "running": capture_engine.is_running,
        "interface": capture_engine.current_interface,
    })


@socketio.on("disconnect")
def on_disconnect():
    logger.info(f"Client disconnected: {flask_request.sid}") # type: ignore


@socketio.on("ping")
def on_ping():
    emit("pong", {"time": datetime.utcnow().isoformat()})


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════╗
║        NetGuard — Packet Analyzer         ║
║        & Firewall Management System       ║
╚═══════════════════════════════════════════╝
  → Web UI: http://localhost:5000
  → API:    http://localhost:5000/api
""")
    # Note: requires root/admin for raw packet capture
    if sys.platform != "win32" and os.geteuid() != 0:
        print("⚠  WARNING: Not running as root. Packet capture may be limited.")
        print("   Run with: sudo python app.py\n")

    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
