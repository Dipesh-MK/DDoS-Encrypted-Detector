#!/usr/bin/env python3
"""
Lightweight Flask API for network scanning + shared attack state.
Serves as backend for the DDoS Detector Web UI.
"""
import subprocess
import re
import socket
import time
import threading
import platform
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------------
# Shared in-memory attack state (written by Attacker, read by Detector)
# ---------------------------------------------------------------------------
_attack_state = {
    "active": False,
    "type": None,
    "intensity": 0,
    "target": None,
    "attacker_ip": None,
    "started_at": None,
    "packets_sent": 0,
}
_attack_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Network Utilities
# ---------------------------------------------------------------------------
def get_local_ip():
    """Get this machine's primary local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ping_sweep(subnet: str, count: int = 254):
    """
    Blast pings across the entire subnet in parallel to populate the ARP cache.
    Must sweep ALL 254 addresses so high-octet IPs (e.g. .95, .200) get discovered.
    """
    is_win = platform.system() == "Windows"
    threads = []
    for i in range(1, min(count + 1, 255)):
        ip = f"{subnet}.{i}"
        if is_win:
            cmd = ["ping", "-n", "1", "-w", "500", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        t = threading.Thread(
            target=lambda c=cmd: subprocess.run(
                c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5)


def scan_network():
    """
    Discover all live devices on the local subnet.
    1. Full ping sweep (1-254) to populate ARP cache.
    2. Parse 'arp -a' table (handles Windows + macOS/Linux).
    3. Always include self even if ARP misses it.
    """
    local_ip = get_local_ip()
    subnet = ".".join(local_ip.split(".")[:3])
    is_win = platform.system() == "Windows"

    # ---- Step 1: Full subnet sweep ----
    ping_sweep(subnet, count=254)
    time.sleep(1.0)  # give ARP cache time to settle

    devices = []
    seen_ips = set()

    # ---- Step 2: Parse ARP table ----
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=8,
        )

        if is_win:
            # Windows output (space-separated, no parens):
            # "  10.209.250.95         aa-bb-cc-dd-ee-ff     dynamic"
            pattern = re.compile(
                r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([a-fA-F0-9][a-fA-F0-9-]{14,})\s+(\w+)",
                re.MULTILINE,
            )
        else:
            # macOS/Linux output:
            # "? (10.0.0.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
            pattern = re.compile(
                r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+([a-fA-F0-9:]+)",
                re.MULTILINE,
            )

        for match in pattern.finditer(result.stdout):
            ip = match.group(1)
            mac = match.group(2)

            # --- Filters ---
            if ip in seen_ips:
                continue
            if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                continue
            if "ff-ff-ff-ff-ff-ff" in mac.lower() or "ff:ff:ff:ff:ff:ff" in mac.lower():
                continue
            if "incomplete" in mac.lower():
                continue
            if not ip.startswith(subnet):
                continue
            # Skip Windows "static" multicast entries
            if is_win:
                entry_type = match.group(3).lower() if match.lastindex >= 3 else ""
                if entry_type == "static" and not ip == local_ip:
                    # Keep gateway (usually static) but drop pure multicast statics
                    first_octet = int(ip.split(".")[0])
                    if first_octet >= 224:
                        continue

            seen_ips.add(ip)

            hostname = f"Device-{ip.split('.')[-1]}"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

            devices.append({
                "ip": ip,
                "mac": mac,
                "name": hostname,
                "is_self": ip == local_ip,
            })

    except Exception as e:
        return [], str(e)

    # ---- Step 3: Always include self ----
    if not any(d["ip"] == local_ip for d in devices):
        devices.insert(0, {
            "ip": local_ip,
            "mac": "self",
            "name": socket.gethostname(),
            "is_self": True,
        })

    # Self first, then numeric sort
    devices.sort(
        key=lambda d: (not d["is_self"], [int(x) for x in d["ip"].split(".")])
    )
    return devices, None


# ---------------------------------------------------------------------------
# Network Scan Routes
# ---------------------------------------------------------------------------
@app.route("/api/scan", methods=["GET"])
def api_scan():
    devices, error = scan_network()
    if error:
        return jsonify({"error": error, "devices": devices}), 500
    return jsonify({"devices": devices, "count": len(devices)})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "local_ip": get_local_ip()})


# ---------------------------------------------------------------------------
# Attack State Routes (shared between Attacker & Detector tabs)
# ---------------------------------------------------------------------------
@app.route("/api/attack/start", methods=["POST"])
def attack_start():
    data = request.get_json(silent=True) or {}
    traffic_type = data.get("type", "Unknown")
    # Normal traffic is tracked as active so Detector can visualise it too
    with _attack_lock:
        _attack_state.update({
            "active": True,
            "type": data.get("type", "Unknown"),
            "intensity": data.get("intensity", 1),
            "target": data.get("target", ""),
            "attacker_ip": data.get("attacker_ip") or get_local_ip(),
            "started_at": time.time(),
            "packets_sent": 0,
        })
    return jsonify({"status": "started", "state": dict(_attack_state)})


@app.route("/api/attack/update", methods=["POST"])
def attack_update():
    data = request.get_json(silent=True) or {}
    with _attack_lock:
        if _attack_state["active"]:
            _attack_state["packets_sent"] = data.get(
                "packets_sent", _attack_state["packets_sent"]
            )
    return jsonify({"status": "ok"})


@app.route("/api/attack/stop", methods=["POST"])
def attack_stop():
    with _attack_lock:
        _attack_state.update({"active": False, "packets_sent": 0})
    return jsonify({"status": "stopped"})


@app.route("/api/attack/status", methods=["GET"])
def attack_status():
    with _attack_lock:
        return jsonify(dict(_attack_state))


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    local = get_local_ip()
    print(f"\n[Scanner] Network Scanner API starting...")
    print(f"   Local IP: {local}")
    print(f"   Subnet:   {'.'.join(local.split('.')[:3])}.0/24")
    print(f"   Scan:     http://localhost:8001/api/scan")
    print(f"   Health:   http://localhost:8001/api/health")
    print(f"   Attack:   http://localhost:8001/api/attack/status\n")
    app.run(host="0.0.0.0", port=8001, debug=False)
