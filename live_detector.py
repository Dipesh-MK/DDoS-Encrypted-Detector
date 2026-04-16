"""
Live DDoS Detector + ACL Blocker (with Explainability)
Now shows WHY a flow was flagged as DDoS.
"""

import os, sys, json, time, joblib, argparse, logging, threading, queue
from collections import defaultdict
from datetime import datetime

import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from colorama import init, Fore, Style

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.FileHandler("detector_log.txt"), logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# ── Firewall blocking (unchanged) ──────────────────────────────────────
BLOCKED_IPS   = set()
BLOCK_LOCK    = threading.Lock()
WHITELIST_IPS = {'127.0.0.1', '::1'}

def block_ip(ip: str, reason: str):
    with BLOCK_LOCK:
        if ip in BLOCKED_IPS or ip in WHITELIST_IPS: return
        BLOCKED_IPS.add(ip)
    log.warning(f"{Fore.RED}[BLOCK] {ip}  — {reason}")
    # ... (firewall code remains the same)
    if sys.platform.startswith('linux'):
        os.system(f"iptables -A INPUT  -s {ip} -j DROP 2>/dev/null")
        os.system(f"iptables -A OUTPUT -d {ip} -j DROP 2>/dev/null")
    elif sys.platform == 'win32':
        os.system(f'netsh advfirewall firewall add rule name="DDOS_BLOCK_{ip}" dir=in action=block remoteip={ip} 2>nul')
    with open("blocked_ips.txt", "a") as f:
        f.write(f"{datetime.utcnow().isoformat()}\t{ip}\t{reason}\n")

def unblock_all():
    log.info("Removing firewall rules...")
    if sys.platform.startswith('linux'):
        for ip in BLOCKED_IPS:
            os.system(f"iptables -D INPUT  -s {ip} -j DROP 2>/dev/null")
            os.system(f"iptables -D OUTPUT -d {ip} -j DROP 2>/dev/null")
    elif sys.platform == 'win32':
        for ip in BLOCKED_IPS:
            os.system(f'netsh advfirewall firewall delete rule name="DDOS_BLOCK_{ip}" 2>nul')

# ── FlowTracker (unchanged except min_packets default) ───────────────
class FlowTracker:
    def __init__(self, timeout=10.0, min_packets=2):
        self.flows = defaultdict(list)
        self.timeout = timeout
        self.min_pkts = min_packets
        self.lock = threading.Lock()

    def flow_key(self, pkt):
        if not pkt.haslayer(IP): return None
        proto = pkt[IP].proto
        src, dst = pkt[IP].src, pkt[IP].dst
        sp = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dp = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        pair = tuple(sorted([(src, sp), (dst, dp)]))
        return (pair[0], pair[1], proto)

    def add(self, pkt):
        k = self.flow_key(pkt)
        if not k: return
        with self.lock:
            self.flows[k].append(pkt)

    def get_src_ip(self, key):
        return key[0][0]

    def harvest_ready(self):
        ready = []
        now = time.time()
        with self.lock:
            to_del = []
            for k, pkts in self.flows.items():
                last_time = float(pkts[-1].time)
                fin_rst = any(p.haslayer(TCP) and (p[TCP].flags & 0x01 or p[TCP].flags & 0x04) for p in pkts[-3:])
                if (now - last_time > self.timeout) or fin_rst:
                    if len(pkts) >= self.min_pkts:
                        ready.append((k, pkts))
                    to_del.append(k)
            for k in to_del:
                del self.flows[k]
        return ready

    def features(self, pkts):
        # (same as before - unchanged)
        times = np.array([float(p.time) for p in pkts])
        sizes = np.array([len(p) for p in pkts])
        dur = times[-1] - times[0]
        iats = np.diff(times)
        n = len(pkts)
        payloads = np.array([len(bytes(p[TCP].payload)) for p in pkts if p.haslayer(TCP)] or [0])

        flags = lambda f: sum(1 for p in pkts if p.haslayer(TCP) and p[TCP].flags & f)
        syn = flags(0x02); ack = flags(0x10); fin = flags(0x01); rst = flags(0x04); psh = flags(0x08)
        dports = [p[TCP].dport for p in pkts if p.haslayer(TCP)]

        return {
            'pkt_count': n, 'total_bytes': int(sizes.sum()), 'duration_s': dur,
            'pps': n / dur if dur > 0 else float(n),
            'bps': sizes.sum() / dur if dur > 0 else float(sizes.sum()),
            'iat_mean': iats.mean() if len(iats) else 0,
            'iat_std': iats.std() if len(iats) else 0,
            'iat_max': iats.max() if len(iats) else 0,
            'iat_min': iats.min() if len(iats) else 0,
            'pkt_size_mean': sizes.mean(), 'pkt_size_std': sizes.std(),
            'payload_mean': payloads.mean(), 'payload_std': payloads.std(),
            'syn_ratio': syn/n, 'fin_ratio': fin/n, 'rst_ratio': rst/n,
            'bytes_per_pkt': sizes.sum()/n,
            'tls_port': int(any(d in [443, 8443, 8080] for d in dports)),
        }

# ── Detector with Explainability ─────────────────────────────────────
class Detector:
    def __init__(self, model_path, config_path, threshold=None):
        with open(config_path) as f:
            self.config = json.load(f)

        self.model = joblib.load(model_path)
        self.scaler = joblib.load('scaler.pkl') if os.path.exists('scaler.pkl') else None
        self.features = self.config['features']
        self.threshold = threshold or self.config.get('threshold', 0.5)
        self.needs_sc = self.config.get('needs_scale', False)

        log.info(f"Model loaded: {self.config['model_name']} (threshold={self.threshold})")
        log.info(f"Features: {self.features}")

        # Print global feature importance (transparency)
        if hasattr(self.model, 'feature_importances_'):
            imp = self.model.feature_importances_
            idx = np.argsort(imp)[::-1][:10]
            print(f"\n{Fore.CYAN}=== TOP 10 IMPORTANT FEATURES ===")
            for i in idx:
                print(f"   {self.features[i]:<18} : {imp[i]:.4f}")
            print("=" * 40)

    def predict(self, feat_dict):
        row = np.array([[feat_dict.get(f, 0) for f in self.features]], dtype=float)
        row = np.nan_to_num(row, nan=0, posinf=0, neginf=0)
        if self.needs_sc and self.scaler:
            row = self.scaler.transform(row)
        prob = self.model.predict_proba(row)[0][1]
        return prob, prob >= self.threshold

# ── Rest of the code (Stats, main, etc.) remains the same but alert is improved ─
class Stats:
    def __init__(self):
        self.flows_total = 0
        self.ddos_count = 0
        self.normal_count = 0
        self.lock = threading.Lock()
        self.start = time.time()

    def update(self, is_ddos):
        with self.lock:
            self.flows_total += 1
            if is_ddos: self.ddos_count += 1
            else: self.normal_count += 1

    def print_dashboard(self):
        elapsed = time.time() - self.start
        with self.lock:
            total = self.flows_total
            ddos = self.ddos_count
            norm = self.normal_count
        rate = total / elapsed if elapsed > 0 else 0
        print(f"\r{Fore.CYAN}[{datetime.now().strftime('%H:%M:%S')}] Flows: {total} | {Fore.RED}DDoS: {ddos} {Fore.GREEN}Normal: {norm} | Blocked: {len(BLOCKED_IPS)} | Rate: {rate:.1f} flows/s", end="", flush=True)

def main():
    parser = argparse.ArgumentParser(description="Live DDoS Detector + Explainable Alerts")
    parser.add_argument("--interface", "-i", default=None)
    parser.add_argument("--model", default="ddos_model_hybrid.pkl")
    parser.add_argument("--config", default="model_config_hybrid.json")
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--flow-timeout", type=float, default=10.0)
    parser.add_argument("--min-packets", type=int, default=2)
    parser.add_argument("--no-block", action="store_true")
    parser.add_argument("--pcap", default=None)
    parser.add_argument("--verbose", action="store_true", help="Show detailed feature explanation on every alert")
    args = parser.parse_args()

    if not os.path.exists(args.model) or not os.path.exists(args.config):
        print("ERROR: Model or config file not found!")
        sys.exit(1)

    detector = Detector(args.model, args.config, args.threshold)
    tracker = FlowTracker(timeout=args.flow_timeout, min_packets=args.min_packets)
    stats = Stats()
    pkt_q = queue.Queue()

    def packet_handler(pkt):
        if args.pcap:
            time.sleep(0.01)
            if pkt.haslayer(IP):
                proto_name = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER")
                print(f"{Fore.BLUE}[PCAP SEQ] {pkt[IP].src:<15} -> {pkt[IP].dst:<15} | {proto_name:<5} | Len: {len(pkt)}", flush=True)
        pkt_q.put(pkt)

    def capture_thread():
        if args.pcap:
            log.info(f"Replaying: {args.pcap}")
            sniff(offline=args.pcap, prn=packet_handler, store=False)
        else:
            log.info(f"Sniffing on: {args.interface or 'default'}")
            sniff(iface=args.interface, prn=packet_handler, store=False, filter="tcp or udp")

    cap_t = threading.Thread(target=capture_thread, daemon=True)
    cap_t.start()

    log.info(f"{'[DRY RUN] ' if args.no_block else ''}Live detection started. Ctrl+C to stop.\n")

    try:
        last_dashboard = 0
        while True:
            try:
                while True:
                    pkt = pkt_q.get_nowait()
                    tracker.add(pkt)
            except queue.Empty:
                pass

            for key, pkts in tracker.harvest_ready():
                src_ip = tracker.get_src_ip(key)
                if src_ip in BLOCKED_IPS: continue

                feat = tracker.features(pkts)
                prob, is_ddos = detector.predict(feat)

                stats.update(is_ddos)

                if is_ddos:
                    reason = f"ML={prob:.3f} pps={feat['pps']:.1f} iat={feat['iat_mean']:.4f}"
                    log.warning(f"\n{Fore.RED}[ALERT] DDoS detected  src={src_ip}  confidence={prob:.1%}  {reason}")

                    # === TRANSPARENT EXPLANATION ===
                    if args.verbose:
                        print(f"{Fore.YELLOW}   Why flagged? Key features:")
                        key_features = ['pps', 'iat_max', 'iat_std', 'iat_mean', 'syn_ratio', 'pkt_count', 'bytes_per_pkt', 'payload_std']
                        for f in key_features:
                            if f in feat:
                                print(f"      {f:<14} = {feat[f]:.4f}")
                    else:
                        print(f"{Fore.YELLOW}   (Run with --verbose for full feature explanation)")

                    if not args.no_block:
                        block_ip(src_ip, reason)

            now = time.time()
            if now - last_dashboard > 1.0:
                stats.print_dashboard()
                last_dashboard = now

            time.sleep(0.05)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Stopping detector...")
        if not args.no_block:
            unblock_all()
        log.info(f"Session summary: {stats.flows_total} flows | DDoS={stats.ddos_count} | Normal={stats.normal_count} | Blocked={len(BLOCKED_IPS)}")

if __name__ == "__main__":
    main()