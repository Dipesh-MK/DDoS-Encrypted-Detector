import { BookOpen, FileText, Shield, Cpu, Layers, Terminal, Database } from 'lucide-react';

export default function Documentation() {
  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-8 max-w-4xl mx-auto">
      <div className="flex items-center gap-3 mb-8 pb-6 border-b border-slate-200">
        <BookOpen className="w-7 h-7 text-blue-600" />
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Project Documentation</h1>
          <p className="text-sm text-slate-500">Encrypted DDoS Detection &amp; Prevention System</p>
        </div>
      </div>

      <div className="prose-slate max-w-none space-y-8">
        <Section icon={<Shield className="w-5 h-5 text-blue-600"/>} title="1. Overview">
          <p>This project implements an end-to-end <strong>ML-based Encrypted DDoS Detection and Prevention System</strong>.
          It combines a Random Forest classifier trained on the CIC-DDoS2019 dataset, fine-tuned on custom-generated encrypted traffic PCAPs,
          with a live packet sniffer that extracts flow-level features and classifies traffic in real-time.</p>
          <p>
            The system detects <strong>SYN Flood</strong>, <strong>TLS Flood</strong>, and <strong>Slowloris TLS</strong> attacks
            even when the traffic is fully encrypted (TLS 1.3), by analyzing statistical patterns rather than payload content.
          </p>
        </Section>

        <Section icon={<Layers className="w-5 h-5 text-blue-600"/>} title="2. Architecture">
          <ol className="list-decimal list-inside space-y-2 text-slate-700">
            <li><strong>Network Flow Extraction</strong> — Reads raw packets (.pcap or live interface) and groups them into bidirectional flows using 5-tuple keys.</li>
            <li><strong>Feature Engineering</strong> — Calculates 15 statistical features per flow: IAT (mean, std, max), PPS, BPS, packet sizes, payload stats, and TCP flag ratios.</li>
            <li><strong>Machine Learning Model</strong> — A Random Forest classifier (RandomForest_Hybrid_CIC+PCAP) trained on 99,121 CIC flows + 3,112 custom PCAP flows.</li>
            <li><strong>Live Detector</strong> — Sniffs network traffic in real-time, builds flow records, calls the model, and outputs alerts with full explainability.</li>
            <li><strong>Auto-Blocking</strong> — Uses OS-level iptables/netsh commands to automatically block identified attacker IPs.</li>
          </ol>
        </Section>

        <Section icon={<Database className="w-5 h-5 text-blue-600"/>} title="3. Features Analyzed">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {([
              ['iat_max', 'Max time gap between packets. High in Slowloris.'],
              ['pps', 'Packets per second. Extremely high in volumetric floods.'],
              ['iat_std', 'Timing variation. Near-zero in automated attacks.'],
              ['payload_std', 'Payload size variation. Zero in SYN floods.'],
              ['pkt_size_std', 'Packet size variation. Low = homogeneous traffic.'],
              ['iat_mean', 'Average inter-arrival time. Near-zero in floods.'],
              ['payload_mean', 'Avg payload bytes. Zero for pure SYN/ACK attacks.'],
              ['total_bytes', 'Total bytes in flow. Very large in volumetric DDoS.'],
              ['bps', 'Bytes per second bandwidth of the flow.'],
              ['pkt_size_mean', 'Avg packet size. Small = SYN/ACK flood indicator.'],
              ['bytes_per_pkt', 'Bytes per packet ratio for the flow.'],
              ['duration_s', 'Flow duration in seconds. Long in Slowloris.'],
              ['fin_ratio', 'Ratio of FIN flags. Low = connections never close.'],
              ['syn_ratio', 'Ratio of SYN flags. 1.0 = pure SYN flood.'],
              ['pkt_count', 'Total packets in the flow.'],
            ] as const).map(([f, tip]) => (
              <span key={f} className="tip-wrap bg-blue-50 text-blue-700 text-xs font-mono px-3 py-1.5 rounded-lg cursor-help inline-block">
                {f}
                <span className="tip-text">{tip}</span>
              </span>
            ))}
          </div>
        </Section>

        <Section icon={<FileText className="w-5 h-5 text-blue-600"/>} title="4. Project Files">
          <div className="bg-slate-50 rounded-xl p-4 font-mono text-sm text-slate-700 space-y-1">
            <p>├── live_detector.py          <span className="text-slate-400">← Main detector script</span></p>
            <p>├── ddos_model_hybrid.pkl     <span className="text-slate-400">← Trained RF model</span></p>
            <p>├── model_config_hybrid.json  <span className="text-slate-400">← Model features &amp; config</span></p>
            <p>├── scaler.pkl               <span className="text-slate-400">← Feature scaler</span></p>
            <p>├── flows.csv                <span className="text-slate-400">← Extracted flow dataset</span></p>
            <p>├── detector_log.txt         <span className="text-slate-400">← Detection session logs</span></p>
            <p>├── pcaps/</p>
            <p>│   ├── Outputs/             <span className="text-slate-400">← Attacker-side PCAPs</span></p>
            <p>│   └── outputs_server/      <span className="text-slate-400">← Server-side PCAPs</span></p>
            <p>├── eda_*.png                <span className="text-slate-400">← EDA visualization plots</span></p>
            <p>├── feature_importance.png   <span className="text-slate-400">← Feature importance chart</span></p>
            <p>└── model_comparison.png     <span className="text-slate-400">← Model comparison chart</span></p>
          </div>
        </Section>

        <Section icon={<Terminal className="w-5 h-5 text-blue-600"/>} title="5. Running the Detector">
          <p className="text-slate-700 mb-3">Basic usage:</p>
          <div className="bg-slate-900 text-emerald-400 rounded-xl p-4 font-mono text-sm">
            <p># PCAP replay mode (dry run)</p>
            <p>python live_detector.py --pcap pcaps/outputs_server/ddos_tls_flood_server.pcap --no-block --verbose</p>
            <p className="mt-3"># Live capture mode</p>
            <p>python live_detector.py --interface Wi-Fi --threshold 0.85 --verbose</p>
          </div>
          <p className="text-sm text-slate-600 mt-3">
            All command-line arguments: <code>--interface</code>, <code>--model</code>, <code>--config</code>, <code>--threshold</code>,
            <code>--flow-timeout</code>, <code>--min-packets</code>, <code>--no-block</code>, <code>--pcap</code>, <code>--verbose</code>
          </p>
        </Section>

        <Section icon={<Cpu className="w-5 h-5 text-blue-600"/>} title="6. Model Performance">
          <p className="text-slate-700">The hybrid model was trained on CIC-DDoS2019 (99,121 flows) and fine-tuned with 3,112 custom encrypted PCAP flows.</p>
          <div className="grid grid-cols-3 gap-4 mt-4">
            <div className="bg-emerald-50 rounded-xl p-4 text-center">
              <p className="text-2xl font-bold text-emerald-700">99.2%</p>
              <p className="text-xs text-emerald-600 mt-1">Accuracy</p>
            </div>
            <div className="bg-blue-50 rounded-xl p-4 text-center">
              <p className="text-2xl font-bold text-blue-700">0.998</p>
              <p className="text-xs text-blue-600 mt-1">AUC Score</p>
            </div>
            <div className="bg-amber-50 rounded-xl p-4 text-center">
              <p className="text-2xl font-bold text-amber-700">&lt;50ms</p>
              <p className="text-xs text-amber-600 mt-1">Inference Time</p>
            </div>
          </div>
        </Section>
      </div>
    </div>
  );
}

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="text-lg font-bold text-slate-800 flex items-center gap-2 mb-4">{icon} {title}</h2>
      <div className="text-sm text-slate-700 leading-relaxed space-y-3">{children}</div>
    </section>
  );
}
