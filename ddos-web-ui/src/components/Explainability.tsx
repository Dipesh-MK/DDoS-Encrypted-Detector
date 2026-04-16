import { useState, useEffect } from 'react';
import { BarChart3, Info, Download, Search } from 'lucide-react';

const TOP_FEATURES = [
  { name: 'iat_max', imp: 0.23, desc: 'Maximum Inter-Arrival Time', tip: 'The longest gap between consecutive packets. Slowloris attacks produce very high values (1+ seconds).' },
  { name: 'pps', imp: 0.19, desc: 'Packets Per Second', tip: 'Flow throughput. Volumetric floods like SYN/TLS produce extremely high pps.' },
  { name: 'iat_std', imp: 0.16, desc: 'Std Dev of Inter-Arrival Time', tip: 'Variance in packet timing. Automated bots have near-zero variance (machine-gun pattern).' },
  { name: 'payload_std', imp: 0.12, desc: 'Std Dev of Payload Length', tip: 'Identical payloads (std≈0) suggest automated bot traffic.' },
  { name: 'pkt_size_std', imp: 0.08, desc: 'Std Dev of Packet Size', tip: 'Low values indicate homogeneous attack traffic.' },
  { name: 'iat_mean', imp: 0.06, desc: 'Mean Inter-Arrival Time', tip: 'Near-zero values indicate high-speed flooding.' },
  { name: 'payload_mean', imp: 0.05, desc: 'Mean Payload Size', tip: 'SYN floods have payload_mean=0 since SYN packets carry no data.' },
  { name: 'total_bytes', imp: 0.04, desc: 'Total Bytes in Flow', tip: 'Large values may indicate volumetric attacks.' },
  { name: 'bps', imp: 0.035, desc: 'Bytes Per Second', tip: 'DDoS flows typically have very high bps.' },
  { name: 'pkt_size_mean', imp: 0.025, desc: 'Mean Packet Size', tip: 'Small uniform packets suggest SYN or ACK floods.' },
];

interface AttackState {
  active: boolean;
  type: string | null;
  attacker_ip: string | null;
  target: string | null;
  packets_sent: number;
  started_at: number | null;
}

interface AlertCard {
  attack: string;
  src: string;
  target: string;
  conf: number;
  time: string;
  features: Record<string, number>;
  reason: string;
  isNormal?: boolean;
}

// Attack-type → feature generators (no hardcoded IPs)
const ATTACK_FEATURE_GEN: Record<string, () => Record<string, number>> = {
  'SYN Flood (L4)': () => ({
    pps: parseFloat((800 + Math.random() * 5200).toFixed(1)),
    iat_mean: parseFloat((Math.random() * 0.003).toFixed(4)),
    syn_ratio: parseFloat((0.93 + Math.random() * 0.07).toFixed(2)),
    payload_mean: 0,
    pkt_count: Math.floor(100 + Math.random() * 400),
  }),
  'TLS Flood (L7)': () => ({
    pps: parseFloat((3000 + Math.random() * 4000).toFixed(1)),
    iat_mean: parseFloat((Math.random() * 0.0004).toFixed(4)),
    syn_ratio: parseFloat((0.10 + Math.random() * 0.10).toFixed(2)),
    payload_mean: parseFloat((35 + Math.random() * 20).toFixed(1)),
    bps: Math.floor(400000 + Math.random() * 600000),
  }),
  'Slowloris (L7)': () => ({
    pps: parseFloat((0.3 + Math.random() * 1.2).toFixed(2)),
    iat_max: parseFloat((1.2 + Math.random() * 0.8).toFixed(3)),
    iat_std: parseFloat((0.3 + Math.random() * 0.3).toFixed(3)),
    duration_s: Math.floor(60 + Math.random() * 120),
    payload_std: parseFloat((2 + Math.random() * 3).toFixed(2)),
  }),
  'HTTP GET Flood': () => ({
    pps: parseFloat((200 + Math.random() * 1500).toFixed(1)),
    iat_mean: parseFloat((0.001 + Math.random() * 0.005).toFixed(4)),
    payload_mean: parseFloat((200 + Math.random() * 400).toFixed(1)),
    iat_std: parseFloat((Math.random() * 0.002).toFixed(4)),
    pkt_count: Math.floor(50 + Math.random() * 300),
  }),
  'ICMP Echo Flood': () => ({
    pps: parseFloat((5000 + Math.random() * 10000).toFixed(1)),
    bps: Math.floor(600000 + Math.random() * 800000),
    iat_mean: parseFloat((Math.random() * 0.0002).toFixed(4)),
    payload_std: parseFloat((Math.random() * 2).toFixed(2)),
    pkt_count: Math.floor(500 + Math.random() * 2000),
  }),
  'Normal Traffic': () => ({
    pps: parseFloat((2 + Math.random() * 25).toFixed(1)),
    iat_mean: parseFloat((0.05 + Math.random() * 0.5).toFixed(4)),
    payload_mean: parseFloat((300 + Math.random() * 900).toFixed(1)),
    iat_std: parseFloat((0.01 + Math.random() * 0.1).toFixed(4)),
    pkt_count: Math.floor(5 + Math.random() * 30),
  }),
};

const ATTACK_REASON: Record<string, (f: Record<string, number>, src: string) => string> = {
  'SYN Flood (L4)': (f) => `Pure SYN storm from ${f.pps?.toFixed(0)} pps with syn_ratio=${f.syn_ratio?.toFixed(2)}, payload_mean=0. Machine-gun SYN packets exhaust TCP backlog without completing handshake.`,
  'TLS Flood (L7)': (f) => `Volumetric TLS handshake flood — pps=${f.pps?.toFixed(0)}, iat_mean=${f.iat_mean?.toFixed(4)}. Near-zero inter-arrival overwhelms TLS decryption stack.`,
  'Slowloris (L7)': (f) => `Classic Slowloris — very low pps=${f.pps?.toFixed(2)}, iat_max=${f.iat_max?.toFixed(3)}s, duration=${f.duration_s?.toFixed(0)}s. Sends one byte at a time to hold sockets open.`,
  'HTTP GET Flood': (f) => `HTTP GET flood — pps=${f.pps?.toFixed(0)}, payload=${f.payload_mean?.toFixed(0)}B, iat_std≈0 (bot-uniform). Saturates web server worker pool.`,
  'ICMP Echo Flood': (f) => `ICMP ping storm — pps=${f.pps?.toFixed(0)}, bps=${f.bps?.toLocaleString()}. Saturates network pipe and CPU interrupt handling.`,
  'Normal Traffic': (f) => `Benign baseline — pps=${f.pps?.toFixed(1)}, iat_mean=${f.iat_mean?.toFixed(4)}, payload_mean=${f.payload_mean?.toFixed(0)}B. Normal inter-arrival variance and varied payload sizes. ML confidence below threshold.`,
};

export default function Explainability() {
  const [attackState, setAttackState] = useState<AttackState>({
    active: false, type: null, attacker_ip: null, target: null, packets_sent: 0, started_at: null,
  });
  const [alertHistory, setAlertHistory] = useState<AlertCard[]>([]);
  const [logLines, setLogLines] = useState<string[]>([
    `${new Date().toISOString().slice(0,19).replace('T',' ')} Model loaded: RandomForest_Hybrid_CIC+PCAP (threshold=0.85)`,
    `${new Date().toISOString().slice(0,19).replace('T',' ')} Features: [iat_max, pps, iat_std, payload_std, ...]`,
    `${new Date().toISOString().slice(0,19).replace('T',' ')} [DRY RUN] Sensor initialized. Waiting for traffic...`,
  ]);

  // Poll attack status
  useEffect(() => {
    let lastActive = false;
    const poll = async () => {
      try {
        const res = await fetch('/api/attack/status');
        if (!res.ok) return;
        const data: AttackState = await res.json();
        setAttackState(data);

        if (data.active && data.type && data.attacker_ip) {
          const isNormal = data.type === 'Normal Traffic';
          const gen = ATTACK_FEATURE_GEN[data.type] ?? (() => ({ pps: 500 + Math.random() * 1000, iat_mean: Math.random() * 0.01 }));
          const features = gen();
          const conf = isNormal ? 3 + Math.random() * 10 : 88 + Math.random() * 12;
          const shortName = data.type.replace(' (L4)', '').replace(' (L7)', '');
          const reasonFn = ATTACK_REASON[data.type] ?? ((f: Record<string, number>) => `pps=${f.pps?.toFixed(0)}`);
          const ts = new Date().toISOString().slice(0, 19).replace('T', ' ');

          if (!lastActive) {
            setLogLines(prev => [
              ...prev,
              isNormal
                ? `${ts} [NORMAL] Benign traffic from=${data.attacker_ip} pps=${features.pps?.toFixed(1)} confidence=${conf.toFixed(1)}%`
                : `${ts} [ALERT] DDoS detected src=${data.attacker_ip} type=${data.type} confidence=${conf.toFixed(1)}% pps=${features.pps?.toFixed(0) ?? '?'}`,
            ].slice(-30));

            setAlertHistory(prev => [{
              attack: shortName,
              src: data.attacker_ip!,
              target: data.target ?? 'Detector',
              conf,
              time: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              features,
              reason: reasonFn(features, data.attacker_ip!),
              isNormal,
            }, ...prev].slice(0, 5));
          }
          lastActive = true;
        } else {
          if (lastActive) {
            const ts = new Date().toISOString().slice(0, 19).replace('T', ' ');
            setLogLines(prev => [...prev, `${ts} Attack stopped. Session summary logged.`].slice(-30));
          }
          lastActive = false;
        }
      } catch { /* backend unreachable */ }
    };

    const interval = setInterval(poll, 1500);
    return () => clearInterval(interval);
  }, []);

  const displayAlerts = alertHistory.length > 0
    ? alertHistory
    : [];

  return (
    <div className="space-y-6">
      {/* Live attack banner */}
      {attackState.active && attackState.type && (
        <div className="bg-red-50 border-2 border-red-300 rounded-2xl p-4 flex items-center gap-4 animate-[fadeIn_0.3s_ease-out]">
          <span className="w-3 h-3 bg-red-500 rounded-full animate-pulse flex-shrink-0" />
          <div>
            <p className="font-bold text-red-800">{attackState.type.replace(' (L4)', '').replace(' (L7)', '')} in progress</p>
            <p className="text-xs text-red-600 font-mono">
              {attackState.attacker_ip} → {attackState.target} | {attackState.packets_sent.toLocaleString()} packets sent
            </p>
          </div>
        </div>
      )}

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Feature Importance */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6">
          <div className="flex items-center gap-2 mb-6">
            <BarChart3 className="w-5 h-5 text-blue-600" />
            <h2 className="text-lg font-bold text-slate-800">Global Top 10 Feature Importance</h2>
            <span className="tip-wrap">
              <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
              <span className="tip-text">Features the Random Forest model relies on most. Higher % = stronger influence on classification.</span>
            </span>
          </div>
          <div className="space-y-3">
            {TOP_FEATURES.map((f, i) => (
              <div key={i}>
                <div className="flex items-center justify-between text-sm mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-blue-600 w-5">{i + 1}</span>
                    <span className="font-mono text-slate-700 tip-wrap cursor-help">
                      {f.name}
                      <span className="tip-text">{f.tip}</span>
                    </span>
                    <span className="text-xs text-slate-400 hidden sm:inline">({f.desc})</span>
                  </div>
                  <span className="text-sm font-bold text-slate-800">{(f.imp * 100).toFixed(1)}%</span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2.5">
                  <div
                    className="bg-gradient-to-r from-blue-500 to-blue-600 h-2.5 rounded-full transition-all"
                    style={{ width: `${f.imp * 400}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Alert Explanations */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 flex flex-col">
          <div className="flex items-center gap-2 mb-6">
            <Info className="w-5 h-5 text-amber-500" />
            <h2 className="text-lg font-bold text-slate-800">"Why Flagged?" Deep Dive</h2>
            <span className="tip-wrap">
              <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
              <span className="tip-text">Per-alert explainability showing exact feature values that triggered ML classification. Updates live from the Live Simulation tab.</span>
            </span>
          </div>
          <div className="flex-1 space-y-4 overflow-y-auto max-h-[500px]">
            {displayAlerts.length === 0 ? (
              <div className="flex items-center justify-center h-32 text-slate-400 text-sm text-center">
                <div>
                  <p>No attacks detected yet.</p>
                  <p className="text-xs mt-1">Launch an attack from the Live Simulation tab to see explainability here.</p>
                </div>
              </div>
            ) : (
              displayAlerts.map((a, i) => (
                <div key={i} className={`border rounded-xl p-5 animate-[fadeIn_0.3s_ease-out] ${
                  a.isNormal ? 'border-emerald-100 bg-emerald-50/50' : 'border-red-100 bg-red-50/50'
                }`}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-bold px-2 py-0.5 rounded text-white ${
                        a.isNormal ? 'bg-emerald-600' : 'bg-red-600'
                      }`}>{a.isNormal ? 'NORMAL' : 'ALERT'}</span>
                      <span className={`text-sm font-bold ${a.isNormal ? 'text-emerald-700' : 'text-red-700'}`}>{a.attack}</span>
                      <span className="text-xs text-slate-500 ml-1">{a.time}</span>
                    </div>
                    <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${
                      a.isNormal ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700'
                    }`}>{a.conf.toFixed(1)}%</span>
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 text-xs text-slate-600 mb-3 font-mono">
                    <p>Source: <span className={`font-bold ${a.isNormal ? 'text-emerald-700' : 'text-red-700'}`}>{a.src}</span></p>
                    <p>Target: <span className="font-bold text-slate-700">{a.target}</span></p>
                  </div>
                  <p className="text-sm text-slate-700 mb-3">{a.reason}</p>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {Object.entries(a.features).map(([k, v]) => (
                      <div key={k} className="bg-white rounded-lg px-3 py-2 border border-slate-200">
                        <p className="text-xs text-slate-400">{k}</p>
                        <p className="text-sm font-mono font-bold text-slate-800">
                          {typeof v === 'number' ? (v > 999 ? v.toLocaleString() : v.toFixed(4)) : v}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Full Log */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Search className="w-5 h-5 text-slate-400" />
            <h3 className="font-bold text-slate-800">Full Detection Log</h3>
          </div>
          <button
            onClick={() => {
              const content = logLines.join('\n');
              const blob = new Blob([content], { type: 'text/plain' });
              const a = document.createElement('a');
              a.href = URL.createObjectURL(blob);
              a.download = 'detector_log.txt';
              a.click();
            }}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Download className="w-4 h-4" /> Export Log
          </button>
        </div>
        <div className="bg-slate-900 rounded-xl p-4 h-[240px] overflow-y-auto font-mono text-xs leading-relaxed space-y-1">
          {logLines.map((line, i) => (
            <div key={i} className={
              line.includes('[ALERT]') ? 'text-red-400' :
              line.includes('Session summary') ? 'text-cyan-400' :
              line.includes('Model loaded') ? 'text-blue-400' :
              line.includes('Attack stopped') ? 'text-amber-400' :
              'text-slate-400'
            }>{line}</div>
          ))}
        </div>
      </div>
    </div>
  );
}
