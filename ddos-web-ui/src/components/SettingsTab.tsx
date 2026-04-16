import { useState } from 'react';
import { Sliders, Terminal, Copy, Check } from 'lucide-react';

export default function SettingsTab() {
  const [threshold, setThreshold] = useState(0.85);
  const [timeout, setFlowTimeout] = useState<number | ''>(2);
  const [minPackets, setMinPackets] = useState<number | ''>(2);
  const [verbose, setVerbose] = useState(true);
  const [noBlock, setNoBlock] = useState(true);
  const [iface, setIface] = useState('en0');
  const [refreshRate, setRefreshRate] = useState(1);
  const [copied, setCopied] = useState(false);

  const cmd = `python live_detector.py --model ddos_model_hybrid.pkl --config model_config_hybrid.json --threshold ${threshold.toFixed(2)} --flow-timeout ${timeout} --min-packets ${minPackets} --interface ${iface}${verbose ? ' --verbose' : ''}${noBlock ? ' --no-block' : ''}`;

  const copyCmd = () => {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="grid lg:grid-cols-3 gap-6">
      {/* Settings Form */}
      <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-200 shadow-sm p-8">
        <div className="flex items-center gap-3 mb-8">
          <Sliders className="w-6 h-6 text-blue-600" />
          <h2 className="text-lg font-bold text-slate-800">Detection Parameters</h2>
        </div>

        <div className="grid md:grid-cols-2 gap-x-8 gap-y-6">
          {/* Left Column */}
          <div className="space-y-6">
            <TipField label="Model File" tip="The trained ML model file (.pkl) used for DDoS classification. Currently using a Random Forest hybrid trained on CIC-IDS2017 + custom PCAP data.">
              <input type="text" readOnly value="ddos_model_hybrid.pkl" className="input-box opacity-70" />
            </TipField>
            <TipField label="Config File" tip="JSON file containing feature names, threshold, and scaler parameters the model was trained with.">
              <input type="text" readOnly value="model_config_hybrid.json" className="input-box opacity-70" />
            </TipField>
            <TipField label="Network Interface" tip="The OS-level network interface to sniff. On macOS, en0 = Wi-Fi, en1 = Ethernet. Use 'lo0' for loopback testing.">
              <input type="text" value={iface} onChange={e => setIface(e.target.value)} className="input-box" />
            </TipField>
            <TipField label={`Auto-refresh Rate: ${refreshRate}s`} tip="How often (in seconds) the dashboard polls for new flow statistics. Lower = more responsive but higher CPU usage.">
              <input type="range" min="0.5" max="5" step="0.5" value={refreshRate} onChange={e => setRefreshRate(parseFloat(e.target.value))} className="w-full accent-blue-600" />
            </TipField>
          </div>

          {/* Right Column */}
          <div className="space-y-6">
            <TipField label={`Detection Threshold: ${threshold.toFixed(2)}`} tip="ML confidence cutoff (0.0–1.0). Flows with confidence ≥ this value are classified as DDoS. Higher = fewer false positives but may miss stealthy attacks. Recommended: 0.85.">
              <input type="range" min="0.5" max="1.0" step="0.01" value={threshold} onChange={e => setThreshold(parseFloat(e.target.value))} className="w-full accent-blue-600" />
              <div className="flex justify-between text-xs text-slate-400 mt-1"><span>0.50</span><span>1.00</span></div>
            </TipField>
            <div className="grid grid-cols-2 gap-4">
              <TipField label="Flow Timeout (s)" tip="Seconds of inactivity before a flow is considered complete and sent for classification. Lower = faster detection but may split long flows.">
                <input type="number" min={1} max={30} value={timeout} onChange={e => setFlowTimeout(e.target.value ? parseInt(e.target.value) : '')} className="input-box" />
              </TipField>
              <TipField label="Min Packets" tip="Minimum number of packets a flow must have before it is evaluated by the model. Flows with fewer packets are ignored. Helps filter out noise and incomplete connections.">
                <input type="number" min={1} max={10} value={minPackets} onChange={e => setMinPackets(e.target.value ? parseInt(e.target.value) : '')} className="input-box" />
              </TipField>
            </div>
            <div className="space-y-4 pt-2">
              <TipToggle label="Verbose Mode (Explainability)" tip="When enabled, each alert includes a 'Why flagged?' breakdown showing which features (pps, iat, syn_ratio, etc.) contributed most to the model's decision." checked={verbose} onChange={setVerbose} />
              <TipToggle label="No-Block Mode (Dry Run)" tip="When enabled, DDoS-flagged IPs are logged but NOT actually blocked via iptables. Useful for testing and demonstration without affecting real network traffic." checked={noBlock} onChange={setNoBlock} />
            </div>
          </div>
        </div>
      </div>

      {/* Command Preview */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 flex flex-col">
        <div className="flex items-center gap-2 mb-4">
          <Terminal className="w-5 h-5 text-blue-600" />
          <h3 className="font-bold text-slate-800">Command Preview</h3>
        </div>
        <p className="text-xs text-slate-500 mb-4">This command reflects the current settings above. Copy and run it in your terminal.</p>
        <div className="flex-1 bg-slate-900 rounded-xl p-4 text-emerald-400 font-mono text-xs break-all leading-relaxed overflow-auto">{cmd}</div>
        <button
          onClick={copyCmd}
          className="w-full mt-4 py-3 border border-slate-200 rounded-xl text-sm font-medium text-slate-700 hover:bg-slate-50 transition-colors flex items-center justify-center gap-2"
        >
          {copied ? <><Check className="w-4 h-4 text-emerald-500" /> Copied!</> : <><Copy className="w-4 h-4" /> Copy Command</>}
        </button>
      </div>
    </div>
  );
}
function TipField({ label, tip, children }: { label: string; tip: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <label className="text-sm font-medium text-slate-600">{label}</label>
        <span className="tip-wrap">
          <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
          <span className="tip-text">{tip}</span>
        </span>
      </div>
      {children}
    </div>
  );
}

function TipToggle({ label, tip, checked, onChange }: { label: string; tip: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center justify-between cursor-pointer">
      <div className="flex items-center gap-2">
        <span className="text-sm text-slate-700">{label}</span>
        <span className="tip-wrap">
          <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
          <span className="tip-text">{tip}</span>
        </span>
      </div>
      <div className="relative">
        <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} className="sr-only" />
        <div className={`w-11 h-6 rounded-full transition-colors ${checked ? 'bg-blue-600' : 'bg-slate-300'}`}></div>
        <div className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${checked ? 'translate-x-5' : ''}`}></div>
      </div>
    </label>
  );
}
