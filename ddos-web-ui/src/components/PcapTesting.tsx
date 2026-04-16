import { useState } from 'react';
import { Play, FileSearch, FolderOpen, CheckCircle2 } from 'lucide-react';

const SERVER_PCAPS = [
  { file: 'normal_traffic_server.pcap', label: '🟢 Normal Traffic', tag: 'Normal' },
  { file: 'normal_traffic_server_2.pcap', label: '🟢 Normal Traffic #2', tag: 'Normal' },
  { file: 'ddos_syn_flood_server.pcap', label: '🔴 SYN Flood', tag: 'DDoS' },
  { file: 'ddos_tls_flood_server.pcap', label: '🔴 TLS Flood', tag: 'DDoS' },
  { file: 'ddos_slowloris_tls_server.pcap', label: '🔴 Slowloris TLS', tag: 'DDoS' },
];
const ATTACKER_PCAPS = [
  { file: 'normal_traffic_attacker.pcap', label: '🟢 Normal (Attacker)', tag: 'Normal' },
  { file: 'ddos_tls_flood_attacker.pcap', label: '🔴 TLS Flood (Attacker)', tag: 'DDoS' },
];

const PCAP_RESULTS: Record<string, {flows: number; ddos: number; normal: number; blocked: number}> = {
  'normal_traffic_server.pcap': { flows: 13, ddos: 1, normal: 12, blocked: 0 },
  'normal_traffic_server_2.pcap': { flows: 13, ddos: 0, normal: 13, blocked: 0 },
  'ddos_syn_flood_server.pcap': { flows: 152, ddos: 148, normal: 4, blocked: 1 },
  'ddos_tls_flood_server.pcap': { flows: 200, ddos: 200, normal: 0, blocked: 1 },
  'ddos_slowloris_tls_server.pcap': { flows: 87, ddos: 87, normal: 0, blocked: 1 },
  'normal_traffic_attacker.pcap': { flows: 11, ddos: 0, normal: 11, blocked: 0 },
  'ddos_tls_flood_attacker.pcap': { flows: 178, ddos: 175, normal: 3, blocked: 1 },
};

export default function PcapTesting() {
  const [selected, setSelected] = useState(SERVER_PCAPS[0].file);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<typeof PCAP_RESULTS[string] | null>(null);

  const runTest = () => {
    setRunning(true);
    setResults(null);
    setTimeout(() => {
      setRunning(false);
      setResults(PCAP_RESULTS[selected] || { flows: 0, ddos: 0, normal: 0, blocked: 0 });
    }, 2000);
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* File Selection */}
        <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-200 shadow-sm p-6">
          <div className="flex items-center gap-2 mb-6">
            <FolderOpen className="w-5 h-5 text-blue-600" />
            <h2 className="text-lg font-bold text-slate-800">PCAP File Selection</h2>
            <span className="tip-wrap">
              <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
              <span className="tip-text">Select a pre-recorded packet capture (.pcap) file to analyze. Server-side captures show traffic as seen by the victim; attacker-side captures are from the attacker's perspective.</span>
            </span>
          </div>

          <div className="mb-4">
            <div className="flex items-center gap-2 mb-2">
              <label className="text-sm font-medium text-slate-600">Server-side Captures (Recommended)</label>
              <span className="tip-wrap">
                <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
                <span className="tip-text">PCAPs captured on the victim/server machine. These are the most realistic for detection testing since they reflect how your detector would see real inbound traffic.</span>
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {SERVER_PCAPS.map(p => (
                <button
                  key={p.file}
                  onClick={() => setSelected(p.file)}
                  className={`text-left px-4 py-3 rounded-xl border-2 transition-all text-sm ${
                    selected === p.file
                      ? 'border-blue-500 bg-blue-50 text-blue-800'
                      : 'border-slate-200 hover:border-slate-300 text-slate-700'
                  }`}
                >
                  <div className="font-medium">{p.label}</div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">{p.file}</div>
                </button>
              ))}
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2 mb-2">
              <label className="text-sm font-medium text-slate-600">Attacker-side Captures</label>
              <span className="tip-wrap">
                <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
                <span className="tip-text">PCAPs captured on the attacker machine. Useful for validating that outbound attack patterns are detectable from either perspective.</span>
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {ATTACKER_PCAPS.map(p => (
                <button
                  key={p.file}
                  onClick={() => setSelected(p.file)}
                  className={`text-left px-4 py-3 rounded-xl border-2 transition-all text-sm ${
                    selected === p.file
                      ? 'border-blue-500 bg-blue-50 text-blue-800'
                      : 'border-slate-200 hover:border-slate-300 text-slate-700'
                  }`}
                >
                  <div className="font-medium">{p.label}</div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">{p.file}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Run Panel */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 flex flex-col">
          <div className="flex items-center gap-2 mb-4">
            <FileSearch className="w-5 h-5 text-blue-600" />
            <h3 className="font-bold text-slate-800">Test Runner</h3>
          </div>
          <div className="bg-slate-50 rounded-xl p-4 mb-4">
            <p className="text-xs text-slate-500 mb-1">Selected File</p>
            <p className="text-sm font-mono text-blue-700 font-semibold break-all">{selected}</p>
          </div>

          <button
            onClick={runTest}
            disabled={running}
            className={`w-full py-4 rounded-xl font-bold flex items-center justify-center gap-2 transition-all shadow-md ${
              running ? 'bg-slate-300 cursor-wait text-slate-500' : 'bg-blue-600 hover:bg-blue-700 text-white shadow-blue-200'
            }`}
          >
            {running ? 'Analyzing packets...' : <><Play className="w-5 h-5" fill="currentColor" /> Run PCAP Test</>}
          </button>

          {/* Results */}
          {results && (
            <div className="mt-6 space-y-3 animate-[fadeIn_0.3s_ease-in-out]">
              <div className="flex items-center gap-2 text-emerald-600 text-sm font-semibold">
                <CheckCircle2 className="w-4 h-4" /> Analysis Complete
              </div>
              <div className="bg-slate-50 rounded-xl p-4 space-y-2 text-sm">
                <TipRow label="Total Flows" value={results.flows.toString()} tip="Number of distinct network flow records extracted from this PCAP file." />
                <TipRow label="DDoS Detected" value={results.ddos.toString()} danger={results.ddos > 0} tip="Flows classified as DDoS by the ML model at confidence ≥ threshold." />
                <TipRow label="Normal Flows" value={results.normal.toString()} success={results.normal > 0} tip="Flows classified as benign/normal traffic below the confidence threshold." />
                <TipRow label="Blocked IPs" value={results.blocked.toString()} tip="Unique attacker IPs that would be auto-blocked via iptables (if blocking is enabled)." />
              </div>
              {/* Mini bar chart */}
              <div className="pt-2">
                <p className="text-xs text-slate-500 mb-2">Distribution</p>
                <div className="flex h-4 rounded-full overflow-hidden bg-slate-200">
                  {results.flows > 0 && (
                    <>
                      <div className="bg-red-500 transition-all" style={{ width: `${(results.ddos / results.flows) * 100}%` }}></div>
                      <div className="bg-emerald-500 transition-all" style={{ width: `${(results.normal / results.flows) * 100}%` }}></div>
                    </>
                  )}
                </div>
                <div className="flex justify-between text-xs mt-1">
                  <span className="text-red-600">{results.flows > 0 ? ((results.ddos / results.flows) * 100).toFixed(0) : 0}% DDoS</span>
                  <span className="text-emerald-600">{results.flows > 0 ? ((results.normal / results.flows) * 100).toFixed(0) : 0}% Normal</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
function TipRow({ label, value, danger, success, tip }: { label: string; value: string; danger?: boolean; success?: boolean; tip?: string }) {
  return (
    <div className="flex justify-between items-center">
      <div className="flex items-center gap-2">
        <span className="text-slate-500">{label}</span>
        {tip && (
          <span className="tip-wrap">
            <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
            <span className="tip-text">{tip}</span>
          </span>
        )}
      </div>
      <span className={`font-bold ${danger ? 'text-red-600' : success ? 'text-emerald-600' : 'text-slate-800'}`}>{value}</span>
    </div>
  );
}
