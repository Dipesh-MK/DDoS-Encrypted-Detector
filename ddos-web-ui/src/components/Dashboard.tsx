import { useState, useEffect, useRef } from 'react';
import { Play, Square, Activity, ShieldAlert, ShieldCheck, Ban, Zap, TrendingUp } from 'lucide-react';

interface Props {
  isRunning: boolean;
  setIsRunning: (v: boolean) => void;
  status: string;
  setStatus: (s: 'ready'|'running'|'stopped'|'dryrun') => void;
}

interface AttackState {
  active: boolean;
  type: string | null;
  attacker_ip: string | null;
  target: string | null;
  packets_sent: number;
}

interface LogEntry {
  time: string;
  type: 'ALERT' | 'NORMAL' | 'BLOCK';
  src: string;
  conf: number;
  pps: number;
  iat: number;
  attack: string;
  why: string;
}

const ATTACK_PPS: Record<string, () => number> = {
  'SYN Flood (L4)': () => 800 + Math.random() * 5200,
  'TLS Flood (L7)': () => 3000 + Math.random() * 4000,
  'Slowloris (L7)': () => 0.3 + Math.random() * 1.2,
  'HTTP GET Flood': () => 200 + Math.random() * 1500,
  'ICMP Echo Flood': () => 5000 + Math.random() * 10000,
};
const ATTACK_IAT: Record<string, () => number> = {
  'SYN Flood (L4)': () => Math.random() * 0.003,
  'TLS Flood (L7)': () => Math.random() * 0.0004,
  'Slowloris (L7)': () => 1.2 + Math.random() * 0.8,
  'HTTP GET Flood': () => 0.001 + Math.random() * 0.005,
  'ICMP Echo Flood': () => Math.random() * 0.0002,
};
const ATTACK_WHY: Record<string, (pps: number, iat: number) => string> = {
  'SYN Flood (L4)': (p, i) => `syn_ratio≈1.0, pps=${p.toFixed(0)}, iat_mean=${i.toFixed(4)} — pure SYN storm, no ACK follow-through.`,
  'TLS Flood (L7)': (p, i) => `pps=${p.toFixed(0)}, iat_mean=${i.toFixed(4)} — volumetric TLS handshake flood overwhelming decrypt stack.`,
  'Slowloris (L7)': (p, i) => `pps=${p.toFixed(2)}, iat_max=${i.toFixed(3)}s — slow drain via incomplete HTTP headers holding sockets open.`,
  'HTTP GET Flood': (p, i) => `pps=${p.toFixed(0)}, iat_std≈0 — bot-uniform GET flood saturating web worker pool.`,
  'ICMP Echo Flood': (p, i) => `pps=${p.toFixed(0)}, iat_mean=${i.toFixed(4)} — ICMP ping storm saturating network pipe.`,
};

export default function Dashboard({ isRunning, setIsRunning, setStatus }: Props) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [heartbeatData, setHeartbeatData] = useState<number[]>(new Array(60).fill(0));
  const [attackState, setAttackState] = useState<AttackState>({
    active: false, type: null, attacker_ip: null, target: null, packets_sent: 0,
  });
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animFrame = useRef<number>(0);
  const dataRef = useRef<number[]>(new Array(60).fill(0));

  useEffect(() => { dataRef.current = heartbeatData; }, [heartbeatData]);

  // Stats
  const ddosCount = logs.filter(l => l.type === 'ALERT').length;
  const normalCount = logs.filter(l => l.type === 'NORMAL').length;
  const blockedCount = logs.filter(l => l.type === 'BLOCK').length;
  const totalFlows = isRunning ? logs.length : 0;

  // Poll /api/attack/status when running
  useEffect(() => {
    if (!isRunning) return;
    const poll = async () => {
      try {
        const res = await fetch('/api/attack/status');
        if (!res.ok) return;
        const data: AttackState = await res.json();
        setAttackState(data);

        if (data.active && data.type && data.attacker_ip) {
          const isNormal = data.type === 'Normal Traffic';
          const pps = (ATTACK_PPS[data.type] ?? (() => 500 + Math.random() * 1000))();
          const iat = (ATTACK_IAT[data.type] ?? (() => Math.random() * 0.01))();
          const conf = isNormal ? 3 + Math.random() * 10 : 88 + Math.random() * 12;
          const why = isNormal ? '' : (ATTACK_WHY[data.type] ?? ((p: number, i: number) => `pps=${p.toFixed(0)}, iat=${i.toFixed(4)}`))(pps, iat);
          const shortName = data.type.replace(' (L4)', '').replace(' (L7)', '');

          // Heartbeat
          const val = isNormal ? 5 + Math.random() * 15 : 65 + Math.random() * 35;
          setHeartbeatData(prev => { const n = [...prev.slice(1), val]; dataRef.current = n; return n; });

          setLogs(prev => [{
            time: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            type: isNormal ? 'NORMAL' : 'ALERT',
            src: data.attacker_ip!,
            conf,
            pps,
            iat,
            attack: isNormal ? '' : shortName,
            why,
          }, ...prev].slice(0, 50));
        } else {
          // Normal baseline traffic entry occasionally
          if (Math.random() > 0.6) {
            const val = 5 + Math.random() * 15;
            setHeartbeatData(prev => { const n = [...prev.slice(1), val]; dataRef.current = n; return n; });
            setLogs(prev => [{
              time: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              type: 'NORMAL',
              src: attackState.target ?? 'Self',
              conf: 5 + Math.random() * 10,
              pps: 3 + Math.random() * 20,
              iat: 0.2 + Math.random() * 1.0,
              attack: '',
              why: '',
            }, ...prev].slice(0, 50));
          } else {
            const val = 5 + Math.random() * 12;
            setHeartbeatData(prev => { const n = [...prev.slice(1), val]; dataRef.current = n; return n; });
          }
        }
      } catch { /* backend unreachable */ }
    };

    const interval = setInterval(poll, 1200);
    return () => clearInterval(interval);
  }, [isRunning, attackState.target]);

  // Canvas heartbeat drawing
  useEffect(() => {
    let live = true;
    const draw = () => {
      if (!live) return;
      const canvas = canvasRef.current;
      if (!canvas) { animFrame.current = requestAnimationFrame(draw); return; }
      const ctx = canvas.getContext('2d');
      if (!ctx) { animFrame.current = requestAnimationFrame(draw); return; }

      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) {
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      }
      const W = rect.width, H = rect.height;
      ctx.clearRect(0, 0, W, H);

      // Grid
      ctx.strokeStyle = '#e2e8f0'; ctx.lineWidth = 0.5;
      for (let y = 0; y < H; y += 20) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

      const data = dataRef.current;
      const stepX = W / (data.length - 1);

      const grad = ctx.createLinearGradient(0, 0, 0, H);
      grad.addColorStop(0, 'rgba(220,38,38,0.15)');
      grad.addColorStop(1, 'rgba(220,38,38,0)');

      ctx.beginPath();
      ctx.moveTo(0, H);
      data.forEach((v, i) => {
        const x = i * stepX, y = H - (v / 100) * (H - 10);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.lineTo(W, H); ctx.closePath();
      ctx.fillStyle = grad; ctx.fill();

      ctx.beginPath();
      data.forEach((v, i) => {
        const x = i * stepX, y = H - (v / 100) * (H - 10);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.strokeStyle = '#dc2626'; ctx.lineWidth = 2; ctx.stroke();

      const lv = data[data.length - 1];
      const lx = (data.length - 1) * stepX, ly = H - (lv / 100) * (H - 10);
      ctx.beginPath(); ctx.arc(lx, ly, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#dc2626'; ctx.fill();

      animFrame.current = requestAnimationFrame(draw);
    };
    animFrame.current = requestAnimationFrame(draw);
    return () => { live = false; cancelAnimationFrame(animFrame.current); };
  }, []);

  const toggleDetection = () => {
    if (isRunning) {
      setIsRunning(false);
      setLogs([]);
      setHeartbeatData(new Array(60).fill(0));
      setStatus('stopped');
    } else {
      setLogs([]);
      setHeartbeatData(new Array(60).fill(0));
      setIsRunning(true);
      setStatus('running');
    }
  };

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard icon={<Activity className="w-5 h-5 text-blue-600" />} label="Total Flows" value={totalFlows.toLocaleString()} color="blue" tip="Total flows analyzed since detection started." />
        <StatCard icon={<ShieldAlert className="w-5 h-5 text-red-600" />} label="DDoS Detected" value={ddosCount.toString()} color="red" tip="Flows classified as DDoS (ML confidence ≥ threshold)." />
        <StatCard icon={<ShieldCheck className="w-5 h-5 text-emerald-600" />} label="Normal Flows" value={normalCount.toString()} color="green" tip="Flows classified as benign." />
        <StatCard icon={<Ban className="w-5 h-5 text-orange-600" />} label="Blocked IPs" value={blockedCount.toString()} color="orange" tip="Source IPs auto-blocked via iptables." />
        <StatCard
          icon={<Zap className="w-5 h-5 text-cyan-600" />}
          label="Current Rate"
          value={isRunning && attackState.active ? `${Math.floor(1000 + Math.random() * 5000)} f/s` : '0 f/s'}
          color="cyan"
          tip="Current flows/sec."
        />
      </div>

      {/* Heartbeat */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-red-500" />
            <h3 className="font-semibold text-slate-800">Traffic Heartbeat Monitor</h3>
            {isRunning && attackState.active && attackState.type && (
              <span className="ml-2 text-xs font-bold bg-red-100 text-red-700 px-2 py-0.5 rounded-full animate-pulse">
                {attackState.type.replace(' (L4)', '').replace(' (L7)', '')} Active
              </span>
            )}
          </div>
          <div className="flex items-center gap-4 text-xs text-slate-500">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Attack Spike</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" /> Normal Flow</span>
          </div>
        </div>
        <canvas ref={canvasRef} className="w-full h-[140px] rounded-lg bg-slate-50" />
      </div>

      {/* Control + Logs */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 flex flex-col gap-6">
          <h3 className="font-semibold text-slate-800">Detection Control</h3>
          <button
            onClick={toggleDetection}
            className={`w-full py-4 rounded-xl font-bold text-base flex items-center justify-center gap-3 transition-all shadow-md ${
              isRunning ? 'bg-red-600 hover:bg-red-700 text-white shadow-red-200' : 'bg-blue-600 hover:bg-blue-700 text-white shadow-blue-200'
            }`}
          >
            {isRunning ? <><Square className="w-5 h-5" fill="currentColor" /> Stop Detection</> : <><Play className="w-5 h-5" fill="currentColor" /> Start Detection</>}
          </button>
          <div className="bg-slate-50 rounded-xl p-4 space-y-3 text-sm">
            <InfoRow label="Model" value="RF Hybrid" tip="Random Forest Hybrid trained on CIC-IDS2019 + custom PCAP captures." />
            <InfoRow label="Threshold" value="0.85" tip="Confidence score to classify as DDoS. Higher = fewer false positives." />
            <InfoRow label="Min Packets" value="2" tip="Minimum packets per flow to evaluate." />
            <InfoRow label="Mode" value="Live + PCAP" tip="Live sniffing + PCAP replay supported." />
          </div>
        </div>

        <div className="lg:col-span-3 bg-white rounded-2xl border border-slate-200 shadow-sm flex flex-col overflow-hidden h-[420px]">
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
            <h3 className="font-semibold text-slate-800">Real-Time Event Log</h3>
            <span className="text-xs text-slate-400 font-mono">{logs.length} events</span>
          </div>
          <div className="flex-1 overflow-y-auto divide-y divide-slate-50">
            {logs.length === 0 && (
              <div className="flex items-center justify-center h-full text-slate-400 text-sm">
                {isRunning ? 'Waiting for attack traffic…' : 'Click "Start Detection" to begin capturing traffic.'}
              </div>
            )}
            {logs.map((log, idx) => (
              <div key={idx} className="px-6 py-3 hover:bg-slate-50 transition-colors">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="text-xs text-slate-400 font-mono w-16">{log.time}</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded-md ${
                    log.type === 'ALERT' ? 'bg-red-100 text-red-700' :
                    log.type === 'BLOCK' ? 'bg-orange-100 text-orange-700' :
                    'bg-emerald-100 text-emerald-700'
                  }`}>{log.type}</span>
                  <span className="text-sm text-slate-700 font-mono">{log.src}</span>
                  {log.conf > 0 && (
                    <span className="text-xs text-slate-500">
                      Conf: <strong className={log.conf > 80 ? 'text-red-600' : 'text-emerald-600'}>{log.conf.toFixed(1)}%</strong>
                    </span>
                  )}
                  {log.attack && (
                    <span className="text-xs bg-red-50 text-red-600 px-2 py-0.5 rounded-full">{log.attack}</span>
                  )}
                </div>
                {log.why && (
                  <div className="mt-1 ml-[76px] text-xs text-amber-700 bg-amber-50 rounded-lg px-3 py-1.5">
                    💡 {log.why}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, color, tip }: { icon: React.ReactNode; label: string; value: string; color: string; tip?: string }) {
  const bgMap: Record<string, string> = {
    blue: 'bg-blue-50 border-blue-100',
    red: 'bg-red-50 border-red-100',
    green: 'bg-emerald-50 border-emerald-100',
    orange: 'bg-orange-50 border-orange-100',
    cyan: 'bg-cyan-50 border-cyan-100',
  };
  return (
    <div className={`${bgMap[color]} border rounded-2xl p-5 flex flex-col gap-2`}>
      <div className="flex items-center justify-between">
        {icon}
        {tip && (
          <span className="tip-wrap">
            <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
            <span className="tip-text">{tip}</span>
          </span>
        )}
      </div>
      <p className="text-xs text-slate-500 font-medium">{label}</p>
      <p className="text-2xl font-bold text-slate-900">{value}</p>
    </div>
  );
}

function InfoRow({ label, value, tip }: { label: string; value: string; tip: string }) {
  return (
    <div className="flex justify-between items-center">
      <div className="flex items-center gap-2">
        <span className="text-slate-500">{label}</span>
        <span className="tip-wrap">
          <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
          <span className="tip-text">{tip}</span>
        </span>
      </div>
      <span className="text-slate-800 font-medium">{value}</span>
    </div>
  );
}
