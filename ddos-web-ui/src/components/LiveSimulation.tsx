import { useState, useEffect, useRef } from 'react';
import {
  Monitor, ServerCrash, AlertTriangle, Shield, Radio, Search,
  ChevronLeft, ArrowRight, Activity, Terminal, Zap, TrendingUp,
} from 'lucide-react';

type Role = 'none' | 'attacker' | 'detector';

// All API calls are relative — Vite proxies /api → localhost:8001
// This means it works from both localhost AND from the Ngrok tunnel on a second PC.
const API = '/api';

interface Device { ip: string; name: string; mac: string; is_self: boolean }

// ─────────────────────────────────────────────────────────────────────────────
// Attack profiles: drives Detector visualisations dynamically
// ─────────────────────────────────────────────────────────────────────────────
interface AttackProfile {
  label: string;
  color: string;
  features: string[];
  genFeatures: () => Record<string, number>;
  explain: (f: Record<string, number>) => string;
  confidence: () => number;
}

const ATTACK_PROFILES: Record<string, AttackProfile> = {
  'SYN Flood (L4)': {
    label: 'SYN Flood',
    color: 'red',
    features: ['pps', 'syn_ratio', 'iat_mean', 'payload_mean'],
    genFeatures: () => ({
      pps: 800 + Math.random() * 5200,
      syn_ratio: parseFloat((0.93 + Math.random() * 0.07).toFixed(2)),
      iat_mean: parseFloat((Math.random() * 0.003).toFixed(4)),
      payload_mean: 0,
    }),
    explain: (f) =>
      `Pure SYN storm — pps=${f.pps?.toFixed(0)}, syn_ratio=${f.syn_ratio?.toFixed(2)}, payload_mean=0. ` +
      `Machine-gun SYN packets with no ACK follow-through exhaust TCP connection backlog (SYN backlog overflow).`,
    confidence: () => 92 + Math.random() * 8,
  },
  'TLS Flood (L7)': {
    label: 'TLS Flood',
    color: 'orange',
    features: ['pps', 'iat_mean', 'bps', 'payload_mean'],
    genFeatures: () => ({
      pps: 3000 + Math.random() * 4000,
      iat_mean: parseFloat((Math.random() * 0.0004).toFixed(4)),
      bps: Math.floor(400000 + Math.random() * 600000),
      payload_mean: parseFloat((35 + Math.random() * 20).toFixed(1)),
    }),
    explain: (f) =>
      `Volumetric TLS handshake flood — pps=${f.pps?.toFixed(0)}, iat_mean=${f.iat_mean?.toFixed(4)}, ` +
      `bps=${f.bps?.toLocaleString()}. Near-zero inter-arrival time overwhelms TLS decryption stack.`,
    confidence: () => 95 + Math.random() * 5,
  },
  'Slowloris (L7)': {
    label: 'Slowloris',
    color: 'amber',
    features: ['pps', 'iat_max', 'iat_std', 'duration_s'],
    genFeatures: () => ({
      pps: parseFloat((0.3 + Math.random() * 1.2).toFixed(2)),
      iat_max: parseFloat((1.2 + Math.random() * 0.8).toFixed(3)),
      iat_std: parseFloat((0.3 + Math.random() * 0.3).toFixed(3)),
      duration_s: Math.floor(60 + Math.random() * 120),
    }),
    explain: (f) =>
      `Classic Slowloris — very low pps=${f.pps?.toFixed(2)}, extreme iat_max=${f.iat_max?.toFixed(3)}s, ` +
      `connection duration=${f.duration_s?.toFixed(0)}s. Sends HTTP headers one-byte-at-a-time to hold sockets open indefinitely.`,
    confidence: () => 88 + Math.random() * 10,
  },
  'HTTP GET Flood': {
    label: 'HTTP GET Flood',
    color: 'purple',
    features: ['pps', 'iat_mean', 'payload_mean', 'iat_std'],
    genFeatures: () => ({
      pps: 200 + Math.random() * 1500,
      iat_mean: parseFloat((0.001 + Math.random() * 0.005).toFixed(4)),
      payload_mean: parseFloat((200 + Math.random() * 400).toFixed(1)),
      iat_std: parseFloat((Math.random() * 0.002).toFixed(4)),
    }),
    explain: (f) =>
      `HTTP GET flood — pps=${f.pps?.toFixed(0)}, payload_mean=${f.payload_mean?.toFixed(0)}B, ` +
      `iat_std=${f.iat_std?.toFixed(4)} (uniform bot timing). Saturates web server worker pool with valid-looking requests.`,
    confidence: () => 85 + Math.random() * 10,
  },
  'ICMP Echo Flood': {
    label: 'ICMP Echo Flood',
    color: 'cyan',
    features: ['pps', 'bps', 'iat_mean', 'payload_std'],
    genFeatures: () => ({
      pps: 5000 + Math.random() * 10000,
      bps: Math.floor(600000 + Math.random() * 800000),
      iat_mean: parseFloat((Math.random() * 0.0002).toFixed(4)),
      payload_std: parseFloat((Math.random() * 2).toFixed(2)),
    }),
    explain: (f) =>
      `ICMP Echo (ping) flood — pps=${f.pps?.toFixed(0)}, bps=${f.bps?.toLocaleString()}, ` +
      `payload_std=${f.payload_std?.toFixed(2)} (uniform payloads). Saturates network pipe and CPU interrupt handling.`,
    confidence: () => 90 + Math.random() * 10,
  },
  'Normal Traffic': {
    label: 'Normal Traffic',
    color: 'green',
    features: ['pps', 'iat_mean', 'payload_mean', 'iat_std'],
    genFeatures: () => ({
      pps: parseFloat((2 + Math.random() * 25).toFixed(1)),
      iat_mean: parseFloat((0.05 + Math.random() * 0.5).toFixed(4)),
      payload_mean: parseFloat((300 + Math.random() * 900).toFixed(1)),
      iat_std: parseFloat((0.01 + Math.random() * 0.1).toFixed(4)),
    }),
    explain: (f) =>
      `Benign baseline traffic — pps=${f.pps?.toFixed(1)}, iat_mean=${f.iat_mean?.toFixed(4)}, ` +
      `payload_mean=${f.payload_mean?.toFixed(0)}B. Normal inter-arrival variance with moderate varied payload sizes.`,
    confidence: () => 3 + Math.random() * 10,
  },
};

const ATTACK_OPTIONS = Object.keys(ATTACK_PROFILES);

const COLOR_MAP: Record<string, string> = {
  red: 'bg-red-600',
  orange: 'bg-orange-500',
  amber: 'bg-amber-500',
  purple: 'bg-purple-600',
  cyan: 'bg-cyan-600',
  green: 'bg-emerald-600',
};
const BORDER_MAP: Record<string, string> = {
  red: 'border-red-200 bg-red-50',
  orange: 'border-orange-200 bg-orange-50',
  amber: 'border-amber-200 bg-amber-50',
  purple: 'border-purple-200 bg-purple-50',
  cyan: 'border-cyan-200 bg-cyan-50',
  green: 'border-emerald-200 bg-emerald-50',
};
const TEXT_MAP: Record<string, string> = {
  red: 'text-red-700',
  orange: 'text-orange-700',
  amber: 'text-amber-700',
  purple: 'text-purple-700',
  cyan: 'text-cyan-700',
  green: 'text-emerald-700',
};

// ─────────────────────────────────────────────────────────────────────────────
// Root Component
// ─────────────────────────────────────────────────────────────────────────────
export default function LiveSimulation() {
  const [role, setRole] = useState<Role>('none');

  if (role === 'none') return <RoleSelection setRole={setRole} />;

  return (
    <div className="space-y-6 animate-[fadeIn_0.4s_ease-out]">
      <div className="flex items-center gap-4">
        <button
          onClick={() => setRole('none')}
          className="p-2 hover:bg-slate-200 bg-slate-100 rounded-full transition-colors text-slate-600"
        >
          <ChevronLeft className="w-5 h-5" />
        </button>
        <h2 className="text-xl font-bold text-slate-800">
          {role === 'attacker' ? 'Attacker Dashboard' : 'Victim Detector Dashboard'}
        </h2>
      </div>
      {role === 'attacker' ? <AttackerUI /> : <DetectorUI />}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Role Selection
// ─────────────────────────────────────────────────────────────────────────────
function RoleSelection({ setRole }: { setRole: (r: Role) => void }) {
  return (
    <div className="max-w-4xl mx-auto py-12 space-y-8 animate-[fadeIn_0.5s_ease-out]">
      <div className="text-center space-y-3">
        <h1 className="text-3xl font-bold text-slate-900">Choose Your Role</h1>
        <p className="text-slate-500 max-w-xl mx-auto text-sm">
          Open this site on <strong>two separate devices</strong> on the same network (or via Ngrok).
          Set one as the <span className="text-red-600 font-semibold">Attacker</span> and the other as the{' '}
          <span className="text-emerald-600 font-semibold">Detector</span>.
          The backend must run on the <strong>Detector PC</strong>.
        </p>
      </div>
      <div className="grid md:grid-cols-2 gap-6">
        <button
          onClick={() => setRole('detector')}
          className="group bg-white border-2 border-emerald-100 hover:border-emerald-500 rounded-2xl p-8 text-left transition-all shadow-sm hover:shadow-xl hover:-translate-y-1 relative overflow-hidden"
        >
          <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-50 rounded-bl-full -z-10 group-hover:scale-110 transition-transform" />
          <Shield className="w-12 h-12 text-emerald-500 mb-6" />
          <h2 className="text-xl font-bold text-slate-800 mb-2">Run as Detector</h2>
          <p className="text-sm text-slate-500 mb-6">
            Victim server. Monitors incoming traffic in real-time, detects anomalies, and shows
            attack type with full explainability.
          </p>
          <div className="flex items-center text-emerald-600 font-semibold text-sm gap-2">
            Initialize Sensor <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        <button
          onClick={() => setRole('attacker')}
          className="group bg-white border-2 border-red-100 hover:border-red-500 rounded-2xl p-8 text-left transition-all shadow-sm hover:shadow-xl hover:-translate-y-1 relative overflow-hidden"
        >
          <div className="absolute top-0 right-0 w-32 h-32 bg-red-50 rounded-bl-full -z-10 group-hover:scale-110 transition-transform" />
          <Radio className="w-12 h-12 text-red-500 mb-6" />
          <h2 className="text-xl font-bold text-slate-800 mb-2">Run as Attacker</h2>
          <p className="text-sm text-slate-500 mb-6">
            Malicious node. Scan the network, pick a target device, choose an attack vector
            and blast encrypted payloads — all visualised in real-time.
          </p>
          <div className="flex items-center text-red-600 font-semibold text-sm gap-2">
            Load Arsenal <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Attacker UI
// ─────────────────────────────────────────────────────────────────────────────
function AttackerUI() {
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState('');
  const [devices, setDevices] = useState<Device[]>([]);
  const [targetIp, setTargetIp] = useState('');
  const [attackType, setAttackType] = useState(ATTACK_OPTIONS[0]);
  const [intensity, setIntensity] = useState(1);
  const [isAttacking, setIsAttacking] = useState(false);
  const [attackLogs, setAttackLogs] = useState<string[]>([]);
  const [totalPkts, setTotalPkts] = useState(0);
  const logEndRef = useRef<HTMLDivElement>(null);

  const handleScan = async () => {
    setIsScanning(true);
    setDevices([]);
    setTargetIp('');
    setScanError('');
    try {
      const res = await fetch(`${API}/scan`);
      if (!res.ok) throw new Error(`API ${res.status}`);
      const data = await res.json();
      if (data.devices?.length > 0) {
        setDevices(data.devices);
      } else {
        setScanError('No other devices found yet — try again in a moment.');
      }
    } catch {
      setScanError(
        'Could not reach the scan backend. Make sure scan_api.py is running on the Detector PC.'
      );
    }
    setIsScanning(false);
  };

  const launchAttack = async () => {
    if (!targetIp) { alert('Select or enter a target IP first.'); return; }
    const profile = ATTACK_PROFILES[attackType];
    const threads = intensity === 2 ? 128 : intensity === 1 ? 32 : 8;

    // Notify backend so Detector can react
    try {
      await fetch(`${API}/attack/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: attackType, intensity, target: targetIp }),
      });
    } catch { /* backend unreachable — visual still runs */ }

    setIsAttacking(true);
    setTotalPkts(0);
    setAttackLogs([
      `[INIT]   Targeting ${targetIp}:443`,
      `[CONFIG] Vector: ${profile.label} | Intensity: ${['Low', 'Medium', 'High'][intensity]}`,
      `[NET]    Spawning ${threads} injection threads...`,
      `[START]  Attack underway — monitoring exfil...`,
    ]);

    let sent = 0;
    let iter = 0;
    const interval = setInterval(async () => {
      iter++;
      const pkts = Math.floor((1200 + Math.random() * 3000) * (intensity + 1));
      sent += pkts;
      setTotalPkts(sent);
      setAttackLogs(prev => [
        ...prev.slice(-14),
        `[${new Date().toLocaleTimeString()}] ${pkts.toLocaleString()} pkts → ${targetIp}:443 (total: ${sent.toLocaleString()})`,
      ]);

      // Keep backend in sync
      try {
        await fetch(`${API}/attack/update`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ packets_sent: sent }),
        });
      } catch { /* ignore */ }

      if (iter >= 25) {
        clearInterval(interval);
        setAttackLogs(prev => [
          ...prev,
          `[DONE]   Attack cycle finished. ${sent.toLocaleString()} total packets sent.`,
          `[SYS]    Clearing buffers. Arsenal offline.`,
        ]);
        setIsAttacking(false);
        try { await fetch(`${API}/attack/stop`, { method: 'POST' }); } catch { /* ignore */ }
      }
    }, 400);
  };

  const stopAttack = async () => {
    setIsAttacking(false);
    setAttackLogs(prev => [...prev, `[STOP]   Attack manually terminated.`]);
    try { await fetch(`${API}/attack/stop`, { method: 'POST' }); } catch { /* ignore */ }
  };

  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [attackLogs]);

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      {/* ── Target Selection ── */}
      <div className="bg-white rounded-2xl border-2 border-slate-200 shadow-sm p-6 space-y-6">
        <div className="flex items-center gap-3">
          <Search className="w-6 h-6 text-slate-700" />
          <h3 className="font-bold text-slate-800 text-lg">Network Reconnaissance</h3>
        </div>

        <button
          onClick={handleScan}
          disabled={isScanning || isAttacking}
          className={`w-full py-3 rounded-xl font-bold flex justify-center items-center gap-2 border-2 transition-colors ${
            isScanning
              ? 'border-amber-400 text-amber-500 bg-amber-50 cursor-wait'
              : 'border-blue-600 text-blue-600 hover:bg-blue-50'
          }`}
        >
          {isScanning
            ? <span className="animate-pulse">Scanning all 254 hosts...</span>
            : <><Search className="w-4 h-4" /> Scan Local Network</>}
        </button>

        {scanError && (
          <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
            {scanError}
          </div>
        )}

        {devices.length > 0 && (
          <div className="space-y-2 animate-[fadeIn_0.4s_ease-out]">
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
              Discovered Hosts <span className="text-blue-600">({devices.length})</span>
            </p>
            {devices.map(d => (
              <label
                key={d.ip}
                className={`flex items-center justify-between p-3 rounded-xl border-2 cursor-pointer transition-all ${
                  d.is_self
                    ? 'border-blue-200 bg-blue-50/50 opacity-60 pointer-events-none'
                    : targetIp === d.ip
                    ? 'border-red-500 bg-red-50'
                    : 'border-slate-100 hover:border-slate-300 bg-slate-50'
                }`}
              >
                <div className="flex items-center gap-3">
                  <input
                    type="radio"
                    name="target"
                    value={d.ip}
                    onChange={() => setTargetIp(d.ip)}
                    disabled={d.is_self}
                    className="accent-red-500 w-4 h-4"
                  />
                  <div>
                    <p className={`font-mono text-sm font-bold ${targetIp === d.ip ? 'text-red-700' : 'text-slate-700'}`}>
                      {d.ip}
                    </p>
                    <p className="text-xs text-slate-500">{d.name}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-1 bg-slate-200 text-slate-600 rounded font-mono">
                    {d.mac.substring(0, 8)}…
                  </span>
                  {d.is_self && (
                    <span className="text-xs font-bold text-blue-600 bg-blue-100 px-2 py-0.5 rounded">YOU</span>
                  )}
                </div>
              </label>
            ))}
          </div>
        )}

        <div className="pt-4 border-t border-slate-100">
          <label className="block text-sm font-medium text-slate-700 mb-2">Or Enter Manual Target IP</label>
          <input
            type="text"
            value={targetIp}
            onChange={e => setTargetIp(e.target.value)}
            placeholder="e.g. 10.209.250.95"
            className="input-box font-mono"
            disabled={isAttacking}
          />
        </div>
      </div>

      {/* ── Arsenal ── */}
      <div className={`rounded-2xl border-2 shadow-sm p-6 space-y-6 flex flex-col ${
        attackType === 'Normal Traffic'
          ? 'bg-emerald-50 border-emerald-200'
          : 'bg-red-50 border-red-200'
      }`}>
        <div className="flex items-center gap-3">
          {attackType === 'Normal Traffic'
            ? <Activity className="w-6 h-6 text-emerald-600" />
            : <ServerCrash className="w-6 h-6 text-red-600" />}
          <h3 className={`font-bold text-lg ${
            attackType === 'Normal Traffic' ? 'text-emerald-900' : 'text-red-900'
          }`}>
            {attackType === 'Normal Traffic' ? 'Normal Traffic Emulator' : 'Weapons Arsenal'}
          </h3>
          {isAttacking && (
            <span className={`ml-auto text-xs font-bold text-white px-3 py-1 rounded-full animate-pulse ${
              attackType === 'Normal Traffic' ? 'bg-emerald-600' : 'bg-red-600'
            }`}>
              LIVE
            </span>
          )}
        </div>

        <div>
          <label className={`block text-sm font-medium mb-2 ${
            attackType === 'Normal Traffic' ? 'text-emerald-800' : 'text-red-800'
          }`}>Traffic Type</label>
          <select
            value={attackType}
            onChange={e => setAttackType(e.target.value)}
            disabled={isAttacking}
            className={`input-box bg-white ${
              attackType === 'Normal Traffic'
                ? 'border-emerald-300 focus:border-emerald-500 text-emerald-900'
                : 'border-red-300 focus:border-red-500 text-red-900'
            }`}
          >
            {ATTACK_OPTIONS.map(o => <option key={o}>{o}</option>)}
          </select>
        </div>

        {attackType !== 'Normal Traffic' && (
        <div>
          <div className="flex justify-between text-sm mb-2">
            <label className="font-medium text-red-800">Botnet Intensity</label>
            <span className={`font-bold ${intensity === 2 ? 'text-red-700' : intensity === 1 ? 'text-amber-600' : 'text-emerald-600'}`}>
              {['Low (Stealth)', 'Medium', 'High (Volumetric)'][intensity]}
            </span>
          </div>
          <input
            type="range" min="0" max="2" value={intensity}
            onChange={e => setIntensity(parseInt(e.target.value))}
            disabled={isAttacking}
            className="w-full accent-red-600"
          />
        </div>
        )}

        {targetIp && (
          <div className="bg-white rounded-xl p-4 border border-red-200 text-sm space-y-1">
            <p className="text-xs text-slate-400 font-semibold uppercase tracking-wide mb-2">Target</p>
            <p className="font-mono font-bold text-red-700">{targetIp}</p>
            <p className="text-xs text-slate-500">
              {devices.find(d => d.ip === targetIp)?.name ?? 'Manual entry'}
            </p>
          </div>
        )}

        {isAttacking ? (
          <button
            onClick={stopAttack}
            className="w-full py-4 rounded-xl font-bold flex justify-center items-center gap-2 bg-slate-700 hover:bg-slate-800 text-white shadow-md mt-auto text-lg transition-all"
          >
            <Zap className="w-5 h-5" /> STOP
          </button>
        ) : (
          <button
            onClick={launchAttack}
            disabled={!targetIp}
            className={`w-full py-4 rounded-xl font-bold flex justify-center items-center gap-2 transition-all shadow-md mt-auto text-lg ${
              !targetIp
                ? 'bg-slate-300 text-slate-500 cursor-not-allowed'
                : attackType === 'Normal Traffic'
                ? 'bg-emerald-600 hover:bg-emerald-700 text-white shadow-emerald-200 hover:-translate-y-0.5'
                : 'bg-red-600 hover:bg-red-700 text-white shadow-red-200 hover:-translate-y-0.5'
            }`}
          >
            {attackType === 'Normal Traffic'
              ? <><Activity className="w-6 h-6" /> SEND NORMAL TRAFFIC</>
              : <><AlertTriangle className="w-6 h-6" /> LAUNCH ATTACK</>}
          </button>
        )}

        {attackLogs.length > 0 && (
          <div className="bg-black rounded-xl p-4 h-36 overflow-y-auto font-mono text-xs text-red-400 space-y-0.5">
            {attackLogs.map((log, i) => (
              <div key={i} className={log.startsWith('[DONE]') || log.startsWith('[SYS]') ? 'text-emerald-400' : log.startsWith('[STOP]') ? 'text-amber-400' : 'text-red-400'}>
                {log}
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector UI
// ─────────────────────────────────────────────────────────────────────────────
interface AlertEntry {
  id: number;
  type: string;
  attackerIp: string;
  targetIp: string;
  conf: number;
  features: Record<string, number>;
  explain: string;
  color: string;
}

function DetectorUI() {
  const [isRunning, setIsRunning] = useState(false);
  const [threshold, setThreshold] = useState(85);
  const [heartbeatData, setHeartbeatData] = useState<number[]>(new Array(50).fill(0));
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [status, setStatus] = useState<{ active: boolean; type: string | null; attacker_ip: string | null; target: string | null; packets_sent: number }>({
    active: false, type: null, attacker_ip: null, target: null, packets_sent: 0,
  });
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animFrame = useRef<number>(0);
  const dataRef = useRef<number[]>(new Array(50).fill(0));
  const thresholdRef = useRef(85);
  const alertCooldown = useRef(false);

  useEffect(() => { dataRef.current = heartbeatData; }, [heartbeatData]);
  useEffect(() => { thresholdRef.current = threshold; }, [threshold]);

  // Poll backend for attack state every second
  useEffect(() => {
    if (!isRunning) return;
    const poll = async () => {
      try {
        const res = await fetch(`${API}/attack/status`);
        if (!res.ok) return;
        const data = await res.json();
        setStatus({
          active: data.active,
          type: data.type,
          attacker_ip: data.attacker_ip,
          target: data.target,
          packets_sent: data.packets_sent,
        });

        if (data.active && data.type) {
          const profile = ATTACK_PROFILES[data.type];
          if (profile) {
            // Spike heartbeat
            const val = 65 + Math.random() * 35;
            setHeartbeatData(prev => {
              const next = [...prev.slice(1), val];
              dataRef.current = next;
              return next;
            });

            // Generate alert (throttled to avoid spamming)
            if (!alertCooldown.current) {
              const conf = profile.confidence();
              if (conf >= thresholdRef.current) {
                const features = profile.genFeatures();
                alertCooldown.current = true;
                setTimeout(() => { alertCooldown.current = false; }, 3000);
                setAlerts(prev => [{
                  id: Date.now(),
                  type: profile.label,
                  attackerIp: data.attacker_ip ?? 'Unknown',
                  targetIp: data.target ?? 'Self',
                  conf,
                  features,
                  explain: profile.explain(features),
                  color: profile.color,
                }, ...prev].slice(0, 10));
              }
            }
          }
        } else {
          // Normal traffic — tiny baseline
          const val = 5 + Math.random() * 15;
          setHeartbeatData(prev => {
            const next = [...prev.slice(1), val];
            dataRef.current = next;
            return next;
          });
        }
      } catch { /* backend unreachable */ }
    };

    const interval = setInterval(poll, 1000);
    return () => clearInterval(interval);
  }, [isRunning]);

  // Canvas drawing
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

      const data = dataRef.current;
      const stepX = W / (data.length - 1);
      const isHot = data[data.length - 1] > 50;

      // Fill gradient
      const grad = ctx.createLinearGradient(0, 0, 0, H);
      if (isHot) {
        grad.addColorStop(0, 'rgba(239,68,68,0.25)');
        grad.addColorStop(1, 'rgba(239,68,68,0)');
      } else {
        grad.addColorStop(0, 'rgba(59,130,246,0.2)');
        grad.addColorStop(1, 'rgba(59,130,246,0)');
      }

      ctx.beginPath();
      data.forEach((v, i) => {
        const x = i * stepX, y = H - (v / 100) * (H - 8);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath();
      ctx.fillStyle = grad; ctx.fill();

      // Stroke
      ctx.beginPath();
      data.forEach((v, i) => {
        const x = i * stepX, y = H - (v / 100) * (H - 8);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.strokeStyle = isHot ? '#ef4444' : '#3b82f6';
      ctx.lineWidth = 2.5; ctx.stroke();

      // Dot
      const lv = data[data.length - 1];
      const lx = (data.length - 1) * stepX, ly = H - (lv / 100) * (H - 8);
      ctx.beginPath(); ctx.arc(lx, ly, 4, 0, Math.PI * 2);
      ctx.fillStyle = isHot ? '#ef4444' : '#3b82f6'; ctx.fill();

      animFrame.current = requestAnimationFrame(draw);
    };
    animFrame.current = requestAnimationFrame(draw);
    return () => { live = false; cancelAnimationFrame(animFrame.current); };
  }, []);

  const reset = () => {
    setAlerts([]);
    setHeartbeatData(new Array(50).fill(0));
    setStatus({ active: false, type: null, attacker_ip: null, target: null, packets_sent: 0 });
  };

  return (
    <div className="grid lg:grid-cols-3 gap-6">
      {/* Controls */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-6 flex flex-col">
        <div className="flex items-center gap-3">
          <Monitor className="w-6 h-6 text-emerald-600" />
          <h3 className="font-bold text-slate-800 text-lg">Sensor Control</h3>
        </div>

        <div className="space-y-5">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <label className="text-sm font-medium text-slate-700">
                Confidence Threshold: <span className="font-bold text-emerald-700">{(threshold / 100).toFixed(2)}</span>
              </label>
              <span className="tip-wrap">
                <span className="text-slate-400 cursor-help text-xs">ℹ️</span>
                <span className="tip-text">Minimum ML score (0–1) to raise an alert. Higher = fewer false positives. Recommended: 0.85+</span>
              </span>
            </div>
            <input
              type="range" min={50} max={99} value={threshold}
              onChange={e => setThreshold(parseInt(e.target.value))}
              disabled={isRunning}
              className="w-full accent-emerald-500"
            />
            <div className="flex justify-between text-xs text-slate-400 mt-1">
              <span>0.50 (Sensitive)</span><span>0.99 (Strict)</span>
            </div>
          </div>

          {/* Live status badge */}
          {isRunning && (
            <div className={`rounded-xl p-4 border-2 ${status.active ? 'border-red-300 bg-red-50' : 'border-slate-200 bg-slate-50'}`}>
              <p className="text-xs font-semibold text-slate-500 mb-2 uppercase tracking-wide">Attack Status</p>
              {status.active ? (
                <div className="space-y-1 text-sm">
                  <p className="font-bold text-red-700 flex items-center gap-2">
                    <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                    {status.type}
                  </p>
                  {status.attacker_ip && <p className="font-mono text-xs text-slate-600">From: {status.attacker_ip}</p>}
                  {status.target && <p className="font-mono text-xs text-slate-600">To: {status.target}</p>}
                  <p className="text-xs text-slate-500">{status.packets_sent.toLocaleString()} pkts sent</p>
                </div>
              ) : (
                <p className="text-sm text-slate-400 animate-pulse">Monitoring… no active attack</p>
              )}
            </div>
          )}
        </div>

        <button
          onClick={() => {
            if (isRunning) { setIsRunning(false); reset(); } else setIsRunning(true);
          }}
          className={`w-full py-4 rounded-xl font-bold mt-auto transition-all shadow-md text-base ${
            isRunning ? 'bg-red-500 hover:bg-red-600 text-white' : 'bg-emerald-500 hover:bg-emerald-600 text-white'
          }`}
        >
          {isRunning ? 'Stop Monitoring' : 'Start Sensor'}
        </button>
      </div>

      {/* Monitor + Alerts */}
      <div className="lg:col-span-2 space-y-6">
        {/* Heartbeat */}
        <div className="bg-slate-900 rounded-2xl shadow-xl p-6 relative overflow-hidden">
          <div className="absolute top-4 right-4 flex items-center gap-2">
            <span className={`w-3 h-3 rounded-full ${isRunning ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'}`} />
            <span className="text-xs font-mono text-slate-400">{isRunning ? 'ACTIVE' : 'OFFLINE'}</span>
          </div>
          <div className="flex items-center gap-3 mb-4">
            <Activity className="w-5 h-5 text-emerald-400" />
            <h3 className="font-bold text-white">Live Traffic Ingress</h3>
            <span className="ml-auto text-xs text-slate-500">threshold: <strong className="text-emerald-400">{(threshold / 100).toFixed(2)}</strong></span>
          </div>
          <canvas ref={canvasRef} className="w-full h-28 bg-slate-800/50 rounded-xl" />
          <div className="flex items-center justify-between mt-2 text-xs text-slate-500">
            <span className="flex items-center gap-1"><span className="w-2 h-2 bg-red-500 rounded-full" /> Attack spike</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 bg-blue-500 rounded-full" /> Normal flow</span>
            <span>alerts: <strong className="text-amber-400">{alerts.length}</strong></span>
          </div>
        </div>

        {/* Threat Feed */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex flex-col" style={{ height: '400px' }}>
          <div className="bg-slate-50 border-b border-slate-200 px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Terminal className="w-5 h-5 text-slate-500" />
              <h3 className="font-bold text-slate-800">Threat Intelligence Feed</h3>
            </div>
            {alerts.length > 0 && (
              <span className="text-xs font-mono text-red-500 bg-red-50 px-2 py-1 rounded-full">{alerts.length} alerts</span>
            )}
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {!isRunning && alerts.length === 0 && (
              <p className="text-slate-400 text-center text-sm mt-8">Sensor offline. Start monitoring to detect attacks.</p>
            )}
            {isRunning && alerts.length === 0 && (
              <p className="text-slate-400 text-center text-sm mt-8 animate-pulse">
                Monitoring… waiting for attacker to launch.
              </p>
            )}
            {alerts.map(a => {
              const borderCls = BORDER_MAP[a.color] ?? 'border-slate-200 bg-slate-50';
              const textCls = TEXT_MAP[a.color] ?? 'text-slate-700';
              return (
                <div key={a.id} className={`border rounded-xl p-4 animate-[slideIn_0.3s_ease-out] ${borderCls}`}>
                  <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`text-white text-xs font-bold px-2 py-0.5 rounded shadow-sm ${COLOR_MAP[a.color] ?? 'bg-slate-600'}`}>
                        {a.conf >= 95 ? 'CRITICAL' : 'WARNING'}
                      </span>
                      <span className={`font-bold text-sm ${textCls}`}>{a.type}</span>
                    </div>
                    <span className={`text-xs font-bold px-2 py-1 rounded-full ${borderCls} ${textCls}`}>
                      {a.conf.toFixed(1)}% ML Conf
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                    <div><span className="text-slate-500">Source IP:</span> <span className="font-mono font-semibold">{a.attackerIp}</span></div>
                    <div><span className="text-slate-500">Target:</span> <span className="font-mono font-semibold">{a.targetIp}</span></div>
                  </div>

                  {/* Dynamic feature grid */}
                  <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {Object.entries(a.features).map(([k, v]) => (
                      <div key={k} className="bg-white rounded-lg px-3 py-2 border border-slate-200">
                        <p className="text-xs text-slate-400">{k}</p>
                        <p className="text-sm font-mono font-bold text-slate-800">
                          {typeof v === 'number' ? (v > 100 ? v.toLocaleString() : v.toFixed(4)) : v}
                        </p>
                      </div>
                    ))}
                  </div>

                  <div className="mt-3 bg-amber-50 border border-amber-100 rounded-lg p-3">
                    <p className="text-xs font-bold text-amber-800 mb-1">💡 Why flagged?</p>
                    <p className="text-xs text-amber-900">{a.explain}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
