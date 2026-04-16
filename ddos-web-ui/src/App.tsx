import { useState } from 'react';
import { ShieldCheck, Activity, Cpu, Settings, FileText, BookOpen } from 'lucide-react';
import Dashboard from './components/Dashboard';
import PcapTesting from './components/PcapTesting';
import LiveSimulation from './components/LiveSimulation';
import SettingsTab from './components/SettingsTab';
import Explainability from './components/Explainability';
import Documentation from './components/Documentation';

const tabs = [
  { id: 'dashboard', label: 'Dashboard', icon: Activity },
  { id: 'pcap', label: 'PCAP Testing', icon: Cpu },
  { id: 'live', label: 'Live Simulation', icon: ShieldCheck },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'explain', label: 'Explainability & Logs', icon: FileText },
  { id: 'docs', label: 'Documentation', icon: BookOpen },
];

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isRunning, setIsRunning] = useState(false);
  const [status, setStatus] = useState<'ready'|'running'|'stopped'|'dryrun'>('ready');

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 shadow-sm sticky top-0 z-50">
        <div className="max-w-[1440px] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center">
              <ShieldCheck className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-900 tracking-tight">Encrypted DDoS Detector</h1>
              <p className="text-xs text-slate-500">Real-time Encrypted DDoS Protection with Full Explainability</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-full ${
              status === 'running' ? 'bg-green-100 text-green-700' :
              status === 'dryrun' ? 'bg-amber-100 text-amber-700' :
              status === 'stopped' ? 'bg-red-100 text-red-700' :
              'bg-slate-100 text-slate-600'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                status === 'running' ? 'bg-green-500 animate-blink' :
                status === 'dryrun' ? 'bg-amber-500 animate-blink' :
                status === 'stopped' ? 'bg-red-500' :
                'bg-slate-400'
              }`}></span>
              {status === 'running' ? 'Running' : status === 'dryrun' ? 'Dry Run' : status === 'stopped' ? 'Stopped' : 'Ready'}
            </span>
          </div>
        </div>
        {/* Tab Bar */}
        <div className="max-w-[1440px] mx-auto px-6">
          <nav className="flex gap-1 overflow-x-auto pb-0">
            {tabs.map(tab => {
              const Icon = tab.icon;
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-all whitespace-nowrap ${
                    active
                      ? 'border-blue-600 text-blue-700'
                      : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-6 py-8">
        {activeTab === 'dashboard' && <Dashboard isRunning={isRunning} setIsRunning={setIsRunning} status={status} setStatus={setStatus} />}
        {activeTab === 'pcap' && <PcapTesting />}
        {activeTab === 'live' && <LiveSimulation />}
        {activeTab === 'settings' && <SettingsTab />}
        {activeTab === 'explain' && <Explainability />}
        {activeTab === 'docs' && <Documentation />}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-4 text-center text-xs text-slate-400">
        Built by <span className="font-semibold text-slate-600">M Dipesh Kumar, Mohammed Ismail &amp; Mohammed Hamza Iqbal</span> – Network Security Project
      </footer>
    </div>
  );
}

export default App;
