'use client';

import { useState, useRef, useEffect } from 'react';
import { ShieldAlert, Terminal, Activity } from 'lucide-react'; 

interface ComplianceCheck {
  id: string;
  name: string;
  description: string;
  status: 'SAFE' | 'VULNERABLE';
}

// --- 1. SMART FORMATTER ENGINE ---
// This cleans up the messy Markdown logs and rewrites them into human-readable text
const humanizeLog = (rawLine: string): string | null => {
  // A. CLEANUP: Strip ANSI codes
  let line = rawLine.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, ''); 
  
  // B. CLEANUP: Remove Markdown artifacts (*, **, -)
  line = line.replace(/\*\*/g, ''); // Remove bold markers
  line = line.replace(/^\*\s/, ''); // Remove bullet points at start
  line = line.replace(/^-\s/, '');  // Remove dash bullets at start
  line = line.trim();

  // C. FILTER: Blocklist (Hide technical noise)
  const NOISE_PATTERNS = [
    "HTTP Request:", "Found credentials", "AFC is enabled", "--- [NODE]", 
    "[DEBUG]", "Traceback", "Input:", "Enter your", "batch_size", "invoke",
    "[USER]: Found Users", "[USER]: CloudTrail", "Plan Parser"
  ];
  if (NOISE_PATTERNS.some(p => line.includes(p)) || line.length < 5) return null;

  // D. REWRITE: Turn robotic logs into meaningful sentences
  
  // Case 1: Remediation Plans
  // Raw: "🔴 [CRITICAL] S3 Bucket x is vulnerable -> ACTION: I will call block_s3"
  if (line.includes("ACTION:")) {
    const resource = line.match(/\] (.*?) is vulnerable/)?.[1] || "Resource";
    const actionRaw = line.match(/ACTION: I will call `?(.*?)`?/)?.[1] || "fix it";
    const action = actionRaw.replace(/_/g, ' ').toUpperCase();
    return `⚠️ Threat detected on ${resource}. Planning to ${action}.`;
  }

  // Case 2: Finding Users
  // Raw: "[USER]: Found Users: admin, dev-user-01"
  if (line.includes("Found Users:")) {
    const users = line.split("Found Users:")[1].trim();
    return `🔍 Identity Scan complete. Active accounts detected: ${users}`;
  }

  // Case 3: CloudTrail Evidence
  // Raw: "[USER]: CloudTrail: 'bucket-x' touched by admin..."
  if (line.includes("CloudTrail:")) {
    const detail = line.split("CloudTrail:")[1].trim();
    return `🕵️ Forensic Evidence found in logs: ${detail}`;
  }

  // Case 4: Auditor Headers
  // Raw: "1. Vulnerabilities Identified"
  if (line.match(/^\d+\.\s/)) {
    return `📌 ${line}`; // Add pin to headers
  }

  // Case 5: Success Messages
  if (line.includes("SUCCESS")) {
    return line.replace("✅ SUCCESS:", "✔ Verified Fix:");
  }

  // Case 6: Generic Cleanups
  line = line.replace("[AGENT]:", "").trim();
  line = line.replace("[USER]:", "").trim();
  line = line.replace("[ACTION_REQUIRED]", "").trim();
  
  return line;
};

// --- UI HELPER: Parse Approval Items for the Table ---
const parseRemediationItem = (line: string) => {
  const resourceMatch = line.match(/\[CRITICAL\] (.*?) is vulnerable/);
  const actionMatch = line.match(/ACTION: I will call `?(.*?)`?/);

  if (resourceMatch && actionMatch) {
    let readableAction = actionMatch[1].replace(/_/g, ' ').toUpperCase();
    // Make action friendlier
    if (readableAction.includes("RESTRICT IAM")) readableAction = "REVOKE ADMIN PRIVILEGES";
    if (readableAction.includes("BLOCK S3")) readableAction = "BLOCK PUBLIC ACCESS";
    if (readableAction.includes("STOP EC2")) readableAction = "QUARANTINE INSTANCE";
    if (readableAction.includes("REVOKE SECURITY")) readableAction = "CLOSE PORT 22";
    if (readableAction.includes("ENABLE VPC")) readableAction = "ENABLE FLOW LOGS";
    return { resource: resourceMatch[1], action: readableAction };
  }
  return null;
};

export default function Home() {
  const [logs, setLogs] = useState<string[]>([]);
  const [checks, setChecks] = useState<ComplianceCheck[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [currentTask, setCurrentTask] = useState<string>('SYSTEM READY');
  const [status, setStatus] = useState<'IDLE' | 'ATTACKING' | 'DEFENDING'>('IDLE');
  const [waitingForApproval, setWaitingForApproval] = useState(false);
  const [remediationPlan, setRemediationPlan] = useState<{resource: string, action: string}[]>([]);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => { terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);

  // POLL DB STATUS
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/status');
        const data = await res.json();
        setChecks(data);
      } catch (e) { console.error(e); }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleApprove = async () => {
    try {
        setWaitingForApproval(false);
        await fetch('http://localhost:8000/api/approve', { method: 'POST' });
    } catch (e) { console.error(e); }
  };

  const streamLogs = async (endpoint: string, mode: 'ATTACKING' | 'DEFENDING') => {
    setIsRunning(true);
    setStatus(mode);
    setLogs([]); 
    setWaitingForApproval(false);
    setRemediationPlan([]);
    
    if (mode === 'ATTACKING') setCurrentTask('INITIALIZING ATTACK...');
    if (mode === 'DEFENDING') setCurrentTask('STARTING AGENT...');

    try {
      const response = await fetch(`http://localhost:8000/api/${endpoint}`);
      if (!response.body) return;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        
        const chunk = decoder.decode(value);
        const lines = chunk.split('\n').filter(Boolean);
        
        lines.forEach(rawLine => {
            // 1. RAW LINE CHECKS (Before Cleanup) for Logic Triggers
            if (rawLine.includes("[PHASE 1]")) setCurrentTask("PHASE 1: DESTROYING INFRASTRUCTURE");
            if (rawLine.includes("[PHASE 2]")) setCurrentTask("PHASE 2: INJECTING VULNERABILITIES");
            if (rawLine.includes("REMEDIATION EXECUTION PLAN")) setCurrentTask("PHASE 2: PLANNING REMEDIATION");
            
            // Build Approval Table with DEDUPLICATION
            if (rawLine.includes("🔴 [CRITICAL]") || rawLine.includes("🔴 [POLICY")) {
                const item = parseRemediationItem(rawLine);
                if (item) {
                    setRemediationPlan(prev => {
                        // FIX: Check if this specific item already exists before adding
                        const exists = prev.some(p => p.resource === item.resource && p.action === item.action);
                        if (exists) return prev;
                        return [...prev, item];
                    });
                }
            }
            
            // Detect Approval Pause
            if (rawLine.includes("[ACTION_REQUIRED] WAITING_FOR_APPROVAL")) {
                setWaitingForApproval(true);
                setCurrentTask("⚠️ WAITING FOR AUTHORIZATION");
            }

            // 2. LOG CLEANUP (The "Meaningful Sentences" Logic)
            const cleanLine = humanizeLog(rawLine);
            if (cleanLine) {
                 setLogs((prev) => [...prev, cleanLine]);
            }
        });
      }
    } catch (err) {
      setLogs((prev) => [...prev, `[UI ERROR] ${err}`]);
    } finally {
      setIsRunning(false);
      setStatus('IDLE');
      setCurrentTask('OPERATION COMPLETE');
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 text-slate-200 p-8 font-mono">
      {/* HEADER */}
      <header className="max-w-7xl mx-auto mb-8 border-b border-slate-800 pb-6 flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
            🛡️ AEGIS-FLOW SOC
          </h1>
          <p className="text-slate-500 mt-2">Autonomous Security Orchestration & Response</p>
        </div>
        <div className="flex gap-4">
           <div className="px-4 py-2 bg-slate-900 rounded border border-slate-800 min-w-[250px] text-center">
            <span className="text-xs text-slate-500 block">CURRENT STATUS</span>
            <span className={`text-sm font-bold animate-pulse ${
                waitingForApproval ? 'text-yellow-400' : 
                status === 'ATTACKING' ? 'text-red-500' : 
                status === 'DEFENDING' ? 'text-blue-400' : 'text-slate-300'
            }`}>
              {currentTask}
            </span>
          </div>
        </div>
      </header>

      {/* INFRASTRUCTURE HEALTH */}
      <section className="max-w-7xl mx-auto mb-8">
        <h2 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4">Infrastructure Health</h2>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {checks.map((check) => (
            <div key={check.id} className={`p-4 rounded-lg border transition-all duration-500 ${
              check.status === 'VULNERABLE' 
                ? 'bg-red-950/30 border-red-500/50 shadow-[0_0_15px_rgba(220,38,38,0.2)]' 
                : 'bg-emerald-950/30 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.2)]'
            }`}>
              <div className="flex justify-between items-start mb-2">
                <span className={`text-xs font-bold px-2 py-1 rounded ${
                  check.status === 'VULNERABLE' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
                }`}>
                  {check.status}
                </span>
                <Activity className={`w-4 h-4 ${check.status === 'VULNERABLE' ? 'text-red-500' : 'text-emerald-500'}`} />
              </div>
              <h3 className="text-sm font-bold text-slate-200">{check.name}</h3>
            </div>
          ))}
        </div>
      </section>

      {/* CONTROLS & TERMINAL */}
      <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-4 gap-8">
        
        {/* SIDEBAR */}
        <div className="space-y-6">
          <div className={`p-6 rounded-lg border bg-slate-900/50 ${status === 'ATTACKING' ? 'border-red-500' : 'border-red-900/30'}`}>
            <h3 className="text-red-400 font-bold mb-2">1. ATTACK</h3>
            <button
              onClick={() => streamLogs('reset', 'ATTACKING')}
              disabled={isRunning}
              className="w-full py-3 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-bold rounded shadow-lg transition-all"
            >
              💥 SIMULATE BREACH
            </button>
          </div>

          <div className={`p-6 rounded-lg border bg-slate-900/50 ${status === 'DEFENDING' ? 'border-blue-500' : 'border-blue-900/30'}`}>
            <h3 className="text-blue-400 font-bold mb-2">2. DEFENSE</h3>
            <button
              onClick={() => streamLogs('run-agent', 'DEFENDING')}
              disabled={isRunning}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold rounded shadow-lg transition-all"
            >
              🛡️ DEPLOY AEGIS
            </button>
          </div>
        </div>

        {/* FEED / APPROVAL */}
        <div className="lg:col-span-3 flex flex-col gap-4">
            
            {/* APPROVAL UI */}
            {waitingForApproval && (
                <div className="bg-slate-900 border-2 border-yellow-500 rounded-lg p-6 animate-in slide-in-from-top-4 fade-in duration-500 shadow-[0_0_30px_rgba(234,179,8,0.2)]">
                    <div className="flex justify-between items-center mb-6">
                        <div className="flex items-center gap-3">
                            <ShieldAlert className="text-yellow-500 w-8 h-8" />
                            <div>
                                <h2 className="text-xl font-bold text-yellow-400">Authorization Required</h2>
                                <p className="text-sm text-slate-400">Critical risks detected. Please authorize remediation.</p>
                            </div>
                        </div>
                        <button 
                            onClick={handleApprove}
                            className="bg-yellow-500 hover:bg-yellow-400 text-black font-bold py-3 px-8 rounded shadow-lg transition-all hover:scale-105"
                        >
                            ✓ AUTHORIZE FIXES
                        </button>
                    </div>

                    <div className="bg-black/50 rounded border border-slate-700 overflow-hidden">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-slate-800 text-slate-400">
                                <tr>
                                    <th className="p-3">Vulnerable Resource</th>
                                    <th className="p-3">Proposed Action</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800">
                                {remediationPlan.map((item, idx) => (
                                    <tr key={idx} className="hover:bg-slate-800/50">
                                        <td className="p-3 font-mono text-red-300">{item.resource}</td>
                                        <td className="p-3 font-bold text-blue-300">{item.action}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* LIVE FEED */}
            <div className="bg-black rounded-lg border border-slate-800 overflow-hidden flex flex-col h-[500px]">
                <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 text-xs text-slate-500 uppercase tracking-widest flex justify-between">
                    <div className="flex items-center gap-2">
                        <Terminal className="w-4 h-4" />
                        <span>Live Operations Feed</span>
                    </div>
                    {isRunning && <span className="animate-pulse text-green-400">● LIVE</span>}
                </div>
                <div className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-relaxed scrollbar-hide">
                    {logs.length === 0 && <div className="text-slate-700 italic">System Ready. Waiting for commands...</div>}
                    {logs.map((log, i) => (
                    <div key={i} className="mb-2 border-l-2 border-slate-800 pl-3 break-all">
                        <span className={
                        log.includes("Verified") || log.includes("SECURE") ? "text-green-400" : 
                        log.includes("Threat") || log.includes("CRITICAL") ? "text-red-400 font-bold" : 
                        log.includes("PHASE") ? "text-blue-300 font-bold underline my-2 block" :
                        log.includes("Evidence") ? "text-orange-300" : "text-slate-300"
                        }>
                        {log}
                        </span>
                    </div>
                    ))}
                    <div ref={terminalEndRef} />
                </div>
            </div>
        </div>
      </div>
    </main>
  );
}