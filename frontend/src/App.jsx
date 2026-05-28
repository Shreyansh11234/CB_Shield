import { useState, useEffect, useRef } from 'react';
import {
  Terminal, Activity, ShieldAlert, Cpu, MemoryStick, Network, Server,
  AlertTriangle, XSquare
} from 'lucide-react';
import './App.css';

const API = window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')
  ? 'http://localhost:8000'
  : window.location.origin;

const WS_URL = API.replace(/^http/, 'ws') + '/ws';

function CyberBar({ value = 0, label, color = "var(--neon-green)" }) {
  return (
    <div style={{ marginTop: '2rem' }}>
      <div style={{ position: 'relative' }}>
        <span style={{ fontFamily: 'Fira Code', textTransform: 'uppercase', fontSize: '0.8rem', color: 'var(--dark-green)'}}>{label}</span>
        <span className="cyber-bar-text" style={{ color }}>{value.toFixed(1)}%</span>
      </div>
      <div className="cyber-bar-container" style={{ borderColor: color === "var(--neon-green)" ? "var(--dark-green)" : color }}>
        <div className="cyber-bar-fill" style={{ width: `${value}%`, background: color, boxShadow: `0 0 10px ${color}` }} />
      </div>
    </div>
  );
}

function RiskDisplay({ score = 0 }) {
  const level = score > 70 ? 'CRITICAL' : score > 35 ? 'WARNING' : 'SECURE';
  const color = score > 70 ? 'var(--alert-red)' : score > 35 ? 'var(--alert-yellow)' : 'var(--neon-green)';

  return (
    <div className="risk-display">
      <div className="risk-number" style={{ color }}>
        {score}
      </div>
      <div style={{ color, fontFamily: 'Fira Code', fontWeight: 'bold', letterSpacing: '2px' }}>
        [{level}]
      </div>
    </div>
  );
}

export default function App() {
  const [isScanning, setIsScanning] = useState(false);
  const [data, setData]             = useState(null);
  const [alerts, setAlerts]         = useState([]);
  const [wsState, setWsState]       = useState('connecting');
  const wsRef = useRef(null);

  useEffect(() => {
    if (!isScanning) return;

    let reconnectTimer;
    let pollTimer;
    let ws;

    function connect() {
      setWsState('connecting');
      ws = new WebSocket(WS_URL);
      wsRef.current = ws;
      
      ws.onopen = () => {
        setWsState('open');
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      };

      ws.onmessage = (evt) => {
        try {
          const payload = JSON.parse(evt.data);
          setData(payload);
          if (payload.alerts?.length) {
            setAlerts(prev => [...payload.alerts, ...prev].slice(0, 50));
          }
        } catch { }
      };

      ws.onclose = () => {
        setWsState('closed');
        // If closed, immediately trigger fallback HTTP polling
        if (!pollTimer) {
          pollTimer = setInterval(pollStats, 2000);
        }
        reconnectTimer = setTimeout(connect, 5000);
      };

      ws.onerror = () => ws.close();
    }

    async function pollStats() {
      try {
        const r = await fetch(`${API}/api/stats`);
        const payload = await r.json();
        setData(payload);
        setWsState('open'); // mock active status for UI during polling
        if (payload.alerts?.length) {
          setAlerts(prev => [...payload.alerts, ...prev].slice(0, 50));
        }
      } catch (err) {
        console.warn("Polling fallback failed:", err);
      }
    }

    connect();
    return () => { 
      clearTimeout(reconnectTimer); 
      if (pollTimer) clearInterval(pollTimer);
      wsRef.current?.close(); 
    };
  }, [isScanning]);

  async function killProcess(pid) {
    try {
      const r = await fetch(`${API}/api/action/kill_process?pid=${pid}`, { method: 'POST' });
      const d = await r.json();
      console.log(d.message);
    } catch { console.error('Kill failed'); }
  }

  async function blockIP(ip) {
    try {
      const r = await fetch(`${API}/api/action/block_ip?ip=${ip}`, { method: 'POST' });
      const d = await r.json();
      console.log(d.message);
    } catch { console.error('Block failed'); }
  }

  if (!isScanning) {
    return (
      <div className="landing-screen">
        <div className="landing-card">
          <h1 className="landing-header">
            <Terminal size={48} style={{ verticalAlign: 'middle', marginRight: '10px', color: 'var(--neon-green)' }} />
            SENTINEL_AI
          </h1>
          
          <div style={{ lineHeight: '1.6', fontSize: '0.95rem' }}>
            <p>
              Welcome to the digital frontline. <strong>Sentinel AI</strong> is an advanced system monitoring and intrusion detection system designed to inspect processes, active network connections, CPU/RAM utilization metrics, and identify anomalies using local machine learning engines in real-time.
            </p>

            <div className="nindo-box">
              <div className="nindo-title">SHREYANSH KUMAR RAO'S NINDO (忍者クリード)</div>
              "To protect the integrity of our digital systems, safeguard user trust, monitor anomalies tirelessly, and never back down in the face of threats — that is my Nindo!"
            </div>

            <p style={{ marginTop: '1rem' }}>
              Built as a shield against digital threats, Sentinel AI implements live Isolation Forest anomaly forecasting, automated firewall rule injection, and system health checks on a cybernetic visual telemetry console.
            </p>
          </div>

          <div className="landing-meta">
            <div>
              <strong>SYSTEM ARCHITECT:</strong><br />
              Shreyansh Kumar Rao
            </div>
            <div>
              <strong>NINDO MISSION:</strong><br />
              Shield, Detect, and Eliminate
            </div>
          </div>

          <button className="btn-scan-start" onClick={() => setIsScanning(true)}>
            INITIALIZE SECURITY SCAN &gt;
          </button>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="splash">
        <div>{">"} ESTABLISHING SECURE CONNECTION...<span className="blink-cursor">_</span></div>
        <div className="loader-bar"></div>
      </div>
    );
  }

  const isTraining = data.ai_status?.includes('Training');
  const riskScore  = data.ai_analysis?.risk_score ?? 0;
  const badgeClass = wsState !== 'open' ? 'badge--offline' : isTraining ? 'badge--training' : '';
  const badgeText  = wsState !== 'open' ? 'CONNECTION_LOST' : isTraining ? data.ai_status.toUpperCase() : 'SYSTEM_SECURE';

  return (
    <div className="dashboard">
      <header className="header">
        <div>
          <div className="sys-prompt">root@sentinel:~# ./monitor.sh</div>
          <h1 className="glitch-title">
            <Terminal size={40} /> SENTINEL_AI<span className="blink-cursor">_</span>
          </h1>
        </div>
        <div className={`badge ${badgeClass}`}>
          [{badgeText}]
        </div>
      </header>

      <div className="stats-row">
        <div className="card">
          <div className="card-header">
            <span><Cpu size={18} /> CPU_METRICS</span>
            <span style={{fontSize:'0.8rem', opacity: 0.5}}>0x01</span>
          </div>
          <CyberBar value={data.cpu_percent} label="utilization" color={data.cpu_percent > 80 ? "var(--alert-red)" : "var(--neon-green)"} />
        </div>

        <div className="card">
          <div className="card-header">
            <span><MemoryStick size={18} /> MEM_METRICS</span>
            <span style={{fontSize:'0.8rem', opacity: 0.5}}>0x02</span>
          </div>
          <CyberBar value={data.memory_percent} label="allocation" color={data.memory_percent > 80 ? "var(--alert-yellow)" : "var(--neon-green)"} />
        </div>

        <div className="card">
          <div className="card-header">
            <span><Activity size={18} /> THREAT_ANALYSIS</span>
            <span style={{fontSize:'0.8rem', opacity: 0.5}}>0x03</span>
          </div>
          <RiskDisplay score={riskScore} />
        </div>
      </div>

      <div className="main-grid">
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <div className="card-header">
              <span><Server size={18} /> ACTIVE_PROCESSES</span>
              <span>[{data.process_count}]</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>EXECUTABLE</th>
                    <th>CPU%</th>
                    <th>MEM%</th>
                    <th>CMD</th>
                  </tr>
                </thead>
                <tbody>
                  {data.processes.map(p => (
                    <tr key={p.pid}>
                      <td>{p.pid}</td>
                      <td style={{ color: '#fff' }}>{p.name}</td>
                      <td style={{ color: p.cpu_percent > 50 ? 'var(--alert-red)' : 'inherit'}}>{p.cpu_percent.toFixed(1)}</td>
                      <td>{p.memory_percent.toFixed(1)}</td>
                      <td>
                        <button className="btn btn-kill" onClick={() => killProcess(p.pid)}>
                          SIGKILL
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <div className="card-header">
              <span><Network size={18} /> NET_CONNECTIONS</span>
              <span>[{data.connections.length}]</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>LOCAL_ADDR</th>
                    <th>REMOTE_ADDR</th>
                    <th>STATE</th>
                    <th>CMD</th>
                  </tr>
                </thead>
                <tbody>
                  {data.connections.length === 0 ? (
                    <tr><td colSpan={4} style={{ textAlign: 'center', opacity: 0.5 }}>NO_ACTIVE_CONNECTIONS</td></tr>
                  ) : data.connections.map((c, i) => (
                    <tr key={i}>
                      <td>{c.laddr}</td>
                      <td style={{ color: c.raddr ? '#fff' : 'inherit' }}>{c.raddr || 'N/A'}</td>
                      <td>{c.status}</td>
                      <td>
                        {c.raddr && (
                          <button className="btn btn-block" onClick={() => blockIP(c.raddr.split(':')[0])}>
                            DROP
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header" style={{ borderColor: 'var(--alert-red)', color: 'var(--alert-red)' }}>
            <span><ShieldAlert size={18} /> IDS_LOGS</span>
            <span className="blink-cursor">_</span>
          </div>
          
          <div className="alert-feed">
            {alerts.length === 0 ? (
              <div style={{ opacity: 0.5, textAlign: 'center', marginTop: '2rem' }}>
                <Terminal size={40} style={{ margin: '0 auto 1rem' }} />
                {">"} NO ANOMALIES DETECTED
              </div>
            ) : (
              alerts.map((a, i) => {
                const isHigh = a.risk_level === 'High';
                const isMed = a.risk_level === 'Medium';
                const cls = isHigh ? 'high' : isMed ? 'medium' : 'low';
                return (
                  <div key={i} className={`alert-item ${cls}`}>
                    <div className="alert-meta">
                      <span>[{a.source.toUpperCase()}]</span>
                      <span>{new Date(a.timestamp * 1000).toLocaleTimeString()}</span>
                    </div>
                    <div className="alert-desc">
                      {">"} {a.description}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
