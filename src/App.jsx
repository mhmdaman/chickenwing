import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Shield,
  Activity,
  Lock,
  Settings,
  Play,
  Search,
  AlertCircle,
  Cpu,
  Trash2,
  Square,
  ChevronDown,
  ChevronUp,
  Ban,
  X,
  CheckCircle,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

import logo from './assets/logo.png';

const API_BASE = 'http://localhost:8000/api';

// Authenticated fetch helper
let apiToken = null;

const authedFetch = async (url, options = {}) => {
  if (!apiToken) {
    const res = await fetch(`${API_BASE}/token`);
    const data = await res.json();
    apiToken = data.token;
  }
  return fetch(url, {
    ...options,
    headers: { ...options.headers, 'X-API-Token': apiToken },
  });
};

const App = () => {
  const [activeTab, setActiveTab] = useState('traffic');
  const [isSniffing, setIsSniffing] = useState(false);
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ packet_count: 0, alert_count: 0 });
  const [richStats, setRichStats] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [protoFilter, setProtoFilter] = useState('All');
  const [dismissedAlerts, setDismissedAlerts] = useState(new Set());
  const [blockedHosts, setBlockedHosts] = useState(new Set());
  const [expandedAlert, setExpandedAlert] = useState(null);
  const [settings, setSettings] = useState({
    tlsInspector: true,
    heuristicEngine: true,
    autoBlock: false,
    privacyAlerts: true,
  });

  const visibleAlerts = useMemo(
    () => {
      const filtered = alerts.filter(a => !dismissedAlerts.has(a.id));
      if (activeTab === 'shield') {
        return filtered.filter(a => !a.type.includes('Site Visit'));
      }
      if (activeTab === 'web-audit') {
        return filtered.filter(a => a.type.includes('Site Visit'));
      }
      return filtered;
    },
    [alerts, dismissedAlerts, activeTab]
  );

  const dismissAlert = useCallback((id) => {
    setDismissedAlerts(prev => new Set([...prev, id]));
  }, []);

  const resolveAll = useCallback(() => {
    setDismissedAlerts(new Set(alerts.map(a => a.id)));
  }, [alerts]);

  const blockHost = useCallback((host) => {
    setBlockedHosts(prev => new Set([...prev, host]));
  }, []);

  const clearAllData = useCallback(async () => {
    try {
      await authedFetch(`${API_BASE}/clear`, { method: 'POST' });
      setDismissedAlerts(new Set());
      setBlockedHosts(new Set());
    } catch (err) { }
  }, []);

  const toggleSetting = useCallback((key) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }));
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statRes, pktRes, alertRes, statsRes] = await Promise.all([
          authedFetch(`${API_BASE}/status`),
          authedFetch(`${API_BASE}/packets?count=100`),
          authedFetch(`${API_BASE}/alerts`),
          authedFetch(`${API_BASE}/stats`),
        ]);

        const statData = await statRes.json();
        const pktData = await pktRes.json();
        const alertData = await alertRes.json();
        const statsData = await statsRes.json();

        setIsSniffing(statData.sniffing);
        setStats(statData);
        setPackets(pktData);
        setAlerts(alertData);
        setRichStats(statsData);
      } catch (err) { }
    };

    const interval = setInterval(fetchData, 2000);
    fetchData();
    return () => clearInterval(interval);
  }, []);

  const toggleSniffing = async () => {
    const endpoint = isSniffing ? 'stop' : 'start';
    try {
      await authedFetch(`${API_BASE}/${endpoint}`, { method: 'POST' });
      setIsSniffing(!isSniffing);
    } catch (err) { }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const filteredPackets = useMemo(
    () =>
      packets.filter((p) => {
        const matchesSearch =
          !searchTerm ||
          p.src_ip?.includes(searchTerm) ||
          p.dst_ip?.includes(searchTerm) ||
          p.protocol?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          p.dst_domain?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          p.app?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          p.service?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          p.category?.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesProto =
          protoFilter === 'All' ||
          p.protocol === protoFilter ||
          p.category === protoFilter;
        return matchesSearch && matchesProto;
      }),
    [packets, searchTerm, protoFilter]
  );

  return (
    <div className="flex h-screen bg-black text-white overflow-hidden font-display">
      <div className="scanline" />

      {/* Sidebar */}
      <aside className="w-[280px] border-r border-white/5 flex flex-col z-20">
        <div className="p-8">
          <div className="mb-12">
            <div className="flex items-center gap-4 mb-4">
              <img src={logo} alt="Chickenwing Logo" className="w-12 h-12 rounded-lg border border-white/10" />
              <div>
                <h1 className="font-logo text-2xl tracking-tight leading-none">Chickenwing</h1>
                <div className="inline-block px-2 py-0.5 border border-white/20 text-[8px] font-mono text-white/40 uppercase mt-1">
                  For Your Safety!
                </div>
              </div>
            </div>
          </div>

          <div className="meta mb-6 opacity-40 uppercase">Navigation</div>
          <nav className="space-y-1">
            <NavItem
              active={activeTab === 'overview'}
              onClick={() => setActiveTab('overview')}
              icon={<Activity size={16} />}
              label="Overview"
              index="01"
            />
            <NavItem
              active={activeTab === 'traffic'}
              onClick={() => setActiveTab('traffic')}
              icon={<Cpu size={16} />}
              label="Traffic Analysis"
              index="02"
            />
            <NavItem
              active={activeTab === 'shield'}
              onClick={() => setActiveTab('shield')}
              icon={<Lock size={16} />}
              label="Vulnerability Scan"
              index="03"
            />
            <NavItem
              active={activeTab === 'web-audit'}
              onClick={() => setActiveTab('web-audit')}
              icon={<Search size={16} />}
              label="Web Audit"
              index="04"
            />
            <NavItem
              active={activeTab === 'prefs'}
              onClick={() => setActiveTab('prefs')}
              icon={<Settings size={16} />}
              label="Preferences"
              index="05"
            />
          </nav>
        </div>

        <div className="mt-auto p-6 space-y-6">
          <div className="space-y-4">
            <div className="meta opacity-40 uppercase">Engine Status</div>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${isSniffing ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-white/20'}`} />
              <span className="text-xs font-mono tracking-wider opacity-60 uppercase">
                {isSniffing ? 'Active' : (stats.error ? 'Error' : 'Standby')}
              </span>
            </div>

            {stats.error && (
              <div className="bg-red-500/10 border border-red-500/20 p-4 text-[10px] font-mono text-red-500 uppercase leading-relaxed">
                Critical Engine Error: {stats.error}<br/>
                <span className="opacity-60 mt-2 block">Run with sudo / administrator privileges</span>
              </div>
            )}

            <button
              onClick={toggleSniffing}
              className="btn-capture w-full py-4 flex items-center justify-center gap-3 active:scale-[0.98] transition-transform"
            >
              <Play size={14} fill="currentColor" />
              {isSniffing ? 'STOP CAPTURE' : 'START CAPTURE'}
            </button>
          </div>

          <div className="pt-6 border-t border-white/5 flex items-center justify-between meta opacity-30 uppercase">
            <span>UPLINK en0</span>
            <span>1 Gbps</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col relative overflow-hidden">
        <header className="h-[100px] border-b border-white/5 flex items-center justify-between px-10 flex-shrink-0">
          <div className="flex items-center gap-12">
            <div>
              <h2 className="text-4xl font-bold tracking-tight mb-1">
                {activeTab === 'overview' && 'Overview'}
                {activeTab === 'traffic' && 'Traffic Analysis'}
                {activeTab === 'shield' && 'Vulnerability Scan'}
                {activeTab === 'web-audit' && 'Web Audit'}
                {activeTab === 'prefs' && 'Preferences'}
              </h2>
              <div className="meta opacity-40 uppercase tracking-[0.2em]">
                / MODULE 0{activeTab === 'overview' ? '1' : activeTab === 'traffic' ? '2' : activeTab === 'shield' ? '3' : activeTab === 'web-audit' ? '4' : '5'} .
                {activeTab === 'overview' && ' LAST HOUR'}
                {activeTab === 'traffic' && ' PACKET LOG'}
                {activeTab === 'web-audit' && ' WEB ACCESS LOG'}
                {activeTab === 'prefs' && ' SYSTEM CONFIGURATION'}
              </div>
            </div>

            <div className="relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 opacity-20" size={16} />
              <input
                type="text"
                placeholder="Filter by IP, domain.."
                className="bg-white/5 border border-white/10 rounded-sm py-3 pl-12 pr-10 text-xs font-mono w-[320px] focus:outline-none focus:border-white/30 transition-colors uppercase"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              <span className="absolute right-4 top-1/2 -translate-y-1/2 text-[9px] font-mono opacity-20">⌘K</span>
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto custom-scrollbar p-10">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              {activeTab === 'overview' && (
                <div className="space-y-12">
                  {/* Top stats row */}
                  <div className="grid grid-cols-4 gap-10">
                    <div className="space-y-3">
                      <div className="meta opacity-40 uppercase">Total Packets</div>
                      <div className="text-6xl font-bold">{stats.packet_count || 0}</div>
                      {stats.uptime && <div className="text-xs font-mono text-green-500 uppercase tracking-widest">Uptime {stats.uptime}</div>}
                    </div>
                    <div className="space-y-3">
                      <div className="meta opacity-40 uppercase">Bandwidth</div>
                      <div className="text-6xl font-bold">{formatBytes(stats.total_bytes)}</div>
                      <div className="text-xs font-mono opacity-40 uppercase tracking-widest">Total captured</div>
                    </div>
                    <div className="space-y-3">
                      <div className="meta opacity-40 uppercase">Connections</div>
                      <div className="text-6xl font-bold">{stats.unique_connections || 0}</div>
                      <div className="text-xs font-mono opacity-40 uppercase tracking-widest">Unique flows</div>
                    </div>
                    <div className="space-y-3">
                      <div className="meta opacity-40 uppercase">Security Alerts</div>
                      <div className="text-6xl font-bold text-red-500">{stats.alert_count || 0}</div>
                      <div className="text-xs font-mono opacity-40 uppercase tracking-widest">{stats.unique_domains || 0} domains seen</div>
                    </div>
                  </div>

                  {/* Protocol & Category breakdown */}
                  <div className="grid grid-cols-2 gap-12">
                    <div className="space-y-4">
                      <div className="meta opacity-40 uppercase">Protocol Distribution</div>
                      <div className="space-y-2">
                        {richStats?.protocol_distribution && Object.entries(richStats.protocol_distribution).slice(0, 8).map(([proto, count]) => (
                          <div key={proto} className="flex items-center justify-between font-mono text-xs uppercase tracking-wider">
                            <span className="opacity-60">{proto}</span>
                            <div className="flex items-center gap-3">
                              <div className="w-32 h-1 bg-white/5 overflow-hidden"><div className="h-full bg-white/30" style={{ width: `${Math.min(100, (count / (richStats.total_packets || 1)) * 100)}%` }} /></div>
                              <span className="opacity-40 w-12 text-right">{count}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="space-y-4">
                      <div className="meta opacity-40 uppercase">Traffic Categories</div>
                      <div className="space-y-2">
                        {richStats?.category_distribution && Object.entries(richStats.category_distribution).map(([cat, count]) => (
                          <div key={cat} className="flex items-center justify-between font-mono text-xs uppercase tracking-wider">
                            <span className="opacity-60">{cat}</span>
                            <div className="flex items-center gap-3">
                              <div className="w-32 h-1 bg-white/5 overflow-hidden"><div className="h-full bg-green-500/50" style={{ width: `${Math.min(100, (count / (richStats.total_packets || 1)) * 100)}%` }} /></div>
                              <span className="opacity-40 w-12 text-right">{count}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Top Domains & Top Apps */}
                  <div className="grid grid-cols-2 gap-12">
                    <div className="space-y-4">
                      <div className="meta opacity-40 uppercase">Top Destinations</div>
                      <div className="space-y-2">
                        {richStats?.top_domains?.slice(0, 8).map((d, i) => (
                          <div key={i} className="flex items-center justify-between font-mono text-xs tracking-wider">
                            <span className="opacity-60 truncate max-w-[250px]">{d.domain}</span>
                            <span className="opacity-40">{d.count} hits</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="space-y-4">
                      <div className="meta opacity-40 uppercase">Top Apps by Bandwidth</div>
                      <div className="space-y-2">
                        {richStats?.top_apps?.slice(0, 8).map((a, i) => (
                          <div key={i} className="flex items-center justify-between font-mono text-xs uppercase tracking-wider">
                            <span className="opacity-60">{a.app}</span>
                            <span className="opacity-40">{formatBytes(a.bytes)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'traffic' && (
                <div className="space-y-8">
                  <div className="flex items-center justify-between">
                    <div className="flex gap-2">
                      {['All', 'HTTPS', 'HTTP', 'DNS', 'TCP', 'UDP', 'Email', 'Browsing'].map(f => (
                        <button key={f} className={`filter-btn ${protoFilter === f ? 'active' : ''}`} onClick={() => setProtoFilter(f)}>{f}</button>
                      ))}
                    </div>
                    <div className="meta opacity-30 uppercase tracking-widest">
                      {filteredPackets.length} PACKETS MATCHING CURRENT FILTER
                    </div>
                  </div>

                  <div className="w-full">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr>
                          <th className="table-header">Timestamp</th>
                          <th className="table-header">Application</th>
                          <th className="table-header">Protocol</th>
                          <th className="table-header">Flags</th>
                          <th className="table-header">Endpoint</th>
                          <th className="table-header text-right">Size</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPackets.length > 0 ? (
                          filteredPackets.map((pkt, i) => (
                            <tr key={i} className="table-row group">
                              <td className="px-6 py-5 opacity-40 group-hover:opacity-100 transition-opacity">{pkt.time}</td>
                              <td className="px-6 py-5">{pkt.service || pkt.app || 'System'}</td>
                              <td className="px-6 py-5 opacity-40 group-hover:opacity-100 transition-opacity">{pkt.protocol}</td>
                              <td className="px-6 py-5 font-mono text-[10px] text-blue-400/70 uppercase">{pkt.flags || '—'}</td>
                              <td className="px-6 py-5">{pkt.dst_domain || pkt.dst_ip}</td>
                              <td className="px-6 py-5 text-right opacity-40 group-hover:opacity-100 transition-opacity">{formatBytes(pkt.size)}</td>
                            </tr>
                          ))
                        ) : (
                          [...Array(8)].map((_, i) => (
                            <tr key={i} className="table-row opacity-20">
                              <td className="px-6 py-5">18:12:20</td>
                              <td className="px-6 py-5">Google Chrome Helper</td>
                              <td className="px-6 py-5">TCP</td>
                              <td className="px-6 py-5 opacity-20">S</td>
                              <td className="px-6 py-5">192.168.29.245</td>
                              <td className="px-6 py-5 text-right">74 B</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === 'shield' && (
                <div className="space-y-8">
                  <div className={`${visibleAlerts.length > 0 ? 'bg-red-500/10 border-red-500/20' : 'bg-green-500/10 border-green-500/20'} border p-8 flex items-center justify-between`}>
                    <div className="flex items-center gap-6">
                      <div className={`w-12 h-12 ${visibleAlerts.length > 0 ? 'bg-red-500/20 text-red-500' : 'bg-green-500/20 text-green-500'} flex items-center justify-center`}>
                        {visibleAlerts.length > 0 ? <AlertCircle size={24} /> : <CheckCircle size={24} />}
                      </div>
                      <div>
                        <div className={`text-2xl font-bold ${visibleAlerts.length > 0 ? 'text-red-500' : 'text-green-500'} flex items-center gap-3`}>
                          {visibleAlerts.length > 0 ? `${visibleAlerts.length} Potential Vulnerabilities Detected` : 'All Clear — No Vulnerabilities Found'}
                        </div>
                        <div className="meta opacity-40 mt-1 uppercase tracking-widest">
                          {blockedHosts.size > 0 && `${blockedHosts.size} hosts blocked · `}Heuristic engine active
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-3">
                      {visibleAlerts.length > 0 && (
                        <button onClick={resolveAll} className="bg-white text-black text-xs font-mono font-bold px-6 py-3 tracking-[0.2em] hover:bg-white/90 active:scale-[0.98] transition-all uppercase">
                          Resolve All
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Blocked hosts list */}
                  {blockedHosts.size > 0 && (
                    <div className="border border-white/5 p-6">
                      <div className="meta opacity-40 uppercase mb-4">Blocked Hosts</div>
                      <div className="flex flex-wrap gap-2">
                        {[...blockedHosts].map(host => (
                          <div key={host} className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 px-3 py-1.5 text-xs font-mono">
                            <Ban size={10} className="text-red-500" />
                            <span className="text-red-400">{host}</span>
                            <button onClick={() => setBlockedHosts(prev => { const n = new Set(prev); n.delete(host); return n; })} className="opacity-40 hover:opacity-100 transition-opacity">
                              <X size={10} />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {visibleAlerts.length > 0 ? (
                    visibleAlerts.map((alert) => (
                      <motion.div
                        key={alert.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, x: -50 }}
                        className={`border border-white/5 relative p-10 group mb-2 hover:bg-white/[0.02] transition-colors ${blockedHosts.has(alert.dst_domain || alert.dst) ? 'opacity-40' : ''}`}
                      >
                        <div className={`absolute left-0 top-0 bottom-0 w-1 ${alert.severity === 'critical' ? 'bg-red-500' : 'bg-yellow-500'}`} />
                        <div className="flex justify-between items-start">
                          <div className="space-y-4">
                            <div className="flex items-center gap-4">
                              <div className="text-xs font-mono opacity-30">{alert.time}</div>
                              <div className={`inline-block px-3 py-1 border ${alert.severity === 'critical' ? 'border-red-500/30 text-red-500' : alert.seriousness === 'LOW' ? 'border-green-500/30 text-green-500' : 'border-yellow-500/30 text-yellow-500'} text-[10px] font-mono uppercase tracking-[0.2em]`}>
                                {alert.seriousness === 'LOW' ? 'INFO / FINE' : alert.seriousness}
                              </div>
                              {alert.protocol && <div className="text-[10px] font-mono opacity-30 uppercase">{alert.protocol}</div>}
                              {blockedHosts.has(alert.dst_domain || alert.dst) && (
                                <div className="text-[10px] font-mono text-red-500 uppercase flex items-center gap-1"><Ban size={10} /> Blocked</div>
                              )}
                            </div>
                            <h3 className="text-2xl font-bold">{alert.type} exposed by {alert.app || 'Unknown'}</h3>
                            <div className="text-xs font-mono opacity-40 uppercase tracking-widest">
                              Target — {alert.dst_domain || alert.dst}
                            </div>
                             <div className="bg-white/[0.03] border border-white/5 p-6 font-mono text-sm opacity-80 max-w-3xl whitespace-pre-wrap leading-relaxed">
                              {alert.content}
                            </div>

                            {/* Expanded details */}
                            {expandedAlert === alert.id && (
                              <motion.div
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                className="space-y-2 text-xs font-mono opacity-40 border-t border-white/5 pt-4 mt-2"
                              >
                                <div>Source: {alert.src}</div>
                                <div>Destination: {alert.dst}</div>
                                <div>Domain: {alert.dst_domain || 'N/A'}</div>
                                <div>Protocol: {alert.protocol || 'N/A'}</div>
                                <div>Category: {alert.category || 'N/A'}</div>
                                <div>Severity: {alert.severity || 'N/A'}</div>
                              </motion.div>
                            )}
                          </div>
                          <div className="flex flex-col gap-3 flex-shrink-0">
                            {!blockedHosts.has(alert.dst_domain || alert.dst) && (
                              <button onClick={() => blockHost(alert.dst_domain || alert.dst)} className="text-xs font-mono border border-red-500/30 text-red-500 px-6 py-3 hover:bg-red-500/5 transition-all uppercase tracking-widest flex items-center gap-2">
                                <Ban size={12} /> Block Host
                              </button>
                            )}
                            <button onClick={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)} className="text-xs font-mono border border-white/10 px-6 py-3 hover:bg-white/5 opacity-40 hover:opacity-100 transition-all uppercase tracking-widest flex items-center gap-2">
                              {expandedAlert === alert.id ? <><ChevronUp size={12} /> Collapse</> : <><ChevronDown size={12} /> Details</>}
                            </button>
                            <button onClick={() => dismissAlert(alert.id)} className="text-xs font-mono border border-white/10 px-6 py-3 hover:bg-white/5 opacity-40 hover:opacity-100 transition-all uppercase tracking-widest flex items-center gap-2">
                              <X size={12} /> Dismiss
                            </button>
                          </div>
                        </div>
                      </motion.div>
                    ))
                  ) : (
                    <div className="border border-white/5 p-16 text-center">
                      <CheckCircle size={48} className="mx-auto mb-6 opacity-20" />
                      <div className="text-xl font-bold opacity-40 mb-2">No Active Threats</div>
                      <div className="text-xs font-mono opacity-20 uppercase tracking-widest">
                        {isSniffing ? 'Monitoring traffic in real-time...' : 'Start capture to begin monitoring'}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'web-audit' && (
                <div className="space-y-8">
                   <div className="bg-blue-500/10 border border-blue-500/20 p-8 flex items-center justify-between">
                    <div className="flex items-center gap-6">
                      <div className="w-12 h-12 bg-blue-500/20 text-blue-500 flex items-center justify-center">
                        <Activity size={24} />
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-blue-500 flex items-center gap-3">
                          Real-time Web Access Monitoring
                        </div>
                        <div className="meta opacity-40 mt-1 uppercase tracking-widest">
                          Sensing active browser sessions on macOS
                        </div>
                      </div>
                    </div>
                  </div>

                  {visibleAlerts.length > 0 ? (
                    visibleAlerts.map((alert) => (
                      <motion.div
                        key={alert.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="border border-white/5 relative p-10 group mb-2 hover:bg-white/[0.02] transition-colors"
                      >
                        <div className="absolute left-0 top-0 bottom-0 w-1 bg-blue-500" />
                        <div className="flex justify-between items-start">
                          <div className="space-y-4">
                            <div className="flex items-center gap-4">
                              <div className="text-xs font-mono opacity-30">{alert.time}</div>
                              <div className="inline-block px-3 py-1 border border-blue-500/30 text-blue-500 text-[10px] font-mono uppercase tracking-[0.2em]">
                                {alert.type}
                              </div>
                              <div className="text-[10px] font-mono opacity-30 uppercase">{alert.protocol}</div>
                            </div>
                            <h3 className="text-2xl font-bold">{alert.app} Visit to {alert.dst_domain || alert.dst}</h3>
                            <div className="bg-white/[0.03] border border-white/5 p-6 font-mono text-sm opacity-80 max-w-3xl whitespace-pre-wrap leading-relaxed">
                              {alert.content}
                            </div>
                          </div>
                          <button onClick={() => dismissAlert(alert.id)} className="text-xs font-mono border border-white/10 px-6 py-3 hover:bg-white/5 opacity-40 hover:opacity-100 transition-all uppercase tracking-widest flex items-center gap-2">
                            <Trash2 size={12} /> Clear Log
                          </button>
                        </div>
                      </motion.div>
                    ))
                  ) : (
                    <div className="border border-white/5 p-16 text-center">
                      <Search size={48} className="mx-auto mb-6 opacity-20" />
                      <div className="text-xl font-bold opacity-40 mb-2">No Web Activity Sensed</div>
                      <div className="text-xs font-mono opacity-20 uppercase tracking-widest">
                        Start browsing to see real-time security audits
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'prefs' && (
                <div className="grid grid-cols-12 gap-16">
                  <div className="col-span-8 space-y-16">
                    <div className="flex items-center gap-6 mb-12">
                      <div className="w-14 h-14 bg-white/5 border border-white/10 flex items-center justify-center">
                        <Settings size={28} className="opacity-40" />
                      </div>
                      <h3 className="text-3xl font-bold">System Configuration</h3>
                    </div>

                    <div className="space-y-12">
                      <ToggleItem
                        title="TLS Inspector"
                        desc="Extract domains from encrypted HTTPS traffic"
                        enabled={settings.tlsInspector}
                        onToggle={() => toggleSetting('tlsInspector')}
                      />
                      <ToggleItem
                        title="Heuristic Engine"
                        desc="Behavioural anomaly detection"
                        enabled={settings.heuristicEngine}
                        onToggle={() => toggleSetting('heuristicEngine')}
                      />
                      <ToggleItem
                        title="Auto-block Threats"
                        desc="Automatically block flagged hosts"
                        enabled={settings.autoBlock}
                        onToggle={() => toggleSetting('autoBlock')}
                      />
                      <ToggleItem
                        title="Privacy Shield Alerts"
                        desc="Notify on sensitive data exposure"
                        enabled={settings.privacyAlerts}
                        onToggle={() => toggleSetting('privacyAlerts')}
                      />
                    </div>

                    <div className="pt-8 border-t border-white/5">
                      <button onClick={clearAllData} className="flex items-center gap-3 text-xs font-mono border border-red-500/20 text-red-500 px-6 py-3 hover:bg-red-500/5 transition-all uppercase tracking-widest">
                        <Trash2 size={14} /> Clear All Captured Data
                      </button>
                    </div>
                  </div>

                  <div className="col-span-4 border-l border-white/5 pl-16 space-y-10">
                    <div className="meta opacity-40 uppercase tracking-[0.2em]">Live System Stats</div>
                    <div className="space-y-6">
                      <StatRow label="PKT Captured" value={stats.packet_count || 0} />
                      <StatRow label="Alerts" value={stats.alert_count || 0} />
                      <StatRow label="Domains" value={stats.unique_domains || 0} />
                      <StatRow label="Connections" value={stats.unique_connections || 0} />
                      <StatRow label="Bandwidth" value={formatBytes(stats.total_bytes)} />
                      <StatRow label="Interface" value="EN0" />
                      <StatRow label="Uptime" value={stats.uptime || 'Standby'} />
                    </div>
                  </div>
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </div>

        <footer className="h-12 border-t border-white/5 flex items-center px-10 bg-black z-20">
          <div className="ticker-footer uppercase tracking-[0.1em] text-[10px]">
            <span className="opacity-100">Uplink</span>
            <span className="opacity-40">EN0</span>
            <span className="dotdiv" />
            <span className="opacity-100">Engine</span>
            <span className="opacity-40">{isSniffing ? 'Active' : 'Standby'}</span>
            <span className="dotdiv" />
            <span className="opacity-100">Packets</span>
            <span className="opacity-40">{stats.packet_count || 0}</span>
            <span className="dotdiv" />
            <span className="opacity-100">Bandwidth</span>
            <span className="opacity-40">{formatBytes(stats.total_bytes)}</span>
            <span className="dotdiv" />
            <span className="opacity-100">Connections</span>
            <span className="opacity-40">{stats.unique_connections || 0}</span>
            <span className="dotdiv" />
            <span className="opacity-100">Alerts</span>
            <span className="opacity-40">{stats.alert_count || 0}</span>
            <span className="dotdiv" />
            <span className="opacity-100">Uptime</span>
            <span className="opacity-40">{stats.uptime || '—'}</span>
          </div>
        </footer>
      </main>
    </div>
  );
};

const NavItem = ({ active, onClick, icon, label, index }) => (
  <button
    onClick={onClick}
    className={`nav-item w-full flex items-center justify-between p-4 transition-all ${active ? 'active' : ''}`}
  >
    <div className="flex items-center gap-4">
      <span className={active ? 'opacity-100' : 'opacity-40'}>{icon}</span>
      <span className="font-bold tracking-tight text-sm uppercase">{label}</span>
    </div>
    <span className="text-[10px] font-mono opacity-20">{index}</span>
  </button>
);

const ToggleItem = ({ title, desc, enabled, onToggle }) => (
  <div className="flex items-center justify-between group cursor-pointer" onClick={onToggle}>
    <div className="space-y-2">
      <div className="text-xl font-bold group-hover:text-white transition-colors">{title}</div>
      <div className="text-xs font-mono opacity-30 uppercase tracking-[0.2em]">{desc}</div>
    </div>
    <label className="switch">
      <input type="checkbox" checked={enabled} onChange={onToggle} />
      <span className="slider" />
    </label>
  </div>
);

const StatRow = ({ label, value }) => (
  <div className="flex items-center justify-between font-mono text-xs uppercase tracking-[0.15em]">
    <span className="opacity-30">{label}</span>
    <span className="opacity-80">{value}</span>
  </div>
);

export default App;
