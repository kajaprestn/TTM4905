import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import "./App.css";

const API = "http://localhost:8000";

// --- Widget order ---
const DEFAULT_WIDGET_ORDER = ["vt", "verdict", "file", "obs", "device", "user", "argus", "kql"];

function getThreatType(family) {
  if (!family || family === "N/A") return null;
  return family.split(":")[0];
}

// --- Small reusable components ---

function DetectionDonut({ detectionRatio }) {
  if (!detectionRatio) return null;
  const match = detectionRatio.match(/(\d+)\/(\d+)/);
  if (!match) return null;
  const malicious = parseInt(match[1]);
  const total = parseInt(match[2]);
  if (total === 0) return null;
  const r = 36;
  const circumference = 2 * Math.PI * r;
  const dashLength = (malicious / total) * circumference;
  const gapLength = circumference - dashLength;
  const fraction = malicious / total;
  const color = fraction > 0.5 ? "#e05252" : fraction > 0.1 ? "#e8845c" : "#52c07a";
  return (
    <div className="detection-donut">
      <svg width="90" height="90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--color-border)" strokeWidth="10" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${dashLength} ${gapLength}`} strokeLinecap="round"
          transform="rotate(-90 50 50)" />
        <text x="50" y="46" textAnchor="middle" fill={color} fontSize="17" fontWeight="700" fontFamily="system-ui">{malicious}</text>
        <text x="50" y="62" textAnchor="middle" fill="var(--color-label)" fontSize="11" fontFamily="system-ui">/ {total}</text>
      </svg>
      <div className="detection-donut-label">
        <span className="detection-donut-title">Detection ratio</span>
        <span className="detection-donut-sub">{malicious} of {total} vendors flagged</span>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const lvl = (severity || "").toLowerCase();
  return <span className={`severity-badge severity-badge--${lvl}`}>{severity}</span>;
}

function RiskBadge({ level }) {
  const lvl = (level || "").toLowerCase();
  return <span className={`risk-badge risk-badge--${lvl}`}>{level}</span>;
}

function QuarantineStatus({ status }) {
  if (!status) return null;
  const lower = status.toLowerCase();
  let variant = "pending";
  let icon = "⏳";
  if (lower.includes("successful") || lower.includes("blocked")) { variant = "ok"; icon = "✓"; }
  else if (lower.startsWith("failed") || lower.includes("failed")) { variant = "fail"; icon = "✕"; }
  return (
    <div className={`quarantine-status quarantine-status--${variant}`}>
      <span className="quarantine-heading">Quarantine</span>
      <span className="quarantine-icon">{icon}</span>
      <span className="quarantine-label">{status}</span>
    </div>
  );
}

const SUSPICIOUS_PATH_RULES = [
  { test: (seg, i) => i === 0 && /^[d-z]:$/i.test(seg),  reason: "Non-system drive: execution from secondary or removable drives is uncommon for legitimate software" },
  { test: (seg) => /\b(temp|tmp)\b/i.test(seg),          reason: "Temporary directory: commonly used to stage and execute malware without leaving traces in standard locations" },
  { test: (seg) => /appdata/i.test(seg),                 reason: "AppData: frequently targeted by malware for persistence and stealthy payload storage" },
  { test: (seg) => /\bcache\b/i.test(seg),               reason: "Cache directory: execution from here is unusual and may indicate stealth or injection techniques" },
  { test: (seg) => /\bdownloads?\b/i.test(seg),          reason: "Downloads folder: a common initial access vector for phishing-delivered payloads" },
  { test: (seg) => /\bpublic\b/i.test(seg),              reason: "Public directory: world-writable, commonly abused for lateral movement and payload drops" },
  { test: (seg) => /recycle/i.test(seg),                 reason: "Recycle Bin: executing from here is a strong indicator of malicious activity" },
  { test: (seg) => /programdata/i.test(seg),             reason: "ProgramData: abused by malware for persistence, often less monitored than Program Files" },
];

function SuspiciousPath({ path }) {
  if (!path) return <span style={{ color: "var(--color-label)" }}>—</span>;
  const parts = path.split(/[\\\/]/);

  const reasons = [];
  const segSus = parts.map((part, i) => {
    const matched = SUSPICIOUS_PATH_RULES.filter(r => r.test(part, i));
    matched.forEach(r => { if (!reasons.includes(r.reason)) reasons.push(r.reason); });
    return matched.length > 0;
  });

  return (
    <span className="filepath-wrap">
      <span>
        {parts.map((part, i) => (
          <span key={i}>
            {i > 0 && <span style={{ color: "var(--color-label)" }}>\</span>}
            <span className={segSus[i] ? "filepath-segment--sus" : ""}>{part}</span>
          </span>
        ))}
        {reasons.length > 0 && <span className="filepath-sus-tag">⚠</span>}
      </span>
      {reasons.length > 0 && (
        <ul className="filepath-sus-reasons">
          {reasons.map((r, i) => <li key={i}>{r}</li>)}
        </ul>
      )}
    </span>
  );
}

function SightingsTimeline({ firstSeen, lastSeen, firstGlobal, detected, effectiveDays }) {
  const parseDate = (s) => {
    if (!s || s === "N/A") return null;
    const ts = Date.parse(s.replace(" UTC", "Z").replace(" ", "T"));
    return isNaN(ts) ? null : ts;
  };

  const now = Date.now();
  const windowMs = (effectiveDays || 14) * 24 * 60 * 60 * 1000;
  const minTs = now - windowMs;
  const fmt = ts => new Date(ts).toISOString().slice(0, 10);
  const W = 380, PAD = 24;

  const points = [
    { ts: parseDate(firstGlobal), label: "First global",   color: "#888" },
    { ts: parseDate(firstSeen),   label: "First internal", color: "#e8845c" },
    { ts: parseDate(detected),    label: "Detection",      color: "#e05252" },
    { ts: parseDate(lastSeen),    label: "Last internal",  color: "#e8845c" },
  ]
    .filter(p => p.ts !== null && p.ts >= minTs && p.ts <= now)
    .map(p => ({ ...p, x: PAD + ((p.ts - minTs) / windowMs) * W, date: fmt(p.ts) }))
    .sort((a, b) => a.x - b.x);

  // Group by date — one dot and one legend row per unique date
  const COLOR_PRIORITY = { "#e05252": 3, "#e8845c": 2, "#888": 1 };
  const groupMap = {};
  points.forEach(p => {
    if (!groupMap[p.date]) {
      groupMap[p.date] = { ...p, labels: [p.label] };
    } else {
      groupMap[p.date].labels.push(p.label);
      if ((COLOR_PRIORITY[p.color] || 0) > (COLOR_PRIORITY[groupMap[p.date].color] || 0)) {
        groupMap[p.date].color = p.color;
      }
    }
  });
  const groups = Object.values(groupMap).sort((a, b) => a.x - b.x);

  return (
    <div className="timeline-wrap">
      {points.length === 0
        ? <p className="status-text" style={{ fontSize: "0.8rem" }}>No events in the selected {effectiveDays}-day window</p>
        : (
          <>
            <svg viewBox={`0 0 ${W + PAD * 2} 46`} width="100%">
              {/* Track */}
              <line x1={PAD} y1={20} x2={W + PAD} y2={20} stroke="var(--color-border)" strokeWidth="2" />
              {/* End caps */}
              <line x1={PAD}     y1={14} x2={PAD}     y2={26} stroke="var(--color-border)" strokeWidth="1.5" strokeLinecap="round" />
              <line x1={W + PAD} y1={14} x2={W + PAD} y2={26} stroke="#555"               strokeWidth="1.5" strokeLinecap="round" />
              {/* Axis labels */}
              <text x={PAD}     y={38} textAnchor="start" fontSize="8" fill="var(--color-label)" fontFamily="system-ui">{fmt(minTs)}</text>
              <text x={W + PAD} y={38} textAnchor="end"   fontSize="8" fill="#666"               fontFamily="system-ui">Today · {fmt(now)}</text>
              {/* Dots — one per unique date */}
              {groups.map((g, i) => (
                <circle key={i} cx={g.x} cy={20} r={6} fill={g.color} />
              ))}
            </svg>
            <div className="timeline-legend">
              {groups.map((g, i) => (
                <div key={i} className="timeline-legend-item">
                  <span className="timeline-legend-dot" style={{ background: g.color }} />
                  <span className="timeline-legend-label">{g.labels.join(' · ')}</span>
                  <span className="timeline-legend-date">{g.date}</span>
                </div>
              ))}
            </div>
          </>
        )
      }
    </div>
  );
}

function Widget({ title, children, className = "", checked, onToggle, dragHandlers, isDragOver }) {
  return (
    <div
      className={`widget ${className}${isDragOver ? " widget--drag-over" : ""}`}
      onDragOver={dragHandlers?.onDragOver}
      onDrop={dragHandlers?.onDrop}
    >
      <div
        className="widget-header"
        draggable={!!dragHandlers}
        onDragStart={dragHandlers?.onDragStart}
        onDragEnd={dragHandlers?.onDragEnd}
      >
        <div className="widget-header-left">
          {dragHandlers && <span className="widget-drag-handle">⠿</span>}
          <span className="widget-title">{title}</span>
        </div>
        {onToggle && (
          <button
            className={`widget-report-btn ${checked ? "included" : ""}`}
            onClick={e => { e.stopPropagation(); onToggle(); }}
          >{checked ? "✓ In report" : "+ Include in report"}</button>
        )}
      </div>
      <div className="widget-body">{children}</div>
    </div>
  );
}

function StatRow({ label, value }) {
  return (
    <div className="stat-row">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

function BoolValue({ value, positive = false }) {
  const bad = positive ? !value : value;
  return <span className={bad ? "bool-yes" : "bool-no"}>{value ? "Yes" : "No"}</span>;
}

// --- KQL Queries widget content ---
function KQLQueriesContent({ deviceName }) {
  const { data: presets = [], isLoading, error } = useQuery({
    queryKey: ["kql-queries", deviceName],
    queryFn: async () => {
      const res = await fetch(`${API}/api/kql-queries/device/${encodeURIComponent(deviceName)}`);
      if (!res.ok) throw new Error("No KQL queries found");
      return res.json();
    },
    enabled: !!deviceName,
  });
  const [selectedPreset, setSelectedPreset] = useState(null);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);

  if (!deviceName) return <p className="status-text">No device name available.</p>;
  if (isLoading) return <p className="status-text">Loading KQL queries...</p>;
  if (error) return <p className="status-text">{error.message}</p>;

  function selectPreset(preset) { setSelectedPreset(preset); setQuery(preset.kqlStatement); setResult(null); }
  function runQuery() {
    const match = presets.find(p => p.kqlStatement === query);
    if (match) setResult({ resultCount: match.resultCount, columns: match.resultColumns, rows: match.resultRows });
    else setResult({ demo: true });
  }

  return (
    <div className="kql-container">
      {presets.length > 0 && (
        <div className="kql-presets">
          <span className="kql-presets-label">Predefined queries:</span>
          {presets.map((p, i) => (
            <button key={i} className={`kql-preset-btn ${selectedPreset === p ? "active" : ""}`} onClick={() => selectPreset(p)}>
              {p.queryName}
            </button>
          ))}
        </div>
      )}
      {selectedPreset && <p className="kql-description">{selectedPreset.queryDescription}</p>}
      <textarea className="kql-editor" rows={6} placeholder="Write a KQL query or select a predefined one above..."
        value={query} onChange={e => { setQuery(e.target.value); setResult(null); }} />
      <button className="kql-run-btn" onClick={runQuery} disabled={!query.trim()}>Run query</button>
      {result && (
        <div className="kql-results">
          {result.demo ? (
            <p className="kql-results-demo">Query execution not available in demo. Use a predefined query to see sample results.</p>
          ) : result.rows.length === 0 ? (
            <p className="kql-results-demo">Query returned 0 results.</p>
          ) : (
            <>
              <div className="kql-results-header">{result.resultCount} result{result.resultCount !== 1 ? "s" : ""}</div>
              <div className="kql-table-wrapper">
                <table className="kql-table">
                  <thead><tr>{result.columns.map(col => <th key={col}>{col}</th>)}</tr></thead>
                  <tbody>
                    {result.rows.map((row, i) => (
                      <tr key={i}>{row.map((cell, j) => <td key={j}>{cell}</td>)}</tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// --- Report modal ---
function ReportModal({ text, onClose }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <div className="report-modal-overlay" onClick={onClose}>
      <div className="report-modal" onClick={e => e.stopPropagation()}>
        <div className="report-modal-header">
          <span className="report-modal-title">Analysis Report</span>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button className="btn-copy-report" onClick={handleCopy}>
              {copied ? "✓ Copied" : "Copy text"}
            </button>
            <button className="report-modal-close" onClick={onClose}>✕</button>
          </div>
        </div>
        <pre className="report-modal-body">{text}</pre>
      </div>
    </div>
  );
}

// --- Main dashboard ---
function IncidentDashboard({ incident, sectionChecks, onToggleSection, onNavigateToIncident }) {
  const { id: incidentId, fileHash, deviceName, user } = incident;

  const [daysFilter, setDaysFilter] = useState(null);
  const [weeksFilter, setWeeksFilter] = useState(2);

  const [eventIdInput, setEventIdInput] = useState("");
  const [eventIdStatus, setEventIdStatus] = useState(null); // null | "loading" | "not-found"

  async function handleEventIdKeyDown(e) {
    if (e.key !== "Enter" || !eventIdInput.trim()) return;
    setEventIdStatus("loading");
    try {
      const res = await fetch(`${API}/api/incidents/${eventIdInput.trim()}`);
      if (res.ok) {
        const fetched = await res.json();
        onNavigateToIncident?.(fetched);
        setEventIdInput("");
        setEventIdStatus(null);
      } else {
        setEventIdStatus("not-found");
      }
    } catch {
      setEventIdStatus("not-found");
    }
  }
  // Effective window in days — days input overrides weeks when set; fall back to 14 if both empty
  const effectiveDays = daysFilter != null ? daysFilter : (weeksFilter != null ? weeksFilter * 7 : 14);

  const [reportOpen, setReportOpen] = useState(false);
  const [reportText, setReportText] = useState("");

  const [widgetOrder, setWidgetOrder] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem("widgetOrder") || "null");
      if (Array.isArray(saved) && saved.length === DEFAULT_WIDGET_ORDER.length && saved.every(k => DEFAULT_WIDGET_ORDER.includes(k)))
        return saved;
    } catch {}
    return [...DEFAULT_WIDGET_ORDER];
  });

  const dragItemIdx = useRef(null);
  const [dropTargetIdx, setDropTargetIdx] = useState(null);

  function wc(key) {
    return {
      checked: !!sectionChecks?.[`${incidentId}:${key}`],
      onToggle: () => onToggleSection?.(incidentId, key),
    };
  }

  function makeDragHandlers(idx) {
    return {
      onDragStart: (e) => {
        dragItemIdx.current = idx;
        e.dataTransfer.effectAllowed = "move";
      },
      onDragOver: (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        setDropTargetIdx(idx);
      },
      onDrop: (e) => {
        e.preventDefault();
        const from = dragItemIdx.current;
        if (from === null || from === idx) { setDropTargetIdx(null); return; }
        const newOrder = [...widgetOrder];
        const [item] = newOrder.splice(from, 1);
        newOrder.splice(idx, 0, item);
        setWidgetOrder(newOrder);
        localStorage.setItem("widgetOrder", JSON.stringify(newOrder));
        dragItemIdx.current = null;
        setDropTargetIdx(null);
      },
      onDragEnd: () => {
        dragItemIdx.current = null;
        setDropTargetIdx(null);
      },
    };
  }

  const { data: fi, isLoading: fiLoading } = useQuery({
    queryKey: ["file-intelligence", fileHash],
    queryFn: async () => {
      const res = await fetch(`${API}/api/file-intelligence/${fileHash}`);
      if (!res.ok) throw new Error("No file intelligence");
      return res.json();
    },
    enabled: !!fileHash,
  });

  const { data: dc, isLoading: dcLoading } = useQuery({
    queryKey: ["device-context", deviceName],
    queryFn: async () => {
      const res = await fetch(`${API}/api/device-context/${encodeURIComponent(deviceName)}`);
      if (!res.ok) throw new Error("No device context");
      return res.json();
    },
    enabled: !!deviceName,
  });

  const { data: uc, isLoading: ucLoading } = useQuery({
    queryKey: ["user-context", user],
    queryFn: async () => {
      const res = await fetch(`${API}/api/user-context/${encodeURIComponent(user)}`);
      if (!res.ok) throw new Error("No user context");
      return res.json();
    },
    enabled: !!user,
  });

  const { data: campaigns = [] } = useQuery({
    queryKey: ["campaign"],
    queryFn: async () => {
      const res = await fetch(`${API}/api/campaign-context`);
      if (!res.ok) return [];
      return res.json();
    },
  });

  const { data: vtInd } = useQuery({
    queryKey: ["vt-indicators", fileHash],
    queryFn: async () => {
      const res = await fetch(`${API}/api/vt-indicators/${fileHash}`);
      if (!res.ok) return { relatedIps: [], relatedHashes: [], executionParents: [] };
      return res.json();
    },
    enabled: !!fileHash,
  });

  const campaign = campaigns[0];
  const ipList = [...new Set([
    ...(vtInd?.relatedIps || []),
    ...(campaign?.relatedIps || []),
  ])].slice(0, 8);

  const { data: ipRepData } = useQuery({
    queryKey: ["ip-reputation", ipList.join(",")],
    queryFn: async () => {
      if (!ipList.length) return { results: {} };
      const resp = await fetch(
        `${API}/api/ip-reputation?ips=${encodeURIComponent(ipList.join(","))}`
      );
      return resp.json();
    },
    enabled: ipList.length > 0,
    staleTime: 1000 * 60 * 30,
  });
  const ipRep = ipRepData?.results ?? {};

  const threatFamily = fi?.microsoftReputation?.threatFamily || incident.microsoftSignature;
  const threatType = getThreatType(threatFamily);

  const vtHints = [
    fi?.virusTotal?.meaningfulName,
    ...(fi?.virusTotal?.popularThreatLabels ?? []),
  ].filter(Boolean);

  const { data: descData } = useQuery({
    queryKey: ["threat-description", threatFamily, vtHints.join(",")],
    queryFn: async () => {
      if (!threatFamily || threatFamily === "N/A") return null;
      const params = new URLSearchParams({ family: threatFamily });
      if (vtHints.length) params.set("hints", vtHints.join(","));
      const resp = await fetch(`${API}/api/threat-description?${params}`);
      return resp.json();
    },
    enabled: !!threatFamily && threatFamily !== "N/A",
    staleTime: Infinity,
  });
  const threatDesc = descData?.description ?? null;

  // --- IP reputation helpers ---
  function abuseColor(score) {
    if (score >= 75) return "#ff4444";
    if (score >= 25) return "#ffaa00";
    return "#aaa";
  }
  function getRiskLevel(rep) {
    if (!rep) return null;
    if (rep.abuseScore >= 75 || rep.isTor) return "high";
    if (rep.abuseScore >= 25 || rep.isProxy) return "medium";
    return "low";
  }
  function countryFlag(code) {
    if (!code || code.length !== 2) return "";
    return String.fromCodePoint(
      ...code.toUpperCase().split("").map(c => 0x1F1E0 - 65 + c.charCodeAt(0))
    );
  }

  // --- Widget content renderers ---
  function renderVT() {
    return fiLoading ? <p className="status-text">Loading...</p> : fi ? (
      <>
        <DetectionDonut detectionRatio={fi.virusTotal.detectionRatio} />
        <a className="vt-link" href={`https://www.virustotal.com/gui/file/${fileHash}`} target="_blank" rel="noreferrer">
          ↗ View on VirusTotal
        </a>
        <div style={{ marginTop: "1rem" }}>
          <StatRow label="First submission" value={fi.virusTotal.firstSubmission || "N/A"} />
          <StatRow label="Last analysis" value={fi.virusTotal.lastAnalysis || "N/A"} />
          <StatRow label="File type" value={fi.virusTotal.fileType || "N/A"} />
          <StatRow label="Reputation" value={fi.virusTotal.reputationScore || "N/A"} />
        </div>
        {fi.virusTotal.tags?.length > 0 && (
          <div className="vt-tags" style={{ marginTop: "0.75rem" }}>
            {fi.virusTotal.tags.map(t => <span key={t} className="vt-tag">{t}</span>)}
          </div>
        )}
      </>
    ) : (
      <>
        <p className="status-text" style={{ marginBottom: "1rem" }}>No VirusTotal data — configure VT_API_KEY to enable live lookups.</p>
        <a className="vt-link" href={`https://www.virustotal.com/gui/file/${fileHash}`} target="_blank" rel="noreferrer">
          ↗ Search hash on VirusTotal
        </a>
      </>
    );
  }

  function renderVerdict() {
    return (
      <div style={{ display: "flex", gap: "1.25rem", alignItems: "flex-start", flexWrap: "wrap" }}>
        <QuarantineStatus status={incident.quarantineStatus} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "0.6rem", flexWrap: "wrap" }}>
            {threatType && <div className="threat-type-chip">{threatType}</div>}
            <SeverityBadge severity={incident.severity} />
          </div>
          {fi?.virusTotal.meaningfulName
            ? <div className="threat-meaningful-name">{fi.virusTotal.meaningfulName}</div>
            : <div className="threat-meaningful-name" style={{ fontSize: "0.82rem" }}>{incident.microsoftSignature}</div>
          }
          {threatDesc && <p className="threat-description">{threatDesc}</p>}
          {fi?.virusTotal.popularThreatLabels?.length > 0 && (
            <div className="vt-tags" style={{ marginBottom: "0.75rem" }}>
              {fi.virusTotal.popularThreatLabels.map(l => <span key={l} className="vt-tag">{l}</span>)}
            </div>
          )}
          <StatRow label="Status" value={incident.status} />
          <StatRow label="Log source" value={incident.logSource} />
          <StatRow label="Detected" value={incident.detectionTimestamp} />
          <StatRow label="ID" value={incident.id} />
        </div>
      </div>
    );
  }

  function renderFile() {
    return (
      <>
        <StatRow label="File name" value={incident.fileName} />
        <div className="stat-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "0.3rem" }}>
          <span className="stat-label">File path</span>
          <SuspiciousPath path={incident.filePath} />
        </div>
        <div className="stat-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "0.3rem" }}>
          <span className="stat-label">Command line</span>
          <span className="stat-value" style={{ fontFamily: "monospace", fontSize: "0.78rem", textAlign: "left" }}>{incident.commandLine || "—"}</span>
        </div>
        <div className="stat-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "0.3rem" }}>
          <span className="stat-label">File hash (SHA-256)</span>
          <span className="stat-value" style={{ fontFamily: "monospace", fontSize: "0.7rem", wordBreak: "break-all" }}>{incident.fileHash}</span>
        </div>
        <StatRow label="MS signature" value={incident.microsoftSignature} />
        {fi && (
          <>
            <StatRow label="First seen internally" value={fi.internalSightings.firstSeenInternally} />
            <StatRow label="Last seen internally" value={fi.internalSightings.lastSeenInternally} />
          </>
        )}
        <StatRow label="Source IP" value={incident.sourceIp} />
        <StatRow label="Destination IP" value={incident.destinationIp} />
      </>
    );
  }

  function renderObs() {
    return fi ? (
      <>
        <div className="observations-counts">
          <div className="obs-count-item">
            <span className="obs-count-number">{fi.internalSightings.totalInternalDetections}</span>
            <span className="obs-count-label">Internal detections</span>
          </div>
          <div className="obs-count-item">
            <span className="obs-count-number">{fi.internalSightings.numberOfAffectedDevices}</span>
            <span className="obs-count-label">Affected devices</span>
          </div>
          <div className="obs-count-item">
            <span className="obs-count-number">{fi.crossCustomerObservations.numberOfCustomerEnvironments}</span>
            <span className="obs-count-label">Customer envs</span>
          </div>
        </div>
        <StatRow label="Seen before" value={fi.internalSightings.seenBefore} />
        <StatRow label="Spike detected (24h)" value={fi.crossCustomerObservations.spikeDetectedInLast24Hours} />
        <StatRow label="Campaign likelihood" value={fi.crossCustomerObservations.campaignLikelihood} />
        <SightingsTimeline
          firstSeen={fi.internalSightings.firstSeenInternally}
          lastSeen={fi.internalSightings.lastSeenInternally}
          firstGlobal={fi.crossCustomerObservations.firstObservedAcrossCustomers}
          detected={incident.detectionTimestamp}
          effectiveDays={effectiveDays}
        />
      </>
    ) : <p className="status-text">Loading observations...</p>;
  }

  function renderDevice() {
    return dcLoading ? <p className="status-text">Loading...</p> : dc ? (
      <>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
          <span style={{ fontSize: "0.95rem", fontWeight: 600, color: "var(--color-title)" }}>{dc.deviceName}</span>
          <RiskBadge level={dc.riskLevel} />
        </div>
        <StatRow label="Type" value={`${dc.deviceType} · ${dc.osPlatform}`} />
        <StatRow label="OS" value={dc.osVersion} />
        <StatRow label="Exposure" value={dc.exposureLevel} />
        <StatRow label="Last logged on user" value={dc.lastLoggedOnUser} />
        <StatRow label="Failed logons (24h)" value={String(dc.failedLogonsLast24h)} />
        <StatRow label="Suspicious processes (24h)" value={String(dc.suspiciousProcessesLast24h)} />
        <div className="stat-row">
          <span className="stat-label">Beaconing detected</span>
          <BoolValue value={dc.beaconingDetected} />
        </div>
        <div className="stat-row">
          <span className="stat-label">Credential dumping</span>
          <BoolValue value={dc.credentialDumpingDetected} />
        </div>
        <StatRow label="Last seen" value={dc.lastSeen} />
      </>
    ) : <p className="status-text">No device context found</p>;
  }

  function renderUser() {
    return ucLoading ? <p className="status-text">Loading...</p> : uc ? (
      <>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
          <span style={{ fontSize: "0.95rem", fontWeight: 600, color: "var(--color-title)" }}>{uc.displayName}</span>
          <RiskBadge level={uc.riskLevel} />
        </div>
        <StatRow label="UPN" value={uc.userPrincipalName} />
        <StatRow label="Sign-in risk" value={uc.signInRiskLevel} />
        <StatRow label="Failed logins (24h)" value={String(uc.failedLoginsLast24h)} />
        <div className="stat-row">
          <span className="stat-label">MFA enabled</span>
          <BoolValue value={uc.mfaEnabled} positive />
        </div>
        <div className="stat-row">
          <span className="stat-label">Account enabled</span>
          <BoolValue value={uc.accountEnabled} positive />
        </div>
        <div className="stat-row">
          <span className="stat-label">Impossible travel</span>
          <BoolValue value={uc.impossibleTravelDetected} />
        </div>
        <StatRow label="Last sign-in" value={uc.lastSignIn} />
        {uc.privilegedRoles?.length > 0 && (
          <div className="stat-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "0.35rem" }}>
            <span className="stat-label">Privileged roles</span>
            <div className="vt-tags">
              {uc.privilegedRoles.map(r => <span key={r} className="vt-tag">{r}</span>)}
            </div>
          </div>
        )}
      </>
    ) : <p className="status-text">No user context found</p>;
  }

  function renderArgus() {
    return campaign ? (
      <>
        <div className="argus-grid">
          <div className="argus-cell">
            <span className="argus-cell-label">Customer environments</span>
            <span className="argus-cell-value">{campaign.numberOfCustomerEnvironments}</span>
            <span className="argus-cell-sub">globally affected</span>
          </div>
          <div className="argus-cell">
            <span className="argus-cell-label">Campaign likelihood</span>
            <span className="argus-cell-value">{campaign.campaignLikelihood}</span>
            <span className="argus-cell-sub">{campaign.spikeDetectedLast24h ? "⚠ Spike in last 24h" : "No spike detected"}</span>
          </div>
          <div className="argus-cell">
            <span className="argus-cell-label">Affected devices</span>
            <span className="argus-cell-value">{campaign.numberOfAffectedDevices}</span>
            <span className="argus-cell-sub">{campaign.numberOfAffectedUsers} users</span>
          </div>
          <div className="argus-cell">
            <span className="argus-cell-label">First observed</span>
            <span className="argus-cell-value" style={{ fontSize: "1rem" }}>{campaign.firstObserved?.slice(0, 10)}</span>
            <span className="argus-cell-sub">Last: {campaign.lastObserved?.slice(0, 10)}</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: "2.5rem", flexWrap: "wrap" }}>
          {vtInd?.relatedHashes?.length > 0 && (
            <div style={{ width: "100%" }}>
              <div className="argus-cell-label" style={{ marginBottom: "0.4rem" }}>Related hashes (VT)</div>
              <table className="argus-hash-table">
                <thead>
                  <tr>
                    <th>Scanned</th>
                    <th>Detections</th>
                    <th>File type</th>
                    <th>Name</th>
                  </tr>
                </thead>
                <tbody>
                  {vtInd.relatedHashes.slice(0, 10).map(h => {
                    const hash = h.hash ?? h;
                    const detections = h.detections ?? null;
                    const total = h.totalEngines ?? null;
                    const detColor = detections > 0 ? "#e05c5c" : detections === 0 ? "#4caf50" : "inherit";
                    return (
                      <tr key={hash}>
                        <td>{h.lastAnalysis ?? "—"}</td>
                        <td style={{ color: detColor }}>
                          {detections !== null ? `${detections} / ${total}` : "—"}
                        </td>
                        <td>{h.fileType ?? "—"}</td>
                        <td>
                          <a className="argus-hash-link" href={`https://www.virustotal.com/gui/file/${hash}`} target="_blank" rel="noreferrer">
                            {h.name ?? `${hash.slice(0, 16)}…`}
                          </a>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {vtInd?.executionParents?.length > 0 && (
            <div style={{ width: "100%" }}>
              <div className="argus-cell-label" style={{ marginBottom: "0.4rem" }}>Execution parents (VT)</div>
              <table className="argus-hash-table">
                <thead>
                  <tr>
                    <th>Scanned</th>
                    <th>Detections</th>
                    <th>File type</th>
                    <th>Name</th>
                  </tr>
                </thead>
                <tbody>
                  {vtInd.executionParents.map(p => {
                    const detColor = p.detections > 0 ? "#e05c5c" : p.detections === 0 ? "#4caf50" : "inherit";
                    return (
                      <tr key={p.hash}>
                        <td>{p.lastAnalysis ?? "—"}</td>
                        <td style={{ color: detColor }}>{p.totalEngines ? `${p.detections} / ${p.totalEngines}` : "—"}</td>
                        <td>{p.fileType ?? "—"}</td>
                        <td>
                          <a className="argus-hash-link" href={`https://www.virustotal.com/gui/file/${p.hash}`} target="_blank" rel="noreferrer">
                            {p.name}
                          </a>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {ipList.length > 0 && (
            <div>
              <div className="argus-cell-label" style={{ marginBottom: "0.4rem" }}>Related IPs</div>
              <div className="argus-ips">
                {ipList.map(ip => {
                  const rep = ipRep[ip];
                  return (
                    <div key={ip} className="ip-tooltip-wrapper">
                      <span className="argus-hash ip-chip" data-risk={getRiskLevel(rep)}>{ip}</span>
                      {rep && (
                        <div className="ip-tooltip">
                          {rep.country && (
                            <div className="ipt-row">{countryFlag(rep.countryCode)} {rep.country}</div>
                          )}
                          {rep.abuseScore != null && (
                            <div className="ipt-row">
                              Abuse: <span style={{ color: abuseColor(rep.abuseScore) }}>{rep.abuseScore}%</span>
                              {rep.totalReports > 0 && ` (${rep.totalReports} reports)`}
                            </div>
                          )}
                          {rep.isp && <div className="ipt-row ipt-muted">{rep.isp}</div>}
                          {rep.usageType && <div className="ipt-row ipt-muted">{rep.usageType}</div>}
                          <div className="ipt-tags">
                            {rep.isTor     && <span className="ipt-tag tor">TOR</span>}
                            {rep.isProxy   && <span className="ipt-tag proxy">PROXY</span>}
                            {rep.isHosting && <span className="ipt-tag hosting">HOSTING</span>}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </>
    ) : <p className="status-text">Loading cross-customer data...</p>;
  }

  function renderKQL() {
    return <KQLQueriesContent deviceName={deviceName} />;
  }

  const widgetDefs = {
    vt:      { title: "VirusTotal Detection",                    full: false, wcKey: "VT Score",         render: renderVT },
    verdict: { title: "Threat Classification & Verdict",         full: false, wcKey: "Verdict",          render: renderVerdict },
    file:    { title: "File & Execution",                        full: false, wcKey: "File & Execution", render: renderFile },
    obs:     { title: "Observations & Timeline",                 full: false, wcKey: "Observations",     render: renderObs },
    device:  { title: "Device Context",                          full: false, wcKey: "Device",           render: renderDevice },
    user:    { title: "User Context",                            full: false, wcKey: "User",             render: renderUser },
    argus:   { title: "Argus / Cross-Customer Intelligence",     full: true,  wcKey: "Argus",            render: renderArgus },
    kql:     { title: "KQL Threat Hunting",                      full: true,  wcKey: null,               render: renderKQL },
  };

  const summaryFields = [
    { label: "Detection timestamp", value: incident.detectionTimestamp },
    { label: "Severity",            value: incident.severity },
    { label: "Device name",         value: incident.deviceName },
    { label: "User",                value: incident.user },
    { label: "File name",           value: <span style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{incident.fileName || "—"}</span> },
    { label: "Path",                value: <span style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{incident.filePath || "—"}</span> },
    { label: "Command line",        value: <span style={{ fontFamily: "monospace", fontSize: "0.82rem", textAlign: "left" }}>{incident.commandLine || "—"}</span> },
    { label: "File hash",           value: <span style={{ fontFamily: "monospace", fontSize: "0.75rem", wordBreak: "break-all" }}>{incident.fileHash}</span> },
    { label: "Microsoft signature", value: incident.microsoftSignature },
    { label: "Quarantine status",   value: incident.quarantineStatus },
  ];

  function buildReportText() {
    const now = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
    const lines = [];
    const sep = "─".repeat(52);

    lines.push("INCIDENT ANALYSIS REPORT");
    lines.push("=".repeat(52));
    lines.push(`Incident : ${incident.title}`);
    lines.push(`ID       : ${incident.id}`);
    lines.push(`Generated: ${now}`);
    lines.push("");

    const includedKeys = widgetOrder.filter(key => {
      const def = widgetDefs[key];
      return def?.wcKey && sectionChecks?.[`${incidentId}:${def.wcKey}`];
    });

    if (includedKeys.length === 0) {
      lines.push("No sections included. Click '+ Include in report' on widgets to add them.");
      return lines.join("\n");
    }

    for (const key of includedKeys) {
      lines.push(sep);
      lines.push(widgetDefs[key].title.toUpperCase());
      lines.push(sep);

      switch (key) {
        case "vt":
          if (fi) {
            lines.push(`Detection ratio  : ${fi.virusTotal.detectionRatio}`);
            lines.push(`File type        : ${fi.virusTotal.fileType || "N/A"}`);
            lines.push(`First submission : ${fi.virusTotal.firstSubmission || "N/A"}`);
            lines.push(`Last analysis    : ${fi.virusTotal.lastAnalysis || "N/A"}`);
            lines.push(`Reputation       : ${fi.virusTotal.reputationScore || "N/A"}`);
            if (fi.virusTotal.tags?.length > 0)
              lines.push(`Tags             : ${fi.virusTotal.tags.join(", ")}`);
          } else {
            lines.push("No VirusTotal data available.");
          }
          break;

        case "verdict":
          lines.push(`Quarantine status: ${incident.quarantineStatus}`);
          lines.push(`Threat type      : ${threatType || "Unknown"}`);
          lines.push(`Severity         : ${incident.severity}`);
          lines.push(`Signature        : ${fi?.virusTotal.meaningfulName || incident.microsoftSignature}`);
          lines.push(`Status           : ${incident.status}`);
          lines.push(`Log source       : ${incident.logSource}`);
          lines.push(`Detected         : ${incident.detectionTimestamp}`);
          if (threatDesc) { lines.push(""); lines.push(threatDesc); }
          if (fi?.virusTotal.popularThreatLabels?.length > 0)
            lines.push(`Threat labels    : ${fi.virusTotal.popularThreatLabels.join(", ")}`);
          break;

        case "file":
          lines.push(`File name        : ${incident.fileName}`);
          lines.push(`File path        : ${incident.filePath}`);
          lines.push(`Command line     : ${incident.commandLine || "—"}`);
          lines.push(`SHA-256          : ${incident.fileHash}`);
          lines.push(`MS signature     : ${incident.microsoftSignature}`);
          if (fi) {
            lines.push(`First seen (int) : ${fi.internalSightings.firstSeenInternally}`);
            lines.push(`Last seen (int)  : ${fi.internalSightings.lastSeenInternally}`);
          }
          lines.push(`Source IP        : ${incident.sourceIp}`);
          lines.push(`Destination IP   : ${incident.destinationIp}`);
          break;

        case "obs":
          if (fi) {
            lines.push(`Internal detections   : ${fi.internalSightings.totalInternalDetections}`);
            lines.push(`Affected devices      : ${fi.internalSightings.numberOfAffectedDevices}`);
            lines.push(`Customer environments : ${fi.crossCustomerObservations.numberOfCustomerEnvironments}`);
            lines.push(`Seen before           : ${fi.internalSightings.seenBefore}`);
            lines.push(`Spike detected (24h)  : ${fi.crossCustomerObservations.spikeDetectedInLast24Hours}`);
            lines.push(`Campaign likelihood   : ${fi.crossCustomerObservations.campaignLikelihood}`);
            lines.push(`First seen internally : ${fi.internalSightings.firstSeenInternally}`);
            lines.push(`Last seen internally  : ${fi.internalSightings.lastSeenInternally}`);
            lines.push(`First seen globally   : ${fi.crossCustomerObservations.firstObservedAcrossCustomers}`);
          }
          break;

        case "device":
          if (dc) {
            lines.push(`Device               : ${dc.deviceName}`);
            lines.push(`Risk level           : ${dc.riskLevel}`);
            lines.push(`Type                 : ${dc.deviceType} · ${dc.osPlatform}`);
            lines.push(`OS                   : ${dc.osVersion}`);
            lines.push(`Exposure             : ${dc.exposureLevel}`);
            lines.push(`Last logged on user  : ${dc.lastLoggedOnUser}`);
            lines.push(`Failed logons (24h)  : ${dc.failedLogonsLast24h}`);
            lines.push(`Suspicious processes : ${dc.suspiciousProcessesLast24h}`);
            lines.push(`Beaconing detected   : ${dc.beaconingDetected ? "Yes" : "No"}`);
            lines.push(`Credential dumping   : ${dc.credentialDumpingDetected ? "Yes" : "No"}`);
            lines.push(`Last seen            : ${dc.lastSeen}`);
          }
          break;

        case "user":
          if (uc) {
            lines.push(`User             : ${uc.displayName} (${uc.userPrincipalName})`);
            lines.push(`Risk level       : ${uc.riskLevel}`);
            lines.push(`Sign-in risk     : ${uc.signInRiskLevel}`);
            lines.push(`Failed logins    : ${uc.failedLoginsLast24h}`);
            lines.push(`MFA enabled      : ${uc.mfaEnabled ? "Yes" : "No"}`);
            lines.push(`Account enabled  : ${uc.accountEnabled ? "Yes" : "No"}`);
            lines.push(`Impossible travel: ${uc.impossibleTravelDetected ? "Yes" : "No"}`);
            lines.push(`Last sign-in     : ${uc.lastSignIn}`);
            if (uc.privilegedRoles?.length > 0)
              lines.push(`Privileged roles : ${uc.privilegedRoles.join(", ")}`);
          }
          break;

        case "argus":
          if (campaign) {
            lines.push(`Customer environments: ${campaign.numberOfCustomerEnvironments}`);
            lines.push(`Campaign likelihood  : ${campaign.campaignLikelihood}`);
            lines.push(`Affected devices     : ${campaign.numberOfAffectedDevices}`);
            lines.push(`Affected users       : ${campaign.numberOfAffectedUsers}`);
            lines.push(`First observed       : ${campaign.firstObserved?.slice(0, 10)}`);
            lines.push(`Last observed        : ${campaign.lastObserved?.slice(0, 10)}`);
            lines.push(`Spike (24h)          : ${campaign.spikeDetectedLast24h ? "Yes" : "No"}`);
            const ips = [...new Set([...(vtInd?.relatedIps || []), ...(campaign.relatedIps || [])])].slice(0, 8);
            if (ips.length > 0) lines.push(`Related IPs          : ${ips.join(", ")}`);
            if (vtInd?.relatedHashes?.length > 0)
              lines.push(`Related hashes       : ${vtInd.relatedHashes.slice(0, 6).map(h => h.hash ?? h).join(", ")}`);
          }
          break;

        default:
          break;
      }
      lines.push("");
    }

    return lines.join("\n");
  }

  return (
    <div className="incident-detail-wrap">
      <div className="incident-summary">
        <div className="incident-summary-top">
          <div>
            <h1 className="incident-title">{incident.title}</h1>
            <p className="incident-id">ID: {incident.id}</p>
          </div>
        </div>
        <div className="meta-table">
          {summaryFields.map(({ label, value }) => (
            <div key={label} className="meta-row">
              <span className="meta-label">{label}:</span>
              <span className="meta-value">{value}</span>
            </div>
          ))}
        </div>
      </div>
      <hr className="summary-divider" />
      <div className="dashboard-toolbar">
        <div className="event-id-wrap">
          <input
            className="event-id-input"
            type="text"
            placeholder={(incident.id)}
            value={eventIdInput}
            onChange={e => { setEventIdInput(e.target.value); setEventIdStatus(null); }}
            onKeyDown={handleEventIdKeyDown}
          />
          {eventIdStatus === "loading" && <span className="event-id-status">Loading…</span>}
          {eventIdStatus === "not-found" && <span className="event-id-status event-id-status--err">Not found</span>}
        </div>
        <label className="weeks-filter-btn">
          Data for the last
          <input
            className="weeks-num-input"
            type="number"
            min={1}
            max={365}
            value={daysFilter ?? ""}
            placeholder="—"
            onChange={e => {
              const v = parseInt(e.target.value);
              setDaysFilter(isNaN(v) ? null : Math.max(1, Math.min(365, v)));
              if (!isNaN(v)) setWeeksFilter(2);
            }}
            onClick={e => e.target.select()}
          />
          {daysFilter === 1 ? "day" : "days"}
        </label>
        <label className="weeks-filter-btn">
          Data for the last
          <input
            className="weeks-num-input"
            type="number"
            min={1}
            max={52}
            value={weeksFilter ?? ""}
            placeholder="—"
            onChange={e => {
              const v = parseInt(e.target.value);
              setWeeksFilter(isNaN(v) ? null : Math.max(1, Math.min(52, v)));
              if (!isNaN(v)) setDaysFilter(null);
            }}
            onClick={e => e.target.select()}
          />
          {weeksFilter === 1 ? "week" : "weeks"}
        </label>
        <button className="btn-generate-report" onClick={() => { setReportText(buildReportText()); setReportOpen(true); }}>Generate report</button>
      </div>
      <div className="dashboard-grid">
        {widgetOrder.map((key, idx) => {
          const def = widgetDefs[key];
          return (
            <Widget
              key={key}
              title={def.title}
              className={def.full ? "widget--full" : ""}
              {...(def.wcKey ? wc(def.wcKey) : {})}
              isDragOver={dropTargetIdx === idx}
              dragHandlers={makeDragHandlers(idx)}
            >
              {def.render()}
            </Widget>
          );
        })}
      </div>
      {reportOpen && <ReportModal text={reportText} onClose={() => setReportOpen(false)} />}
    </div>
  );
}

// --- Incident list view ---
function IncidentList({ incidents, onSelect, lightMode, onToggleTheme }) {
  return (
    <div className={`incident-page ${lightMode ? "light" : ""}`}>
      <nav className="top-bar">
        <div className="top-bar-left">
          <span className="top-bar-title">Security Incidents</span>
        </div>
        <div className="top-bar-right">
          <button className="btn-theme" onClick={onToggleTheme}>
            {lightMode ? "\u263D" : "\u2600"}
          </button>
        </div>
      </nav>
      <main className="incident-list">
        <div className="incident-list-row incident-list-header">
          <span className="incident-list-title">Incident</span>
          <span className="incident-list-meta">Log source</span>
          <span className="incident-list-meta">Source IP</span>
          <span className="incident-list-meta">Destination IP</span>
          <span></span>
        </div>
        {incidents.map((inc) => (
          <div className="incident-list-row" key={inc.id}>
            <span className="incident-list-title">{inc.title}</span>
            <span className="incident-list-meta">{inc.logSource}</span>
            <span className="incident-list-meta">{inc.sourceIp}</span>
            <span className="incident-list-meta">{inc.destinationIp}</span>
            <button className="btn-show-details" onClick={() => onSelect(inc.id)}>Show details</button>
          </div>
        ))}
      </main>
    </div>
  );
}

// --- App root ---
function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lightMode, setLightMode] = useState(false);
  const [sectionChecks, setSectionChecks] = useState(() => {
    try { return JSON.parse(localStorage.getItem("sectionChecks") || "{}"); }
    catch { return {}; }
  });

  function toggleSection(incidentId, title) {
    setSectionChecks((prev) => {
      const key = `${incidentId}:${title}`;
      const next = { ...prev, [key]: !prev[key] };
      localStorage.setItem("sectionChecks", JSON.stringify(next));
      return next;
    });
  }

  useEffect(() => {
    fetch(`${API}/api/incidents`)
      .then(res => res.json())
      .then(data => { setIncidents(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="incident-page"><p className="status-text" style={{ padding: "3rem" }}>Loading incidents...</p></div>;
  }
  if (incidents.length === 0) {
    return <div className="incident-page"><p className="status-text" style={{ padding: "3rem" }}>No incidents found. Is the backend running?</p></div>;
  }

  if (!selectedId) {
    return (
      <IncidentList
        incidents={incidents}
        onSelect={id => setSelectedId(id)}
        lightMode={lightMode}
        onToggleTheme={() => setLightMode(!lightMode)}
      />
    );
  }

  const data = incidents.find(inc => inc.id === selectedId);

  if (!data) return null;

  function handleNavigateToIncident(fetchedIncident) {
    setIncidents(prev =>
      prev.find(i => i.id === fetchedIncident.id) ? prev : [...prev, fetchedIncident]
    );
    setSelectedId(fetchedIncident.id);
  }

  return (
    <div className={`incident-page ${lightMode ? "light" : ""}`}>
      <nav className="top-bar">
        <div className="top-bar-left">
          <span className="top-bar-title">{data.title}</span>
        </div>
        <div className="top-bar-right">
          <span className="top-bar-meta">{data.logSource}</span>
          <span className="top-bar-meta">Source: {data.sourceIp}</span>
          <span className="top-bar-meta">Dest: {data.destinationIp}</span>
          <button className="btn-theme" onClick={() => setLightMode(!lightMode)}>
            {lightMode ? "\u263D" : "\u2600"}
          </button>
          <button className="btn-realtime" onClick={() => setSelectedId(null)}>All incidents</button>
        </div>
      </nav>
      <IncidentDashboard
        incident={data}
        sectionChecks={sectionChecks}
        onToggleSection={toggleSection}
        onNavigateToIncident={handleNavigateToIncident}
      />
    </div>
  );
}

export default App;
