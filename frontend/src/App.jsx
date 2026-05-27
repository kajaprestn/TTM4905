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
      <svg width="120" height="120" viewBox="0 0 100 100">
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

const EXT_DESCRIPTIONS = {
  exe:  "Windows Executable",
  dll:  "Dynamic Link Library",
  ps1:  "PowerShell Script",
  psm1: "PowerShell Module",
  bat:  "Windows Batch File",
  cmd:  "Windows Command Script",
  vbs:  "VBScript",
  js:   "JavaScript",
  wsf:  "Windows Script File",
  hta:  "HTML Application",
  msi:  "Windows Installer Package",
  msp:  "Windows Installer Patch",
  com:  "DOS/Windows Executable",
  scr:  "Windows Screensaver / Executable",
  pif:  "Program Information File",
  lnk:  "Windows Shortcut",
  iso:  "Disk Image",
  cab:  "Windows Cabinet Archive",
  jar:  "Java Archive",
  crx:  "Chrome Extension",
  zip:  "ZIP Archive",
  rar:  "RAR Archive",
  "7z": "7-Zip Archive",
  pdf:  "PDF Document",
  doc:  "Word Document",
  docx: "Word Document",
  xls:  "Excel Spreadsheet",
  xlsx: "Excel Spreadsheet",
  reg:  "Windows Registry File",
  sys:  "Windows System Driver",
  drv:  "Windows Device Driver",
  inf:  "Setup Information File",
  cpl:  "Windows Control Panel Item",
  docm: "Word Macro-Enabled Document",
  xlsm: "Excel Macro-Enabled Spreadsheet",
  pptm: "PowerPoint Macro-Enabled Presentation",
  vbe:  "VBScript Encoded Script",
  jse:  "JavaScript Encoded Script",
  cer:  "Security Certificate",
  pfx:  "Personal Information Exchange (Certificate)",
  crt:  "Certificate File",
  der:  "DER Encoded Certificate",
  p7b:  "PKCS#7 Certificate",
  ocx:  "ActiveX Control",
  html: "HTML Document",
  htm:  "HTML Document",
  json: "JSON Data File",
  xml:  "XML Document",
  yaml: "YAML Configuration File",
  yml:  "YAML Configuration File",
  ini:  "Configuration Settings",
  cfg:  "Configuration File",
  sh:   "Shell Script",
  py:   "Python Script",
  pl:   "Perl Script",
  rb:   "Ruby Script",
  tar:  "Tarball Archive",
  gz:   "Gzip Compressed Archive",
  img:  "Disk Image File",
  vhd:  "Virtual Hard Disk",
  vhdx: "Virtual Hard Disk (Extended)"
};

function FileExtHint({ fileName }) {
  if (!fileName || fileName === "N/A") return <span>{fileName || "—"}</span>;
  const ext = fileName.split(".").pop().toLowerCase();
  const desc = EXT_DESCRIPTIONS[ext];
  return (
    <span className="filename-with-hint">
      <span className="filename-text">{fileName}</span>
      {desc && <span className="filename-ext-hint" title={desc}>.{ext} — {desc}</span>}
    </span>
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

function QuarantineBadge({ status }) {
  const lower = (status || "").toLowerCase();
  let lvl;
  if (["quarantined", "blocked", "prevented"].includes(lower)) lvl = "ok";
  else if (lower === "detected") lvl = "detected";
  else if (["notremediated", "failed"].includes(lower)) lvl = "fail";
  else lvl = "unknown";
  return <span className={`quarantine-badge quarantine-badge--${lvl}`}>{status}</span>;
}

function QuarantineStatus({ status, hasFile }) {
  const lower = (status || "").toLowerCase();
  let variant, icon, label;
  if (!status || lower === "none" || lower === "notavailable") {
    if (!hasFile) return null;
    variant = "fail"; icon = "✕"; label = "Not contained";
  } else if (lower.includes("successful") || lower.includes("blocked") || lower === "quarantined") {
    variant = "ok"; icon = "✓"; label = status;
  } else if (lower.startsWith("failed") || lower.includes("failed")) {
    variant = "fail"; icon = "✕"; label = status;
  } else {
    variant = "pending"; icon = "⏳"; label = status;
  }
  return (
    <div className={`quarantine-status quarantine-status--${variant}`}>
      <span className="quarantine-heading">Quarantine</span>
      <span className="quarantine-icon">{icon}</span>
      <span className="quarantine-label">{label}</span>
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

function getPathWarnings(path) {
  if (!path) return [];
  const parts = path.split(/[\\\/]/);
  const reasons = [];
  parts.forEach((part, i) =>
    SUSPICIOUS_PATH_RULES.filter(r => r.test(part, i))
      .forEach(r => { if (!reasons.includes(r.reason)) reasons.push(r.reason); })
  );
  return reasons;
}

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

function Widget({ title, children, className = "", dragHandlers, isDragOver }) {
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

function InfoTip({ text }) {
  return (
    <span className="infotip">
      <span className="infotip-icon">ⓘ</span>
      <span className="infotip-popup">{text}</span>
    </span>
  );
}

// --- IP reputation helpers (module-scope so IpTooltipChip can use them) ---
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
function countryFlag() { return ""; }

function IpTooltipChip({ ip, rep }) {
  const wrapperRef = useRef(null);
  const [tipPos, setTipPos] = useState(null);

  function handleMouseEnter() {
    if (!rep || !wrapperRef.current) return;
    const rect = wrapperRef.current.getBoundingClientRect();
    const tipWidth = 210;
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - tipWidth - 8));
    setTipPos({ bottom: window.innerHeight - rect.top + 6, left });
  }

  return (
    <div ref={wrapperRef} className="ip-tooltip-wrapper"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={() => setTipPos(null)}>
      <span className="argus-hash ip-chip" data-risk={getRiskLevel(rep)}>{ip}</span>
      {tipPos && rep && (
        <div className="ip-tooltip ip-tooltip--fixed" style={{ bottom: tipPos.bottom, left: tipPos.left }}>
          {rep.country && <div className="ipt-row">{countryFlag(rep.countryCode)} {rep.country}</div>}
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
}

function BoolValue({ value, positive = false }) {
  const bad = positive ? !value : value;
  return <span className={bad ? "bool-yes" : "bool-no"}>{value ? "Yes" : "No"}</span>;
}

// --- KQL Queries widget content ---
function KQLQueriesContent({ alertId }) {
  const { data: presets = [], isLoading, error } = useQuery({
    queryKey: ["kql-queries", alertId],
    queryFn: async () => {
      const res = await fetch(`${API}/api/kql-queries/alert/${encodeURIComponent(alertId)}`);
      if (!res.ok) throw new Error("No KQL queries found");
      return res.json();
    },
    enabled: !!alertId,
  });
  const [selectedPreset, setSelectedPreset] = useState(null);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);

  if (!alertId) return <p className="status-text">No alert ID available.</p>;
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


// --- Main dashboard ---
function IncidentDashboard({ incident }) {
  const { fileHash, deviceName, user } = incident;

  const [weeksFilter, setWeeksFilter] = useState(2);
  const [weeksInput, setWeeksInput] = useState("2");

const effectiveDays = (weeksFilter ?? 2) * 7;

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

  const { data: vtInd } = useQuery({
    queryKey: ["vt-indicators", fileHash],
    queryFn: async () => {
      const res = await fetch(`${API}/api/vt-indicators/${fileHash}`);
      if (!res.ok) return { relatedIps: [], relatedHashes: [], executionParents: [] };
      return res.json();
    },
    enabled: !!fileHash,
  });

  const ipList = [...new Set(vtInd?.relatedIps || [])].slice(0, 8);

  const deviceIpList = [...new Set([
    dc?.lastIpAddress,
    dc?.lastExternalIpAddress,
    incident.sourceIp,
  ].filter(Boolean))];

  const allIps = [...new Set([...ipList, ...deviceIpList])];

  const { data: ipRepData } = useQuery({
    queryKey: ["ip-reputation", allIps.join(",")],
    queryFn: async () => {
      if (!allIps.length) return { results: {} };
      const resp = await fetch(
        `${API}/api/ip-reputation?ips=${encodeURIComponent(allIps.join(","))}`
      );
      return resp.json();
    },
    enabled: allIps.length > 0,
    staleTime: 1000 * 60 * 30,
  });
  const ipRep = ipRepData?.results ?? {};

  const threatFamily = fi?.mdeFileInfo?.determinationValue || incident.microsoftSignature;
  const threatType = getThreatType(threatFamily);

  const vtHints = [
    fi?.virusTotal?.meaningfulName,
    ...(fi?.virusTotal?.popularThreatLabels ?? []),
  ].filter(Boolean);

  const { data: descData, fetchStatus: descFetchStatus, isSuccess: descIsSuccess } = useQuery({
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
  const { threatDesc, mitreUrl } = (() => {
    const raw = descData?.description;
    if (!raw) return { threatDesc: null, mitreUrl: null };
    // Extract the first markdown link URL from the description
    const linkMatch = raw.match(/\[([^\]]+)\]\((https:\/\/attack\.mitre\.org[^)]+)\)/);
    const url = linkMatch ? linkMatch[2] : null;
    // Strip markdown links and citations, leaving plain text
    const cleaned = raw
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
      .replace(/\s*\(Citation:[^)]*\)/g, "")
      .trim();
    return { threatDesc: cleaned, mitreUrl: url };
  })();

  // --- Widget content renderers ---
  function renderVT() {
    return fiLoading ? <p className="status-text">Loading...</p> : fi ? (
      <>
        <DetectionDonut detectionRatio={fi.virusTotal.detectionRatio} />
        {fi.virusTotal.popularThreatLabels?.length > 0 && (
          <div className="vt-common-classification">
            <span className="vt-classification-label">Common classification</span>
            <span className="vt-classification-value">{fi.virusTotal.popularThreatLabels[0]}</span>
          </div>
        )}
        <a className="vt-link" href={`https://www.virustotal.com/gui/file/${fileHash}`} target="_blank" rel="noreferrer">
          ↗ View on VirusTotal
        </a>
        <div style={{ marginTop: "1rem" }}>
          <StatRow label="First submission" value={fi.virusTotal.firstSubmission || "N/A"} />
          <StatRow label="Last analysis" value={fi.virusTotal.lastAnalysis || "N/A"} />
          <StatRow label="File type" value={fi.virusTotal.fileType || "N/A"} />
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
        <QuarantineStatus status={incident.quarantineStatus} hasFile={!!incident.fileHash} />
        <div style={{ flex: 1, minWidth: 0 }}>
          {fi?.virusTotal.meaningfulName
            ? <div className="threat-meaningful-name">{fi.virusTotal.meaningfulName}</div>
            : <div className="threat-meaningful-name" style={{ fontSize: "0.82rem" }}>{incident.microsoftSignature}</div>
          }
          {threatDesc
            ? <p className="threat-description">{threatDesc}</p>
            : descIsSuccess && <p className="threat-description" style={{ color: "var(--color-label)", fontStyle: "italic" }}>No MITRE ATT&amp;CK documentation found for this threat.</p>
          }
          {mitreUrl && (
            <a className="vt-link" href={mitreUrl} target="_blank" rel="noreferrer">
              ↗ View on MITRE ATT&CK
            </a>
          )}
          <div style={{ marginTop: "1rem" }}>
            <StatRow label="Status" value={incident.status} />
            <StatRow label="Log source" value={incident.logSource} />
            <StatRow label="Detected" value={incident.detectionTimestamp} />
            <StatRow label="ID" value={incident.id} />
            <StatRow label="Category" value={incident.category} />
            <StatRow label="Detection source" value={incident.detectionSource} />
            {incident.classification && <StatRow label="Classification" value={incident.classification} />}
            {incident.determination && <StatRow label="Determination" value={incident.determination} />}
            {incident.assignedTo && <StatRow label="Assigned to" value={incident.assignedTo} />}
            {fi?.virusTotal.popularThreatLabels?.length > 0 && (
              <div className="vt-tags" style={{ marginTop: "0.75rem" }}>
                {fi.virusTotal.popularThreatLabels.map(l => <span key={l} className="vt-tag">{l}</span>)}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  function renderFile() {
    return (
      <>
        <StatRow label="File name" value={<FileExtHint fileName={incident.fileName} />} />
        <div className="stat-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "0.3rem" }}>
          <span className="stat-label">File path</span>
          <SuspiciousPath path={incident.filePath} />
        </div>
        <div className="stat-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "0.3rem" }}>
          <span className="stat-label">Command line</span>
          <span className="stat-value" style={{ fontFamily: "monospace", fontSize: "0.78rem", textAlign: "left" }}>{incident.commandLine || "—"}</span>
        </div>
        {incident.parentProcessName && (
          <StatRow label="Parent process" value={incident.parentProcessName} />
        )}
        {incident.evidenceUrl && (
          <StatRow label="URL" value={incident.evidenceUrl} />
        )}
        {incident.registryKey && (
          <StatRow label="Registry key" value={<span style={{fontFamily:"monospace",fontSize:"0.75rem"}}>{incident.registryKey}</span>} />
        )}
        <div className="stat-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "0.3rem" }}>
          <span className="stat-label">File hash (SHA-256)</span>
          <span className="stat-value" style={{ fontFamily: "monospace", fontSize: "0.7rem", wordBreak: "break-all" }}>{incident.fileHash}</span>
        </div>
        <StatRow label="MS signature" value={incident.microsoftSignature} />
        {incident.sourceIp && <StatRow label="Source IP" value={<IpTooltipChip ip={incident.sourceIp} rep={ipRep[incident.sourceIp]} />} />}
        <StatRow label="Destination IP" value={incident.destinationIp} />
      </>
    );
  }

  function renderObs() {
    return fi ? (
      <>
        {fi?.mdeFileInfo && (
          <>
            {fi.mdeFileInfo.determinationType && <StatRow label="Determination" value={fi.mdeFileInfo.determinationType} />}
            {fi.mdeFileInfo.determinationValue && <StatRow label="Threat family" value={fi.mdeFileInfo.determinationValue} />}
            {fi.mdeFileInfo.filePublisher && <StatRow label="Publisher" value={fi.mdeFileInfo.filePublisher} />}
            {fi.mdeFileInfo.signer && <StatRow label="Signer" value={fi.mdeFileInfo.signer} />}
            {fi.mdeFileInfo.isValidCertificate !== null && (
              <div className="stat-row"><span className="stat-label">Valid certificate</span><BoolValue value={fi.mdeFileInfo.isValidCertificate} positive /></div>
            )}
          </>
        )}
        <div className="observations-counts">
          <div className="obs-count-item">
            <span className="obs-count-number">{fi.mdeFileInfo?.orgPrevalence ?? "—"}</span>
            <span className="obs-count-label">Devices in org</span>
          </div>
          <div className="obs-count-item">
            <span className="obs-count-number">{fi.mdeFileInfo?.globalPrevalence ?? "—"}</span>
            <span className="obs-count-label">Devices worldwide</span>
          </div>
        </div>
        <StatRow label="Seen before" value={fi.internalSightings.seenBefore} />
        <StatRow label="First seen internally" value={fi.internalSightings.firstSeenInternally} />
        <StatRow label="Last seen internally" value={fi.internalSightings.lastSeenInternally} />
        <div className="stat-row">
          <span className="stat-label">Spike detected (24h) <InfoTip text="A spike is detected when the number of internal detections in the last 24 hours exceeds the baseline average for this alert type" /></span>
          <span className="stat-value">{fi.crossCustomerObservations.spikeDetectedInLast24Hours}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Campaign likelihood <InfoTip text="Campaign likelihood is assessed based on cross-tenant prevalence, file hash overlap, and shared infrastructure indicators" /></span>
          <span className="stat-value">{fi.crossCustomerObservations.campaignLikelihood}</span>
        </div>
        <div className="obs-timeline-track">
          <SightingsTimeline
            firstSeen={fi.internalSightings.firstSeenInternally || fi.mdeFileInfo?.orgFirstSeen}
            lastSeen={fi.internalSightings.lastSeenInternally || fi.mdeFileInfo?.orgLastSeen}
            firstGlobal={fi.crossCustomerObservations.firstObservedAcrossCustomers || fi.mdeFileInfo?.globalFirstObserved}
            detected={incident.detectionTimestamp}
            effectiveDays={effectiveDays}
          />
        </div>
        <div style={{ display: "flex", justifyContent: "center", marginTop: "1.5rem" }}>
        <label className="weeks-filter-btn" style={{ width: "fit-content" }}>
          Last
          <input
            className="weeks-num-input"
            type="number"
            min={1}
            max={52}
            value={weeksInput}
            placeholder="2"
            onChange={e => {
              setWeeksInput(e.target.value);
              const v = parseInt(e.target.value);
              if (!isNaN(v) && v >= 1 && v <= 52) setWeeksFilter(v);
            }}
            onBlur={e => {
              const v = parseInt(e.target.value);
              const clamped = isNaN(v) ? 2 : Math.max(1, Math.min(52, v));
              setWeeksFilter(clamped);
              setWeeksInput(String(clamped));
            }}
            onClick={e => e.target.select()}
          />
          {weeksFilter === 1 ? "week" : "weeks"}
        </label>
        </div>
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
        <div className="stat-row">
          <span className="stat-label">Suspicious processes (24h) <InfoTip text="Count of processes flagged as anomalous by Defender based on behavior heuristics in the last 24 hours" /></span>
          <span className="stat-value">{String(dc.suspiciousProcessesLast24h)}</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Beaconing detected <InfoTip text="Indicates whether the device has shown periodic outbound connection patterns consistent with C2 communication" /></span>
          <BoolValue value={dc.beaconingDetected} />
        </div>
        <div className="stat-row">
          <span className="stat-label">Credential dumping <InfoTip text="Indicates whether Defender has detected process activity consistent with credential extraction from memory" /></span>
          <BoolValue value={dc.credentialDumpingDetected} />
        </div>
        <StatRow label="Last seen" value={dc.lastSeen} />
        {dc.healthStatus && <StatRow label="Health status" value={dc.healthStatus} />}
        {dc.lastIpAddress && (
          <StatRow label="Last IP (internal)" value={<IpTooltipChip ip={dc.lastIpAddress} rep={ipRep[dc.lastIpAddress]} />} />
        )}
        {dc.lastExternalIpAddress && (
          <StatRow label="Last IP (external)" value={<IpTooltipChip ip={dc.lastExternalIpAddress} rep={ipRep[dc.lastExternalIpAddress]} />} />
        )}
        {dc.rbacGroupName && <StatRow label="Device group" value={dc.rbacGroupName} />}
{dc.firstSeen && <StatRow label="First seen" value={dc.firstSeen} />}
        {dc.machineTags?.length > 0 && (
          <div className="stat-row" style={{flexDirection:"column",alignItems:"flex-start",gap:"0.35rem"}}>
            <span className="stat-label">Tags</span>
            <div className="vt-tags">{dc.machineTags.map(t => <span key={t} className="vt-tag">{t}</span>)}</div>
          </div>
        )}
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
    const hasData = vtInd && (vtInd.relatedHashes?.length > 0 || vtInd.executionParents?.length > 0 || ipList.length > 0);
    if (!hasData) return <p className="status-text">No external intelligence available for this file.</p>;
    return (
      <>
        {vtInd.relatedHashes?.length > 0 && (
          <div style={{ marginBottom: "1.5rem" }}>
            <div className="argus-cell-label" style={{ marginBottom: "0.4rem" }}>Related hashes (VT)</div>
            <table className="argus-hash-table">
              <thead><tr><th>Scanned</th><th>Detections</th><th>File type</th><th>Name</th></tr></thead>
              <tbody>
                {vtInd.relatedHashes.map(p => {
                  const detColor = p.detections > 0 ? "#e05c5c" : p.detections === 0 ? "#4caf50" : "inherit";
                  return (
                    <tr key={p.hash}>
                      <td>{p.lastAnalysis ?? "—"}</td>
                      <td style={{ color: detColor }}>{p.totalEngines ? `${p.detections} / ${p.totalEngines}` : "—"}</td>
                      <td>{p.fileType ?? "—"}</td>
                      <td><a className="argus-hash-link" href={`https://www.virustotal.com/gui/file/${p.hash}`} target="_blank" rel="noreferrer">{p.name}</a></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {vtInd.executionParents?.length > 0 && (
          <div style={{ marginBottom: "1.5rem" }}>
            <div className="argus-cell-label" style={{ marginBottom: "0.4rem" }}>Execution parents (VT)</div>
            <table className="argus-hash-table">
              <thead><tr><th>Scanned</th><th>Detections</th><th>File type</th><th>Name</th></tr></thead>
              <tbody>
                {vtInd.executionParents.map(p => {
                  const detColor = p.detections > 0 ? "#e05c5c" : p.detections === 0 ? "#4caf50" : "inherit";
                  return (
                    <tr key={p.hash}>
                      <td>{p.lastAnalysis ?? "—"}</td>
                      <td style={{ color: detColor }}>{p.totalEngines ? `${p.detections} / ${p.totalEngines}` : "—"}</td>
                      <td>{p.fileType ?? "—"}</td>
                      <td><a className="argus-hash-link" href={`https://www.virustotal.com/gui/file/${p.hash}`} target="_blank" rel="noreferrer">{p.name}</a></td>
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
              {ipList.map(ip => (
                <IpTooltipChip key={ip} ip={ip} rep={ipRep[ip]} />
              ))}
            </div>
          </div>
        )}
      </>
    );
  }

  function renderKQL() {
    return <KQLQueriesContent alertId={incident.id} />;
  }

  const widgetDefs = {
    vt:      { title: "VirusTotal Detection",        full: false, render: renderVT },
    verdict: { title: "Threat Classification & Verdict", full: false, render: renderVerdict },
    file:    { title: "File & Execution",            full: false, render: renderFile },
    obs:     { title: "Observations & Timeline",     full: false, render: renderObs },
    device:  { title: "Device Context",              full: false, render: renderDevice },
    user:    { title: "User Context",                full: false, render: renderUser },
    argus:   { title: "External Intelligence",       full: true,  render: renderArgus },
    kql:     { title: "KQL Threat Hunting",          full: true,  render: renderKQL },
  };

  const summaryFields = [
    { label: "Detection timestamp", value: <span className="timestamp-value">{incident.detectionTimestamp}</span> },
    { label: "Severity",            value: <SeverityBadge severity={incident.severity} /> },
    { label: "File name",           value: <span style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{incident.fileName || "—"}</span> },
    { label: "Path",                value: <span style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{incident.filePath || "—"}</span> },
    { label: "Command line",        value: <span style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{(incident.commandLine || "—").replace(/^"|"$/g, "")}</span> },
    { label: "File hash",           value: <span style={{ fontFamily: "monospace", fontSize: "0.75rem", wordBreak: "break-all" }}>{incident.fileHash}</span> },
    { label: "Microsoft signature", value: incident.microsoftSignature },
    { label: "Quarantine status",   value: incident.quarantineStatus ? <QuarantineBadge status={incident.quarantineStatus} /> : "—" },
  ];


  return (
    <div className="incident-detail-wrap">
      <div className="incident-summary">
        <div className="incident-summary-top">
          <div>
            <h1 className="incident-title">{incident.title}</h1>
            <p className="incident-id">ID: {incident.id}</p>
            <div className="incident-identity-row">
              <span className="incident-identity-chip">
                <span className="incident-identity-icon">⬡</span>
                <span className="incident-identity-label">Device</span>
                <span className="incident-identity-value">{incident.deviceName}</span>
              </span>
              <span className="incident-identity-chip">
                <span className="incident-identity-icon">◎</span>
                <span className="incident-identity-label">User</span>
                <span className="incident-identity-value">{incident.user}</span>
              </span>
            </div>
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
      <div className="dashboard-grid">
        {widgetOrder.map((key, idx) => {
          const def = widgetDefs[key];
          return (
            <Widget
              key={key}
              title={def.title}
              className={def.full ? "widget--full" : ""}
              isDragOver={dropTargetIdx === idx}
              dragHandlers={makeDragHandlers(idx)}
            >
              {def.render()}
            </Widget>
          );
        })}
      </div>
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
        onNavigateToIncident={handleNavigateToIncident}
      />
    </div>
  );
}

export default App;
