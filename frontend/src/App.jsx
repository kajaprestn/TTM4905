import { useState, useEffect, useRef } from "react";
import "./App.css";

const API = "http://localhost:8000";

const accordionSections = [
  "File Intelligence Section",
  "Device Context",
  "User Context",
  "Network Context",
  "Campaign",
  "Malware Analysis",
  "KQL Queries",
];

function SubSection({ title, rows }) {
  return (
    <div className="subsection">
      <div className="subsection-layout">
        <span className="meta-label subsection-title">{title}</span>
        <div className="subsection-rows">
          {rows.map((row) => (
            <div
              className={`subsection-row ${row.list ? "subsection-row--stacked" : ""}`}
              key={row.label}
            >
              <span className="subsection-row-label">
                {row.label} {!row.list && row.value}
              </span>
              {row.list && (
                <ul className="meta-list">
                  {row.list.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function FileIntelligenceContent({ fileHash }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!fileHash) {
      setLoading(false);
      setError("No file hash available for this incident.");
      return;
    }
    setLoading(true);
    setError(null);
    fetch(`${API}/api/file-intelligence/${fileHash}`)
      .then((res) => {
        if (!res.ok) throw new Error("No intelligence found for this hash");
        return res.json();
      })
      .then((json) => {
        setData(json);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [fileHash]);

  if (loading) return <p className="status-text">Loading file intelligence...</p>;
  if (error) return <p className="status-text">{error}</p>;
  if (!data) return null;

  const d = data;
  return (
    <div className="file-intelligence">
      <div className="meta-row">
        <span className="meta-label subsection-title">File hash:</span>
        <span className="meta-value">{d.fileHash}</span>
      </div>

      <SubSection
        title="VirusTotal:"
        rows={[
          { label: "Detection ratio:", value: d.virusTotal.detectionRatio },
          { label: "First submission:", value: d.virusTotal.firstSubmission },
          { label: "Last analysis:", value: d.virusTotal.lastAnalysis },
          { label: "File type:", value: d.virusTotal.fileType },
          {
            label: "Popular threat labels:",
            value: "",
            list: d.virusTotal.popularThreatLabels,
          },
          { label: "Reputation score:", value: d.virusTotal.reputationScore },
        ]}
      />

      <SubSection
        title="Microsoft Reputation"
        rows={[
          {
            label: "Classification:",
            value: d.microsoftReputation.classification,
          },
          {
            label: "Threat familiy:",
            value: d.microsoftReputation.threatFamily,
          },
          { label: "Prevalence:", value: d.microsoftReputation.prevalence },
          {
            label: "Global detection level:",
            value: d.microsoftReputation.globalDetectionLevel,
          },
          {
            label: "Cloud protection level:",
            value: d.microsoftReputation.cloudProtectionLevel,
          },
        ]}
      />

      <SubSection
        title="Internal Sightings"
        rows={[
          { label: "Seen before:", value: d.internalSightings.seenBefore },
          {
            label: "First seen internally:",
            value: d.internalSightings.firstSeenInternally,
          },
          {
            label: "Last seen internally:",
            value: d.internalSightings.lastSeenInternally,
          },
          {
            label: "Number of affected devices:",
            value: d.internalSightings.numberOfAffectedDevices,
            list: d.internalSightings.affectedDevices,
          },
          {
            label: "Total internal detections:",
            value: d.internalSightings.totalInternalDetections,
          },
        ]}
      />

      <SubSection
        title="Cross-Customer Observations"
        rows={[
          {
            label: "Seen across multiple customers:",
            value: d.crossCustomerObservations.seenAcrossMultipleCustomers,
          },
          {
            label: "Number of customer environments:",
            value: d.crossCustomerObservations.numberOfCustomerEnvironments,
          },
          {
            label: "First observed across customers:",
            value: d.crossCustomerObservations.firstObservedAcrossCustomers,
          },
          {
            label: "Spike detected in last 24 hours:",
            value: d.crossCustomerObservations.spikeDetectedInLast24Hours,
          },
          {
            label: "Campaign likelihood:",
            value: d.crossCustomerObservations.campaignLikelihood,
          },
        ]}
      />

      <SubSection
        title="Detection Frequency"
        rows={[
          {
            label: "Classification:",
            value: d.detectionFrequency.classification,
          },
          {
            label: "Threat familiy:",
            value: d.detectionFrequency.threatFamily,
          },
          { label: "Prevalence:", value: d.detectionFrequency.prevalence },
          {
            label: "Global detection level:",
            value: d.detectionFrequency.globalDetectionLevel,
          },
          {
            label: "Cloud protection level:",
            value: d.detectionFrequency.cloudProtectionLevel,
          },
        ]}
      />
    </div>
  );
}

function DeviceContextContent({ deviceName }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!deviceName) {
      setLoading(false);
      setError("No device name available for this incident.");
      return;
    }
    setLoading(true);
    setError(null);
    fetch(`${API}/api/device-context/${encodeURIComponent(deviceName)}`)
      .then((res) => {
        if (!res.ok) throw new Error("No device context found");
        return res.json();
      })
      .then((json) => { setData(json); setLoading(false); })
      .catch((err) => { setError(err.message); setLoading(false); });
  }, [deviceName]);

  if (loading) return <p className="status-text">Loading device context...</p>;
  if (error) return <p className="status-text">{error}</p>;
  if (!data) return null;

  return (
    <div className="file-intelligence">
      <SubSection title="Device Info" rows={[
        { label: "Device name:", value: data.deviceName },
        { label: "Device ID:", value: data.deviceId },
        { label: "Device type:", value: data.deviceType },
        { label: "OS platform:", value: data.osPlatform },
        { label: "OS version:", value: data.osVersion },
      ]} />
      <SubSection title="Risk Assessment" rows={[
        { label: "Risk level:", value: data.riskLevel },
        { label: "Exposure level:", value: data.exposureLevel },
        { label: "Beaconing detected:", value: data.beaconingDetected ? "Yes" : "No" },
        { label: "Credential dumping detected:", value: data.credentialDumpingDetected ? "Yes" : "No" },
      ]} />
      <SubSection title="Activity" rows={[
        { label: "Last logged on user:", value: data.lastLoggedOnUser },
        { label: "Failed logons (24h):", value: String(data.failedLogonsLast24h) },
        { label: "Suspicious processes (24h):", value: String(data.suspiciousProcessesLast24h) },
        { label: "MITRE techniques:", value: "", list: data.mitreTechniques },
        { label: "Last seen:", value: data.lastSeen },
      ]} />
    </div>
  );
}

function UserContextContent({ user }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!user) {
      setLoading(false);
      setError("No user available for this incident.");
      return;
    }
    setLoading(true);
    setError(null);
    fetch(`${API}/api/user-context/${encodeURIComponent(user)}`)
      .then((res) => {
        if (!res.ok) throw new Error("No user context found");
        return res.json();
      })
      .then((json) => { setData(json); setLoading(false); })
      .catch((err) => { setError(err.message); setLoading(false); });
  }, [user]);

  if (loading) return <p className="status-text">Loading user context...</p>;
  if (error) return <p className="status-text">{error}</p>;
  if (!data) return null;

  return (
    <div className="file-intelligence">
      <SubSection title="User Info" rows={[
        { label: "Display name:", value: data.displayName },
        { label: "User principal name:", value: data.userPrincipalName },
        { label: "Account enabled:", value: data.accountEnabled ? "Yes" : "No" },
        { label: "MFA enabled:", value: data.mfaEnabled ? "Yes" : "No" },
      ]} />
      <SubSection title="Risk Assessment" rows={[
        { label: "Risk level:", value: data.riskLevel },
        { label: "Sign-in risk level:", value: data.signInRiskLevel },
        { label: "Impossible travel detected:", value: data.impossibleTravelDetected ? "Yes" : "No" },
        { label: "Failed logins (24h):", value: String(data.failedLoginsLast24h) },
      ]} />
      <SubSection title="Roles & Activity" rows={[
        { label: "Privileged roles:", value: "", list: data.privilegedRoles },
        { label: "MITRE techniques:", value: "", list: data.mitreTechniques },
        { label: "Last sign-in:", value: data.lastSignIn },
      ]} />
    </div>
  );
}

function CampaignContent() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${API}/api/campaign-context`)
      .then((res) => {
        if (!res.ok) throw new Error("No campaign data found");
        return res.json();
      })
      .then((json) => { setData(json); setLoading(false); })
      .catch((err) => { setError(err.message); setLoading(false); });
  }, []);

  if (loading) return <p className="status-text">Loading campaign data...</p>;
  if (error) return <p className="status-text">{error}</p>;
  if (!data || data.length === 0) return <p className="status-text">No campaign data available.</p>;

  return (
    <div className="file-intelligence">
      {data.map((c) => (
        <div key={c.campaignId}>
          <SubSection title={`Campaign ${c.campaignId}`} rows={[
            { label: "Likelihood:", value: c.campaignLikelihood },
            { label: "Spike detected (24h):", value: c.spikeDetectedLast24h ? "Yes" : "No" },
            { label: "Affected devices:", value: String(c.numberOfAffectedDevices) },
            { label: "Affected users:", value: String(c.numberOfAffectedUsers) },
            { label: "Customer environments:", value: String(c.numberOfCustomerEnvironments) },
            { label: "First observed:", value: c.firstObserved },
            { label: "Last observed:", value: c.lastObserved },
          ]} />
          <SubSection title="Related Indicators" rows={[
            { label: "Related hashes:", value: "", list: c.relatedHashes },
            { label: "Related IPs:", value: "", list: c.relatedIps },
            { label: "Related techniques:", value: "", list: c.relatedTechniques },
          ]} />
        </div>
      ))}
    </div>
  );
}

function MalwareAnalysisContent({ fileHash }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!fileHash) {
      setLoading(false);
      setError("No file hash available for this incident.");
      return;
    }
    setLoading(true);
    setError(null);
    fetch(`${API}/api/malware-analysis/${fileHash}`)
      .then((res) => {
        if (!res.ok) throw new Error("No malware analysis found for this hash");
        return res.json();
      })
      .then((json) => { setData(json); setLoading(false); })
      .catch((err) => { setError(err.message); setLoading(false); });
  }, [fileHash]);

  if (loading) return <p className="status-text">Loading malware analysis...</p>;
  if (error) return <p className="status-text">{error}</p>;
  if (!data) return null;

  return (
    <div className="file-intelligence">
      <SubSection title="Sandbox Results" rows={[
        { label: "Sandbox score:", value: data.sandboxScore },
        { label: "Behavior summary:", value: data.behaviorSummary },
      ]} />
      <SubSection title="Observed Behavior" rows={[
        { label: "Processes spawned:", value: "", list: data.processesSpawned },
        { label: "Registry changes:", value: "", list: data.registryChanges },
        { label: "Network connections:", value: "", list: data.networkConnections },
      ]} />
      <SubSection title="Detection Flags" rows={[
        { label: "Persistence detected:", value: data.persistenceDetected ? "Yes" : "No" },
        { label: "Credential access detected:", value: data.credentialAccessDetected ? "Yes" : "No" },
        { label: "C2 detected:", value: data.commandAndControlDetected ? "Yes" : "No" },
        { label: "MITRE techniques:", value: "", list: data.mitreTechniques },
        { label: "Analysis timestamp:", value: data.analysisTimestamp },
      ]} />
    </div>
  );
}

function KQLQueriesContent({ deviceName }) {
  const [presets, setPresets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedPreset, setSelectedPreset] = useState(null);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!deviceName) {
      setLoading(false);
      setError("No device name available for this incident.");
      return;
    }
    setLoading(true);
    setError(null);
    fetch(`${API}/api/kql-queries/device/${encodeURIComponent(deviceName)}`)
      .then((res) => {
        if (!res.ok) throw new Error("No KQL queries found");
        return res.json();
      })
      .then((json) => { setPresets(json); setLoading(false); })
      .catch((err) => { setError(err.message); setLoading(false); });
  }, [deviceName]);

  function selectPreset(preset) {
    setSelectedPreset(preset);
    setQuery(preset.kqlStatement);
    setResult(null);
  }

  function runQuery() {
    const match = presets.find((p) => p.kqlStatement === query);
    if (match) {
      setResult({
        resultCount: match.resultCount,
        columns: match.resultColumns,
        rows: match.resultRows,
      });
    } else {
      setResult({ demo: true });
    }
  }

  if (loading) return <p className="status-text">Loading KQL queries...</p>;
  if (error) return <p className="status-text">{error}</p>;

  return (
    <div className="kql-container">
      {presets.length > 0 && (
        <div className="kql-presets">
          <span className="kql-presets-label">Predefined queries:</span>
          {presets.map((p, i) => (
            <button
              key={i}
              className={`kql-preset-btn ${selectedPreset === p ? "active" : ""}`}
              onClick={() => selectPreset(p)}
            >
              {p.queryName}
            </button>
          ))}
        </div>
      )}

      {selectedPreset && (
        <p className="kql-description">{selectedPreset.queryDescription}</p>
      )}

      <textarea
        className="kql-editor"
        rows={6}
        placeholder="Write a KQL query or select a predefined one above..."
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setResult(null);
        }}
      />

      <button
        className="kql-run-btn"
        onClick={runQuery}
        disabled={!query.trim()}
      >
        Run query
      </button>

      {result && (
        <div className="kql-results">
          {result.demo ? (
            <p className="kql-results-demo">
              Query execution not available in demo. Use a predefined query to see sample results.
            </p>
          ) : result.rows.length === 0 ? (
            <p className="kql-results-demo">Query returned 0 results.</p>
          ) : (
            <>
              <div className="kql-results-header">
                {result.resultCount} result{result.resultCount !== 1 ? "s" : ""}
              </div>
              <div className="kql-table-wrapper">
                <table className="kql-table">
                  <thead>
                    <tr>
                      {result.columns.map((col) => (
                        <th key={col}>{col}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.rows.map((row, i) => (
                      <tr key={i}>
                        {row.map((cell, j) => (
                          <td key={j}>{cell}</td>
                        ))}
                      </tr>
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

function AccordionItem({ title, isOpen, onToggle, children }) {
  const bodyRef = useRef(null);
  const [height, setHeight] = useState("0px");

  useEffect(() => {
    if (isOpen && bodyRef.current) {
      const observer = new ResizeObserver(() => {
        setHeight(bodyRef.current.scrollHeight + "px");
      });
      observer.observe(bodyRef.current);
      setHeight(bodyRef.current.scrollHeight + "px");
      return () => observer.disconnect();
    } else {
      setHeight("0px");
    }
  }, [isOpen]);

  return (
    <div className="accordion-item">
      <button className="accordion-header" onClick={onToggle}>
        <span className={`accordion-chevron ${isOpen ? "open" : ""}`}>
          &#x203A;
        </span>
        <span className="accordion-title">{title}</span>
      </button>
      <div
        ref={bodyRef}
        className="accordion-body"
        style={{ maxHeight: height }}
      >
        <div className="accordion-content">{children}</div>
      </div>
    </div>
  );
}

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
            <button
              className="btn-show-details"
              onClick={() => onSelect(inc.id)}
            >
              Show details
            </button>
          </div>
        ))}
      </main>
    </div>
  );
}

function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [openSections, setOpenSections] = useState({});
  const [lightMode, setLightMode] = useState(false);

  useEffect(() => {
    fetch(`${API}/api/incidents`)
      .then((res) => res.json())
      .then((data) => {
        setIncidents(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  function toggleSection(section) {
    setOpenSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  }

  if (loading) {
    return (
      <div className="incident-page">
        <p className="status-text" style={{ padding: "3rem" }}>
          Loading incidents...
        </p>
      </div>
    );
  }

  if (incidents.length === 0) {
    return (
      <div className="incident-page">
        <p className="status-text" style={{ padding: "3rem" }}>
          No incidents found. Is the backend running?
        </p>
      </div>
    );
  }

  // List view (realtime)
  if (!selectedId) {
    return (
      <IncidentList
        incidents={incidents}
        onSelect={(id) => {
          setSelectedId(id);
          setOpenSections({});
        }}
        lightMode={lightMode}
        onToggleTheme={() => setLightMode(!lightMode)}
      />
    );
  }

  // Detail view
  const data = incidents.find((inc) => inc.id === selectedId);

  const metaFields = [
    { label: "Detection timestamp:", value: data.detectionTimestamp },
    { label: "Severity:", value: data.severity },
    { label: "Device name:", value: data.deviceName },
    { label: "User:", value: data.user },
    { label: "File name:", value: data.fileName },
    { label: "File hash:", value: data.fileHash },
    { label: "Microsoft signature:", value: data.microsoftSignature },
    { label: "MITRE ATT&CK:", value: data.mitreAttack },
    { label: "Quarantine status:", value: data.quarantineStatus },
  ];

  return (
    <div className={`incident-page ${lightMode ? "light" : ""}`}>
      <nav className="top-bar">
        <div className="top-bar-left">
          <span className="top-bar-title">{data.title}</span>
        </div>
        <div className="top-bar-right">
          <span className="top-bar-meta">{data.logSource}</span>
          <span className="top-bar-meta">Source: {data.sourceIp}</span>
          <span className="top-bar-meta">
            Destination: {data.destinationIp}
          </span>
          <button
            className="btn-theme"
            onClick={() => setLightMode(!lightMode)}
          >
            {lightMode ? "\u263D" : "\u2600"}
          </button>
          <button
            className="btn-realtime"
            onClick={() => setSelectedId(null)}
          >
            Back to Realtime
          </button>
        </div>
      </nav>

      <main className="incident-content">
        <h1 className="event-title">{data.title}</h1>
        <p className="event-id">ID: {data.id}</p>

        <hr className="divider" />

        <div className="meta-table">
          {metaFields.map((field) => (
            <div className="meta-row" key={field.label}>
              <span className="meta-label">{field.label}</span>
              <span className="meta-value">{field.value}</span>
            </div>
          ))}
        </div>

        <div className="accordion">
          {accordionSections.map((section) => (
            <AccordionItem
              key={section}
              title={section}
              isOpen={!!openSections[section]}
              onToggle={() => toggleSection(section)}
            >
              {section === "File Intelligence Section" ? (
                <FileIntelligenceContent fileHash={data.fileHash} />
              ) : section === "Device Context" ? (
                <DeviceContextContent deviceName={data.deviceName} />
              ) : section === "User Context" ? (
                <UserContextContent user={data.user} />
              ) : section === "Campaign" ? (
                <CampaignContent />
              ) : section === "Malware Analysis" ? (
                <MalwareAnalysisContent fileHash={data.fileHash} />
              ) : section === "KQL Queries" ? (
                <KQLQueriesContent deviceName={data.deviceName} />
              ) : (
                <p>No data available.</p>
              )}
            </AccordionItem>
          ))}
        </div>
      </main>
    </div>
  );
}

export default App;
