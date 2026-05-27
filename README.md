# Security Incident Response Dashboard

A SOC analyst dashboard for investigating and triaging Microsoft Defender for Endpoint (MDE) security incidents. It enriches alerts with threat intelligence from multiple external sources and presents everything in a single, customisable view.

---

## Features

- **Incident list & detail view** — browse open incidents and drill into a full investigation panel
- **VirusTotal integration** — detection ratio donut, threat labels, file metadata, related hashes, and execution parents
- **IP reputation** — enrichment from AbuseIPDB, ip-api.com, ipdata.co, and the Tor exit-node list; colour-coded hover tooltips per IP
- **MITRE ATT&CK descriptions** — automatic lookup against the live MITRE CTI feed; falls back gracefully when no match is found
- **Device context** — OS, risk/exposure level, failed logons, beaconing & credential-dumping flags, machine tags
- **User context** — sign-in risk, MFA status, impossible-travel detection, privileged roles
- **Campaign context** — cross-tenant prevalence, spike detection, related hashes/IPs/techniques
- **KQL Threat Hunting** — predefined queries per alert with an inline editor and sample results
- **Suspicious-path analysis** — highlights high-risk execution locations (Temp, AppData, Downloads, …) with explanations
- **Sightings timeline** — visual SVG timeline of first/last internal and global sightings
- **Draggable widgets** — rearrange the dashboard layout; order is persisted in `localStorage`
- **Dark / light mode** — toggle in the top-right corner
- **Multi-tenant support** — register multiple Azure AD tenants; per-tenant or shared app registration credentials

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Vite, TanStack Query |
| Backend | Python, FastAPI, SQLModel |
| Database | SQLite (`alerts.db`) |
| HTTP client | httpx (async) |

---

## Project Structure

```
master/
├── backend/
│   ├── main.py          # FastAPI app, all API routes
│   ├── models.py        # SQLModel table definitions
│   ├── database.py      # DB init, migration helpers
│   ├── seed_data.py     # Synthetic seed data for demo/dev
│   ├── data/            # Static JSON fixtures (MDE exports)
│   ├── requirements.txt
│   └── .env             # API keys (not committed)
└── frontend/
    ├── src/
    │   ├── App.jsx      # Entire frontend (single-file)
    │   └── App.css
    ├── index.html
    └── package.json
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+

### 1 — Backend

```bash
cd backend

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env          # then fill in the values (see below)

# Start the development server
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`.

### 2 — Frontend

```bash
cd frontend

npm install
npm run dev
```

The app will be available at `http://localhost:5173`.

---

## Environment Variables

Copy the example file and fill in your keys:

```bash
cp backend/.env.example backend/.env
```

All keys are optional — the dashboard degrades gracefully when a key is absent.

> **Security:** Never commit your `.env` file. It is listed in `.gitignore` and should stay there.
> If you accidentally expose a key, rotate it immediately at the provider's dashboard.

| Variable | Description |
|----------|-------------|
| `VT_API_KEY` | [VirusTotal](https://www.virustotal.com/) API v3 key — enables live file hash lookups |
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) key — adds abuse confidence scores to IPs |
| `IPDATA_API_KEY` | [ipdata.co](https://ipdata.co/) key — adds datacenter/proxy/Tor flags |
| `AZURE_CLIENT_ID` | Shared Azure app registration client ID (for MDE API sync) |
| `AZURE_CLIENT_SECRET` | Shared Azure app registration client secret |

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/incidents` | List all incidents |
| `GET` | `/api/incidents/{id}` | Single incident detail |
| `GET` | `/api/incidents/{id}/logs` | Raw log lines for an incident |
| `GET` | `/api/file-intelligence/{hash}` | File intel (VirusTotal + MDE) |
| `GET` | `/api/vt-indicators/{hash}` | Related IPs, hashes, execution parents (VT) |
| `GET` | `/api/ip-reputation?ips=…` | Reputation data for a comma-separated IP list |
| `GET` | `/api/threat-description?family=…` | MITRE ATT&CK description for a threat family |
| `GET` | `/api/device-context/{name}` | MDE device metadata |
| `GET` | `/api/user-context/{upn}` | User risk and identity context |
| `GET` | `/api/campaign-context` | Campaign correlation data |
| `GET` | `/api/kql-queries/{entity_type}/{entity_id}` | KQL queries for an entity |
| `GET` | `/api/machine-actions/{machine_id}` | MDE machine actions (isolations, scans, …) |
| `GET` | `/api/ip-stats/{ip}` | MDE IP prevalence statistics |
| `GET` | `/api/tenants` | List registered tenants |
| `POST` | `/api/tenants` | Register a new tenant |
| `DELETE` | `/api/tenants/{id}` | Remove a tenant |

Interactive API docs are available at `http://localhost:8000/docs`.

---

## Data Caching

- **VirusTotal** results are cached in SQLite after the first lookup — subsequent requests are served from the DB without consuming API credits.
- **IP reputation** data is cached in-memory for the lifetime of the server process.
- **MITRE ATT&CK** index is loaded once at startup from the [mitre/cti](https://github.com/mitre/cti) GitHub bundle.
- **Tor exit nodes** are fetched once per process from `check.torproject.org`.
