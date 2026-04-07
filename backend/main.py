from contextlib import asynccontextmanager
import os
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
import httpx

from database import init_db, migrate_db, get_session
from models import (
    Incident, Tenant, FileIntelligence, DeviceContext, UserContext,
    CampaignContext, KQLQuery,
)
from mde_ingest import get_mde_token, fetch_mde_alerts, map_alert_to_incident
import json
from seed_data import seed

VT_API_KEY        = os.environ.get("VT_API_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
IPDATA_API_KEY    = os.environ.get("IPDATA_API_KEY", "")
AZURE_CLIENT_ID     = os.environ.get("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

import asyncio

# ---------------------------------------------------------------------------
# IP reputation helpers (AbuseIPDB, ip-api.com, ExoneraTor, ipdata.co)
# ---------------------------------------------------------------------------

_ip_cache: dict[str, dict] = {}
_tor_exit_nodes: set[str] = set()
_tor_loaded = False


async def _load_tor_exit_nodes() -> None:
    global _tor_loaded
    if _tor_loaded:
        return
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get("https://check.torproject.org/torbulkexitlist")
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    _tor_exit_nodes.add(line)
    except Exception:
        pass
    _tor_loaded = True


async def _fetch_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if r.status_code != 200:
                return {}
            d = r.json().get("data", {})
            return {
                "abuseScore": d.get("abuseConfidenceScore"),
                "countryCode": d.get("countryCode"),
                "isp": d.get("isp"),
                "usageType": d.get("usageType"),
                "totalReports": d.get("totalReports", 0),
                "isWhitelisted": d.get("isWhitelisted", False),
            }
    except Exception:
        return {}


async def _fetch_ipapi(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,isp,org,proxy,hosting"},
            )
            if r.status_code != 200:
                return {}
            d = r.json()
            if d.get("status") != "success":
                return {}
            return {
                "country": d.get("country"),
                "countryCode": d.get("countryCode"),
                "isp": d.get("isp") or d.get("org"),
                "isProxy": d.get("proxy", False),
                "isHosting": d.get("hosting", False),
            }
    except Exception:
        return {}


async def _check_tor(ip: str) -> dict:
    await _load_tor_exit_nodes()
    return {"isTor": ip in _tor_exit_nodes}


async def _fetch_ipdata(ip: str) -> dict:
    if not IPDATA_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                f"https://api.ipdata.co/{ip}",
                params={"api-key": IPDATA_API_KEY},
            )
            if r.status_code != 200:
                return {}
            d = r.json()
            threat = d.get("threat", {})
            asn = d.get("asn", {})
            return {
                "isTor": threat.get("is_tor", False),
                "isProxy": threat.get("is_proxy", False),
                "isDatacenter": threat.get("is_datacenter", False),
                "asnName": asn.get("name"),
            }
    except Exception:
        return {}


def _merge_ip_results(ip: str, abuse: dict, ipapi: dict, tor: dict, ipdata: dict) -> dict:
    result: dict = {"ip": ip, "sources": []}
    # Country / ISP: prefer AbuseIPDB, fall back to ip-api
    result["countryCode"] = abuse.get("countryCode") or ipapi.get("countryCode")
    result["country"] = ipapi.get("country")
    result["isp"] = abuse.get("isp") or ipapi.get("isp") or ipdata.get("asnName")
    result["usageType"] = abuse.get("usageType")
    # Abuse score
    result["abuseScore"] = abuse.get("abuseScore")
    result["totalReports"] = abuse.get("totalReports", 0)
    result["isWhitelisted"] = abuse.get("isWhitelisted", False)
    # Threat flags: OR across sources
    result["isTor"]     = tor.get("isTor", False) or ipdata.get("isTor", False)
    result["isProxy"]   = ipapi.get("isProxy", False) or ipdata.get("isProxy", False)
    result["isHosting"] = ipapi.get("isHosting", False) or ipdata.get("isDatacenter", False)
    # Track which sources contributed
    if abuse:
        result["sources"].append("abuseipdb")
    if ipapi:
        result["sources"].append("ip-api")
    if tor:
        result["sources"].append("exonerator")
    if ipdata:
        result["sources"].append("ipdata")
    return result


# ---------------------------------------------------------------------------
# MITRE ATT&CK + Claude description helpers
# ---------------------------------------------------------------------------

_desc_cache: dict[str, str] = {}
_mitre_index: dict[str, str] = {}  # lowercase name/alias → description
_mitre_loaded = False


def _extract_software_name(family: str) -> str:
    """Extract specific software name from a threat family string.

    Examples:
      "Trojan:Win32/Mimikatz.A" → "Mimikatz"
      "HackTool:Win32/PsExec"  → "PsExec"
      "Ransom:Win32/LockBit.A" → "LockBit"
    """
    if "/" in family:
        raw = family.split("/")[-1]
        return raw.split(".")[0]
    if ":" in family:
        return family.split(":")[1] if len(family.split(":")) > 1 else family
    return family


MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master"
    "/enterprise-attack/enterprise-attack.json"
)


async def _load_mitre_index() -> None:
    global _mitre_loaded
    if _mitre_loaded:
        return
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.get(MITRE_CTI_URL)
            r.raise_for_status()
            bundle = r.json()
        for obj in bundle.get("objects", []):
            if obj.get("type") not in ("malware", "tool"):
                continue
            desc = obj.get("description", "")
            if not desc:
                continue
            _mitre_index[obj["name"].lower()] = desc
            for alias in obj.get("x_mitre_aliases", []):
                _mitre_index[alias.lower()] = desc
    except Exception:
        pass  # Silently fall through to Claude / generic fallback
    _mitre_loaded = True


async def _mitre_description(software_name: str) -> Optional[str]:
    await _load_mitre_index()
    # Strip file extension (e.g. "mimikatz.exe" → "mimikatz")
    base = software_name.lower()
    if "." in base:
        base = base.rsplit(".", 1)[0]
    # Exact match first
    if base in _mitre_index:
        return _mitre_index[base]
    if software_name.lower() in _mitre_index:
        return _mitre_index[software_name.lower()]
    # Word-boundary match: candidate must appear as a whole word within an indexed name.
    # Never check indexed-in-candidate — short names like "at" would match "mimikatz.exe".
    import re
    pattern = re.compile(r'\b' + re.escape(base) + r'\b')
    for indexed, desc in _mitre_index.items():
        if pattern.search(indexed):
            return desc
    return None


async def _claude_description(category: str, software_name: str) -> str:
    if not ANTHROPIC_API_KEY:
        return f"Detected as {category} category threat based on behavioral and static analysis."
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=200,
            messages=[{
                "role": "user",
                "content": (
                    f"In 2-3 sentences, describe the cybersecurity threat '{software_name}' "
                    f"(category: {category}). Focus on what it does and why it's dangerous. "
                    "Be factual and concise."
                ),
            }],
        )
        return msg.content[0].text
    except Exception:
        return f"Detected as {category} category threat based on behavioral and static analysis."


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB, run migrations, and seed synthetic data on startup."""
    init_db()
    migrate_db()
    seed()
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def incident_to_api(inc: Incident) -> dict:
    """Convert an Incident row to the shape the frontend expects."""
    return {
        "id": inc.id,
        "title": inc.title,
        "detectionTimestamp": inc.detection_timestamp,
        "severity": inc.severity,
        "deviceName": inc.device_name,
        "user": inc.user,
        "fileName": inc.file_name,
        "fileHash": inc.file_hash,
        "microsoftSignature": inc.microsoft_signature,
        "quarantineStatus": inc.quarantine_status,
        "logSource": inc.log_source,
        "sourceIp": inc.source_ip,
        "destinationIp": inc.destination_ip,
        "status": inc.status,
        "commandLine": inc.command_line,
        "filePath": inc.file_path,
        "tenantId": inc.tenant_id,
        "mdeAlertId": inc.mde_alert_id,
        "mdeIncidentId": inc.mde_incident_id,
        "description": inc.description,
        "mitreTechniques": json.loads(inc.mitre_techniques_json or "[]"),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/threat-description")
async def get_threat_description(family: str, hints: str = ""):
    """Return a description for a threat family string, sourced from MITRE ATT&CK or Claude.

    hints: comma-separated list of additional name candidates (e.g. VT meaningful name, labels).
    """
    if not family or family == "N/A":
        raise HTTPException(status_code=400, detail="No family provided")

    cache_key = f"{family}|{hints}"
    if cache_key in _desc_cache:
        return {"description": _desc_cache[cache_key]}

    category = family.split(":")[0]
    software_name = _extract_software_name(family)

    # Build candidate list: hints first (more specific), then signature-derived name
    candidates = [h.strip() for h in hints.split(",") if h.strip()]
    candidates.append(software_name)

    desc = None
    for candidate in candidates:
        desc = await _mitre_description(candidate)
        if desc:
            break

    if not desc:
        # Use the most specific name available for Claude
        best_name = candidates[0] if candidates else software_name
        desc = await _claude_description(category, best_name)

    _desc_cache[cache_key] = desc
    return {"description": desc}


@app.get("/api/incidents")
def list_incidents(session: Session = Depends(get_session)):
    """Return all incidents (without logs)."""
    incidents = session.exec(select(Incident)).all()
    return [incident_to_api(inc) for inc in incidents]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, session: Session = Depends(get_session)):
    """Return a single incident by ID."""
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_to_api(incident)


@app.get("/api/incidents/{incident_id}/logs")
def get_incident_logs(incident_id: str, session: Session = Depends(get_session)):
    """Return the raw log lines for an incident."""
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incidentId": incident_id, "logs": incident.logs}



async def fetch_virustotal(file_hash: str) -> Optional[FileIntelligence]:
    """Fetch file report from VirusTotal API v3 and return a FileIntelligence."""
    if not VT_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VT_API_KEY},
            )
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {})
    except httpx.HTTPError:
        return None

    attrs = data.get("attributes", {})

    # Detection ratio
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
    detection_ratio = f"{malicious}/{total} vendors"

    # Timestamps
    def fmt_ts(unix_ts):
        if not unix_ts:
            return "N/A"
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    first_submission = fmt_ts(attrs.get("first_submission_date"))
    last_analysis = fmt_ts(attrs.get("last_analysis_date"))

    # File type
    file_type = attrs.get("type_description", "Unknown")

    # Threat labels
    threat_class = attrs.get("popular_threat_classification", {})
    labels = []
    if threat_class.get("suggested_threat_label"):
        labels.append(threat_class["suggested_threat_label"])
    for entry in threat_class.get("popular_threat_name", []):
        if entry.get("value"):
            labels.append(entry["value"])
    labels = labels[:5]

    # Reputation
    rep_score = attrs.get("reputation", 0)
    if malicious > total * 0.5:
        reputation = "Malicious"
    elif malicious > total * 0.1:
        reputation = "Suspicious"
    elif malicious > 0:
        reputation = "Low risk"
    else:
        reputation = "Clean"

    # Meaningful name and tags
    meaningful_name = attrs.get("meaningful_name")
    tags = attrs.get("tags", [])[:10]

    return FileIntelligence(
        file_hash=file_hash,
        vt_detection_ratio=detection_ratio,
        vt_first_submission=first_submission,
        vt_last_analysis=last_analysis,
        vt_file_type=file_type,
        vt_popular_threat_labels_json=json.dumps(labels),
        vt_reputation_score=f"{reputation} (score: {rep_score})",
        vt_meaningful_name=meaningful_name,
        vt_tags_json=json.dumps(tags),
        ms_classification="N/A",
        ms_threat_family="N/A",
        ms_prevalence="N/A",
        ms_global_detection_level="N/A",
        ms_cloud_protection_level="N/A",
        seen_before="N/A",
        first_seen_internally="N/A",
        last_seen_internally="N/A",
        number_of_affected_devices="N/A",
        affected_devices_json="[]",
        total_internal_detections="N/A",
        seen_across_customers="N/A",
        number_of_customer_environments="N/A",
        first_observed_across_customers="N/A",
        spike_detected_last_24h="N/A",
        campaign_likelihood="N/A",
        df_classification="N/A",
        df_threat_family="N/A",
        df_prevalence="N/A",
        df_global_detection_level="N/A",
        df_cloud_protection_level="N/A",
    )


@app.get("/api/file-intelligence/{file_hash}")
async def get_file_intelligence(file_hash: str, session: Session = Depends(get_session)):
    """Return file intelligence data for a given hash. Fetches from VirusTotal if not cached."""
    fi = session.exec(
        select(FileIntelligence).where(FileIntelligence.file_hash == file_hash)
    ).first()

    # VT caching: only fetch from VirusTotal if the hash has no cached VT data in
    # SQLite. Subsequent requests return instantly from the DB, preserving API credits.
    if VT_API_KEY and (not fi or fi.vt_detection_ratio is None):
        vt_result = await fetch_virustotal(file_hash)
        if vt_result:
            if fi:
                # Update existing record with VT fields
                fi.vt_detection_ratio = vt_result.vt_detection_ratio
                fi.vt_first_submission = vt_result.vt_first_submission
                fi.vt_last_analysis = vt_result.vt_last_analysis
                fi.vt_file_type = vt_result.vt_file_type
                fi.vt_popular_threat_labels_json = vt_result.vt_popular_threat_labels_json
                fi.vt_reputation_score = vt_result.vt_reputation_score
                fi.vt_meaningful_name = vt_result.vt_meaningful_name
                fi.vt_tags_json = vt_result.vt_tags_json
            else:
                fi = vt_result
                session.add(fi)
            session.commit()
            session.refresh(fi)

    if not fi:
        raise HTTPException(status_code=404, detail="No intelligence found for this hash")
    return fi.to_api_response()


@app.get("/api/vt-indicators/{file_hash}")
async def get_vt_indicators(file_hash: str):
    """Fetch related indicators (contacted IPs, bundled file hashes) from VirusTotal."""
    if not VT_API_KEY:
        return {"relatedIps": [], "relatedHashes": []}

    related_ips = []
    related_hashes = []
    execution_parents = []

    def _parse_file_item(item: dict) -> dict:
        attrs = item.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        ts = attrs.get("last_analysis_date")
        names = attrs.get("names") or []
        name = names[0] if names else attrs.get("meaningful_name")
        return {
            "hash": item["id"],
            "lastAnalysis": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else None,
            "detections": malicious,
            "totalEngines": total,
            "fileType": attrs.get("type_description"),
            "name": name,
        }

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_ips",
                headers={"x-apikey": VT_API_KEY},
                params={"limit": 10},
            )
            if resp.status_code == 200:
                related_ips = [item["id"] for item in resp.json().get("data", [])]
        except httpx.HTTPError:
            pass

        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}/bundled_files",
                headers={"x-apikey": VT_API_KEY},
                params={"limit": 10},
            )
            if resp.status_code == 200:
                related_hashes = [_parse_file_item(i) for i in resp.json().get("data", [])]
        except httpx.HTTPError:
            pass

        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}/execution_parents",
                headers={"x-apikey": VT_API_KEY},
                params={"limit": 20},
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", []):
                    parsed = _parse_file_item(item)
                    # Only include entries with a real name (skip hash-only entries)
                    name = parsed.get("name") or ""
                    if name and not name.startswith("fil") and len(name) < 80:
                        execution_parents.append(parsed)
                        if len(execution_parents) >= 5:
                            break
        except httpx.HTTPError:
            pass

    return {"relatedIps": related_ips, "relatedHashes": related_hashes, "executionParents": execution_parents}


@app.get("/api/ip-reputation")
async def get_ip_reputation(ips: str):
    """Return reputation data for a comma-separated list of IPs (max 10)."""
    ip_list = list(dict.fromkeys(i.strip() for i in ips.split(",") if i.strip()))[:10]
    if not ip_list:
        return {"results": {}}

    results = {}
    uncached = [ip for ip in ip_list if ip not in _ip_cache]

    if uncached:
        async def enrich(ip: str) -> tuple[str, dict]:
            abuse, ipapi, tor, ipdata = await asyncio.gather(
                _fetch_abuseipdb(ip),
                _fetch_ipapi(ip),
                _check_tor(ip),
                _fetch_ipdata(ip),
            )
            return ip, _merge_ip_results(ip, abuse, ipapi, tor, ipdata)

        enriched = await asyncio.gather(*[enrich(ip) for ip in uncached])
        for ip, rep in enriched:
            _ip_cache[ip] = rep

    for ip in ip_list:
        results[ip] = _ip_cache[ip]

    return {"results": results}


@app.get("/api/device-context/{device_name}")
def get_device_context(device_name: str, session: Session = Depends(get_session)):
    """Return device context for a given device name."""
    dc = session.exec(
        select(DeviceContext).where(DeviceContext.device_name == device_name)
    ).first()
    if not dc:
        raise HTTPException(status_code=404, detail="No device context found")
    return {
        "deviceId": dc.device_id,
        "deviceName": dc.device_name,
        "tenantId": dc.tenant_id,
        "osPlatform": dc.os_platform,
        "osVersion": dc.os_version,
        "deviceType": dc.device_type,
        "riskLevel": dc.risk_level,
        "exposureLevel": dc.exposure_level,
        "lastLoggedOnUser": dc.last_logged_on_user,
        "failedLogonsLast24h": dc.failed_logons_last_24h,
        "suspiciousProcessesLast24h": dc.suspicious_processes_last_24h,
        "beaconingDetected": dc.beaconing_detected,
        "credentialDumpingDetected": dc.credential_dumping_detected,
        "lastSeen": dc.last_seen.isoformat(),
    }


@app.get("/api/user-context/{user_principal_name}")
def get_user_context(user_principal_name: str, session: Session = Depends(get_session)):
    """Return user context for a given user principal name."""
    uc = session.exec(
        select(UserContext).where(UserContext.user_principal_name == user_principal_name)
    ).first()
    if not uc:
        raise HTTPException(status_code=404, detail="No user context found")
    return {
        "userId": uc.user_id,
        "userPrincipalName": uc.user_principal_name,
        "displayName": uc.display_name,
        "tenantId": uc.tenant_id,
        "accountEnabled": uc.account_enabled,
        "riskLevel": uc.risk_level,
        "signInRiskLevel": uc.sign_in_risk_level,
        "failedLoginsLast24h": uc.failed_logins_last_24h,
        "impossibleTravelDetected": uc.impossible_travel_detected,
        "mfaEnabled": uc.mfa_enabled,
        "privilegedRoles": json.loads(uc.privileged_roles_json),
        "lastSignIn": uc.last_sign_in.isoformat(),
    }


@app.get("/api/campaign-context")
def list_campaign_contexts(session: Session = Depends(get_session)):
    """Return all campaign context records."""
    campaigns = session.exec(select(CampaignContext)).all()
    return [
        {
            "campaignId": c.campaign_id,
            "campaignLikelihood": c.campaign_likelihood,
            "spikeDetectedLast24h": c.spike_detected_last_24h,
            "numberOfAffectedDevices": c.number_of_affected_devices,
            "numberOfAffectedUsers": c.number_of_affected_users,
            "numberOfCustomerEnvironments": c.number_of_customer_environments,
            "firstObserved": c.first_observed.isoformat(),
            "lastObserved": c.last_observed.isoformat(),
            "relatedHashes": json.loads(c.related_hashes_json),
            "relatedIps": json.loads(c.related_ips_json),
            "relatedTechniques": json.loads(c.related_techniques_json),
        }
        for c in campaigns
    ]


# @app.get("/api/malware-analysis/{file_hash}")
# def get_malware_analysis(file_hash: str, session: Session = Depends(get_session)):
#     """Return malware analysis results for a given file hash."""
#     ma = session.exec(
#         select(MalwareAnalysis).where(MalwareAnalysis.file_hash == file_hash)
#     ).first()
#     if not ma:
#         raise HTTPException(status_code=404, detail="No malware analysis found")
#     return {
#         "fileHash": ma.file_hash,
#         "sandboxScore": ma.sandbox_score,
#         "behaviorSummary": ma.behavior_summary,
#         "processesSpawned": json.loads(ma.processes_spawned_json),
#         "registryChanges": json.loads(ma.registry_changes_json),
#         "networkConnections": json.loads(ma.network_connections_json),
#         "persistenceDetected": ma.persistence_detected,
#         "credentialAccessDetected": ma.credential_access_detected,
#         "commandAndControlDetected": ma.command_and_control_detected,
#         "analysisTimestamp": ma.analysis_timestamp.isoformat(),
#     }


@app.get("/api/kql-queries/{entity_type}/{entity_id:path}")
def get_kql_queries(entity_type: str, entity_id: str, session: Session = Depends(get_session)):
    """Return KQL queries related to a specific entity."""
    queries = session.exec(
        select(KQLQuery).where(
            KQLQuery.related_entity_type == entity_type,
            KQLQuery.related_entity_id == entity_id,
        )
    ).all()
    return [
        {
            "queryName": q.query_name,
            "queryDescription": q.query_description,
            "kqlStatement": q.kql_statement,
            "relatedEntityType": q.related_entity_type,
            "relatedEntityId": q.related_entity_id,
            "executionTimestamp": q.execution_timestamp.isoformat(),
            "resultCount": q.result_count,
            "resultColumns": json.loads(q.result_columns_json),
            "resultRows": json.loads(q.result_rows_json),
        }
        for q in queries
    ]


# ---------------------------------------------------------------------------
# Tenant management
# ---------------------------------------------------------------------------

def tenant_to_api(t: Tenant) -> dict:
    return {
        "id": t.id,
        "tenantId": t.tenant_id,
        "displayName": t.display_name,
        "hasOwnCredentials": bool(t.client_id),
        "isActive": t.is_active,
        "lastSyncedAt": t.last_synced_at.isoformat() if t.last_synced_at else None,
    }


@app.get("/api/tenants")
def list_tenants(session: Session = Depends(get_session)):
    return [tenant_to_api(t) for t in session.exec(select(Tenant)).all()]


@app.post("/api/tenants", status_code=201)
def create_tenant(body: dict, session: Session = Depends(get_session)):
    """Register a tenant. client_id/client_secret are optional if a shared
    app registration is configured via AZURE_CLIENT_ID/AZURE_CLIENT_SECRET."""
    if not body.get("tenantId") or not body.get("displayName"):
        raise HTTPException(status_code=400, detail="tenantId and displayName are required")
    existing = session.exec(
        select(Tenant).where(Tenant.tenant_id == body["tenantId"])
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant already registered")
    tenant = Tenant(
        tenant_id=body["tenantId"],
        display_name=body["displayName"],
        client_id=body.get("clientId"),
        client_secret=body.get("clientSecret"),
    )
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    return tenant_to_api(tenant)


@app.delete("/api/tenants/{tenant_id}", status_code=204)
def delete_tenant(tenant_id: int, session: Session = Depends(get_session)):
    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    session.delete(tenant)
    session.commit()


# ---------------------------------------------------------------------------
# MDE alert sync
# ---------------------------------------------------------------------------

async def _sync_tenant(tenant: Tenant, session: Session, lookback_hours: int) -> dict:
    """Fetch MDE alerts for one tenant and upsert into the incidents table."""
    client_id     = tenant.client_id     or AZURE_CLIENT_ID
    client_secret = tenant.client_secret or AZURE_CLIENT_SECRET
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=400,
            detail=f"No credentials for tenant '{tenant.display_name}'. "
                   "Set clientId/clientSecret on the tenant or configure "
                   "AZURE_CLIENT_ID/AZURE_CLIENT_SECRET env vars.",
        )

    token  = await get_mde_token(tenant.tenant_id, client_id, client_secret)
    alerts = await fetch_mde_alerts(token, lookback_hours=lookback_hours)

    new_count = updated_count = 0
    for alert in alerts:
        fields = map_alert_to_incident(alert)
        existing = session.get(Incident, fields["id"])
        if existing:
            existing.status              = fields["status"]
            existing.quarantine_status   = fields["quarantine_status"]
            existing.detection_timestamp = fields["detection_timestamp"]
            session.add(existing)
            updated_count += 1
        else:
            session.add(Incident(**fields))
            new_count += 1

    from datetime import datetime, timezone
    tenant.last_synced_at = datetime.now(timezone.utc)
    session.add(tenant)
    session.commit()

    return {"tenant": tenant.display_name, "new": new_count, "updated": updated_count}


@app.post("/api/tenants/{tenant_id}/sync")
async def sync_tenant(
    tenant_id: int,
    lookback_hours: int = 168,
    session: Session = Depends(get_session),
):
    """Pull MDE alerts for a single tenant (default: last 7 days)."""
    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return await _sync_tenant(tenant, session, lookback_hours)


@app.post("/api/sync-all")
async def sync_all_tenants(
    lookback_hours: int = 168,
    session: Session = Depends(get_session),
):
    """Pull MDE alerts for all active tenants."""
    tenants = session.exec(select(Tenant).where(Tenant.is_active == True)).all()
    if not tenants:
        return {"results": [], "message": "No active tenants registered"}
    results = []
    for tenant in tenants:
        try:
            result = await _sync_tenant(tenant, session, lookback_hours)
            results.append(result)
        except Exception as e:
            results.append({"tenant": tenant.display_name, "error": str(e)})
    return {"results": results}
