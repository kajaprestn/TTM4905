from contextlib import asynccontextmanager
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
import httpx

from database import init_db, get_session
from models import (
    Incident, FileIntelligence, DeviceContext, UserContext,
    CampaignContext, MalwareAnalysis, KQLQuery,
)
import json
from seed_data import seed

VT_API_KEY = os.environ.get("VT_API_KEY", "")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB and seed synthetic data on startup."""
    init_db()
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

def build_prompt(incident: Incident) -> str:
    logs_block = "\n".join(incident.logs)
    return (
        "You are a cybersecurity analyst. "
        "Given the following security alert and raw log data, write a short "
        "incident summary (3-5 sentences). Include: what happened, the likely "
        "impact, and one recommended next step.\n\n"
        f"Alert: {incident.title}\n"
        f"Severity: {incident.severity}\n"
        f"Source IP: {incident.source_ip}\n"
        f"Target: {incident.device_name}\n"
        f"Time: {incident.detection_timestamp}\n\n"
        f"Raw logs:\n{logs_block}\n\n"
        "Incident summary:"
    )


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
        "mitreAttack": inc.mitre_attack,
        "quarantineStatus": inc.quarantine_status,
        "logSource": inc.log_source,
        "sourceIp": inc.source_ip,
        "destinationIp": inc.destination_ip,
        "status": inc.status,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

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


@app.get("/api/incidents/{incident_id}/summary")
async def get_summary(incident_id: str, session: Session = Depends(get_session)):
    """Send incident + logs to a local LLM (Ollama) and return a summary."""
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    prompt = build_prompt(incident)

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "qwen2:1.5b",
                "prompt": prompt,
                "stream": False,
            },
        )
        resp.raise_for_status()

    answer = resp.json().get("response", "").strip()
    return {"incidentId": incident_id, "summary": answer}


async def fetch_virustotal(file_hash: str) -> FileIntelligence | None:
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
    total = sum(stats.values()) if stats else 0
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

    return FileIntelligence(
        file_hash=file_hash,
        vt_detection_ratio=detection_ratio,
        vt_first_submission=first_submission,
        vt_last_analysis=last_analysis,
        vt_file_type=file_type,
        vt_popular_threat_labels_json=json.dumps(labels),
        vt_reputation_score=f"{reputation} (score: {rep_score})",
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

    if not fi and VT_API_KEY:
        fi = await fetch_virustotal(file_hash)
        if fi:
            session.add(fi)
            session.commit()
            session.refresh(fi)

    if not fi:
        raise HTTPException(status_code=404, detail="No intelligence found for this hash")
    return fi.to_api_response()


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
        "mitreTechniques": json.loads(dc.mitre_techniques_json),
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
        "mitreTechniques": json.loads(uc.mitre_techniques_json),
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


@app.get("/api/malware-analysis/{file_hash}")
def get_malware_analysis(file_hash: str, session: Session = Depends(get_session)):
    """Return malware analysis results for a given file hash."""
    ma = session.exec(
        select(MalwareAnalysis).where(MalwareAnalysis.file_hash == file_hash)
    ).first()
    if not ma:
        raise HTTPException(status_code=404, detail="No malware analysis found")
    return {
        "fileHash": ma.file_hash,
        "sandboxScore": ma.sandbox_score,
        "behaviorSummary": ma.behavior_summary,
        "processesSpawned": json.loads(ma.processes_spawned_json),
        "registryChanges": json.loads(ma.registry_changes_json),
        "networkConnections": json.loads(ma.network_connections_json),
        "persistenceDetected": ma.persistence_detected,
        "credentialAccessDetected": ma.credential_access_detected,
        "commandAndControlDetected": ma.command_and_control_detected,
        "mitreTechniques": json.loads(ma.mitre_techniques_json),
        "analysisTimestamp": ma.analysis_timestamp.isoformat(),
    }


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
            "mitreTechniques": json.loads(q.mitre_techniques_json),
            "resultColumns": json.loads(q.result_columns_json),
            "resultRows": json.loads(q.result_rows_json),
        }
        for q in queries
    ]
