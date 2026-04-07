"""Microsoft Defender for Endpoint alert ingestion.

Token flow: client credentials → MDE API scope.
Required app permission: Alert.Read.All
"""
import json
import httpx

MDE_API_BASE = "https://api.securitycenter.microsoft.com"


async def get_mde_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire a bearer token for the MDE API via client credentials."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": f"{MDE_API_BASE}/.default",
        })
        resp.raise_for_status()
        return resp.json()["access_token"]


async def fetch_mde_alerts(token: str, lookback_hours: int = 168) -> list[dict]:
    """Fetch alerts from MDE, defaulting to last 7 days."""
    from datetime import datetime, timezone, timedelta
    since = (
        datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(
            f"{MDE_API_BASE}/api/alerts",
            headers={"Authorization": f"Bearer {token}"},
            params={"$filter": f"alertCreationTime ge {since}", "$top": 1000},
        )
        resp.raise_for_status()
        return resp.json().get("value", [])


def _pick(evidence: list[dict], entity_type: str) -> list[dict]:
    return [e for e in evidence if e.get("entityType") == entity_type]


def map_alert_to_incident(alert: dict) -> dict:
    """Map a raw MDE API alert object to our Incident field dict.

    Evidence array is the richest source: we extract the first File,
    Process, and IP entries to populate file/process/network fields.
    """
    ev = alert.get("evidence", [])

    files = _pick(ev, "File")
    procs = _pick(ev, "Process")
    users = _pick(ev, "User")
    ips = [e["ipAddress"] for e in ev if e.get("ipAddress")]

    pf = files[0] if files else {}   # primary file
    pp = procs[0] if procs else {}   # primary process

    # Resolve user string: prefer UPN, fall back to domain\account
    user_str = "N/A"
    if users and users[0].get("userPrincipalName"):
        user_str = users[0]["userPrincipalName"]
    elif users:
        u = users[0]
        user_str = (
            f"{u['domainName']}\\{u['accountName']}"
            if u.get("domainName") else u.get("accountName", "N/A")
        )
    elif alert.get("loggedOnUsers"):
        lu = alert["loggedOnUsers"][0]
        user_str = (
            f"{lu['domainName']}\\{lu['accountName']}"
            if lu.get("domainName") else lu.get("accountName", "N/A")
        )

    mitre = [t for t in alert.get("mitreTechniques", []) if t]

    # Build a human-readable log from the evidence
    logs = [
        f"{alert.get('alertCreationTime', '')} [{alert.get('severity', '')}] {alert.get('title', '')}",
        f"Detection source: {alert.get('detectionSource', 'N/A')} | Category: {alert.get('category', 'N/A')}",
    ]
    for e in ev:
        detail = (
            e.get("fileName") or e.get("ipAddress") or
            e.get("accountName") or e.get("registryKey") or ""
        )
        if e.get("entityType") and detail:
            logs.append(f"Evidence [{e['entityType']}]: {detail}")

    return {
        "id": alert["id"],
        "title": alert.get("title", "Unknown Alert"),
        "detection_timestamp": alert.get("alertCreationTime", ""),
        "severity": (alert.get("severity") or "").upper(),
        "device_name": alert.get("computerDnsName", "N/A"),
        "user": user_str,
        "file_name": pf.get("fileName") or "N/A",
        "file_hash": pf.get("sha256") or pf.get("sha1") or "N/A",
        "microsoft_signature": alert.get("threatFamilyName") or alert.get("category") or "N/A",
        "quarantine_status": pf.get("detectionStatus") or "Unknown",
        "log_source": "Microsoft Defender for Endpoint",
        "source_ip": ips[0] if ips else "N/A",
        "destination_ip": ips[1] if len(ips) > 1 else "N/A",
        "status": alert.get("status", "New"),
        "command_line": pp.get("processCommandLine") or pf.get("processCommandLine"),
        "file_path": pf.get("filePath"),
        "tenant_id": alert.get("aadTenantId"),
        "mde_alert_id": alert["id"],
        "mde_incident_id": str(alert["incidentId"]) if alert.get("incidentId") else None,
        "description": alert.get("description"),
        "mitre_techniques_json": json.dumps(mitre),
        "logs_json": json.dumps(logs),
    }
