"""Synthetic seed data matching the frontend's expected structure."""

import json
from sqlmodel import Session, select
from database import engine, init_db
from datetime import datetime
from models import (
    Incident, FileIntelligence, DeviceContext, UserContext,
    KQLQuery,
)


TENANT_ID = "335391db-0df6-4699-b48b-92a8feadccb5"

INCIDENTS = [
    # --- Incident 15609: Aikaantivm malware detected (winPEASx64.exe) ---
    # Alert from MDE antivirus — winPEASx64.exe flagged as VirTool:MSIL/Aikaantivm.GG!MTB
    # Spawned by powershell.exe as chrisr; file dropped to C:\ProgramData\legit
    Incident(
        id="dad50712b6-e83b-41c8-827e-8af5873236be_1",
        mde_alert_id="dad50712b6-e83b-41c8-827e-8af5873236be_1",
        mde_incident_id="15609",
        tenant_id=TENANT_ID,
        title="An active 'Aikaantivm' malware was detected",
        description=(
            "Malware and unwanted software are undesirable applications that perform annoying, "
            "disruptive, or harmful actions on affected machines. Some of these undesirable "
            "applications can replicate and spread from one machine to another. Others are able "
            "to receive commands from remote attackers and perform activities associated with "
            "cyber attacks.\n\nA malware is considered active if it is found running on the "
            "machine or it already has persistence mechanisms in place. Active malware detections "
            "are assigned higher severity ratings.\n\nBecause this malware was active, take "
            "precautionary measures and check for residual signs of infection."
        ),
        detection_timestamp="2026-04-20T15:06:27Z",
        severity="LOW",
        device_name="chrisr-lab-ws08.lab.local",
        user="chrisr@lab.local",
        file_name="winPEASx64.exe",
        file_hash="a5e3ded4dff907d728cdb22d85f0ebfe65895189bc1b13983d6687d46476efe0",
        microsoft_signature="Aikaantivm",
        quarantine_status="detected",
        log_source="Microsoft Defender for Endpoint",
        source_ip="10.0.38.66",
        destination_ip=None,
        status="new",
        command_line='winPEASx64.exe',
        file_path=r"C:\ProgramData\legit",
        mitre_techniques_json=json.dumps([]),
        logs_json=json.dumps([
            "2026-04-20T15:03:06Z [LOW] chrisr-lab-ws08 defender: winPEASx64.exe started via powershell.exe as chrisr@lab.local",
            "2026-04-20T15:05:07Z [LOW] chrisr-lab-ws08 defender: VirTool:MSIL/Aikaantivm.GG!MTB detected in winPEASx64.exe at C:\\ProgramData\\legit",
            "2026-04-20T15:06:27Z [LOW] chrisr-lab-ws08 defender: Alert created — An active 'Aikaantivm' malware was detected (antivirus, Malware)",
            "Evidence [File]: winPEASx64.exe",
            "Evidence [IP]: 10.0.38.66",
        ]),
        classification=None,
        determination=None,
        category="Malware",
        detection_source="antivirus",
        threat_name=None,
        assigned_to=None,
        first_event_time="2026-04-20T15:03:06Z",
        last_event_time="2026-04-20T15:05:07Z",
        last_update_time="2026-04-20T15:22:17Z",
        resolved_time=None,
        machine_id="afd75be34dbbae255be8f9b9a0730bca80f4d0d7",
        rbac_group_name="TRS LAB",
        parent_process_name="powershell.exe",
        parent_process_path=None,
        evidence_url=None,
        registry_key=None,
        registry_hive=None,
        registry_value=None,
        comments_json=json.dumps([
            {"comment": "Collected alert to Argus", "createdByDisplayName": "API Action", "createdDateTime": "2026-04-20T15:07:30Z"},
            {"comment": "Collected alert to Argus", "createdByDisplayName": "API Action", "createdDateTime": "2026-04-20T15:22:17Z"},
        ]),
    ),
    # --- Incident 15609: Mimikatz lateral movement (human-operated) ---
    # High-severity alert: mimikatz.exe spawned via powershell.exe targeting lsass.exe
    # File dropped to C:\ProgramData\foo\mimikatz_trunk\x64 — credential dumping in progress
    Incident(
        id="da411feb4c-4ffd-4162-9d5d-f7799f1baf4b_1",
        mde_alert_id="da411feb4c-4ffd-4162-9d5d-f7799f1baf4b_1",
        mde_incident_id="15609",
        tenant_id=TENANT_ID,
        title="Potential human-operated malicious activity",
        description=(
            "Malware was detected on this device. An attacker might be attempting to move "
            "laterally to this device from another device on the network."
        ),
        detection_timestamp="2026-04-20T14:54:00Z",
        severity="HIGH",
        device_name="chrisr-lab-ws08.lab.local",
        user="chrisr@lab.local",
        file_name="mimikatz.exe",
        file_hash="61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1",
        microsoft_signature="HackTool:Win64/Mimikatz!MSR",
        quarantine_status="detected",
        log_source="Microsoft Defender for Endpoint",
        source_ip="10.0.38.66",
        destination_ip=None,
        status="new",
        command_line='"mimikatz.exe"',
        file_path=r"C:\ProgramData\foo\mimikatz_trunk\x64",
        mitre_techniques_json=json.dumps(["T1021.003"]),
        logs_json=json.dumps([
            r"2026-04-20T14:49:51Z [HIGH] chrisr-lab-ws08 defender: mimikatz.exe spawned via powershell.exe as chrisr@lab.local from C:\ProgramData\foo\mimikatz_trunk\x64",
            "2026-04-20T14:50:02Z [HIGH] chrisr-lab-ws08 defender: lsass.exe (wininit.exe child) — credential access attempt detected",
            "2026-04-20T14:54:00Z [HIGH] chrisr-lab-ws08 defender: Alert created — Potential human-operated malicious activity (LateralMovement, T1021.003)",
            "2026-04-20T15:14:22Z [HIGH] chrisr-lab-ws08 defender: Last observed mimikatz.exe process activity",
            "Evidence [File]: mimikatz.exe",
            "Evidence [IP]: 10.0.38.66",
        ]),
        classification=None,
        determination=None,
        category="LateralMovement",
        detection_source="microsoftDefenderForEndpoint",
        threat_name=None,
        assigned_to=None,
        first_event_time="2026-04-20T14:49:51Z",
        last_event_time="2026-04-20T15:14:22Z",
        last_update_time="2026-04-20T16:02:29Z",
        resolved_time=None,
        machine_id="afd75be34dbbae255be8f9b9a0730bca80f4d0d7",
        rbac_group_name="TRS LAB",
        parent_process_name="powershell.exe",
        parent_process_path=None,
        evidence_url=None,
        registry_key=None,
        registry_hive=None,
        registry_value=None,
        comments_json=json.dumps([
            {"comment": "Collected alert to Argus", "createdByDisplayName": "API Action", "createdDateTime": "2026-04-20T14:55:27Z"},
            {"comment": "Collected alert to Argus", "createdByDisplayName": "API Action", "createdDateTime": "2026-04-20T15:07:42Z"},
        ]),
    ),
]


FILE_INTELLIGENCE = [
    # winPEASx64.exe — source: aikaantivm_sha.json (MDE File API)
    FileIntelligence(
        file_hash="a5e3ded4dff907d728cdb22d85f0ebfe65895189bc1b13983d6687d46476efe0",
        determination_type="Malware",
        determination_value="VirTool:MSIL/Aikaantivm!rfn",
        global_prevalence=3,
        global_first_observed="2026-04-17",
        global_last_observed="2026-04-21",
        file_publisher=None,
        file_product_name=None,
        is_pe_file=True,
        top_file_names_json=json.dumps(["winpeasx64.exe", "winPEASx64.exe"]),
        org_prevalence=1,
        org_first_seen="2026-04-20",
        org_last_seen="2026-04-20",
        seen_before="No",
        first_seen_internally="2026-04-20",
        last_seen_internally="2026-04-20",
        number_of_affected_devices="1",
        affected_devices_json=json.dumps(["chrisr-lab-ws08.lab.local"]),
        total_internal_detections="1",
        seen_across_customers="Yes",
        number_of_customer_environments="3",
        first_observed_across_customers="2026-04-17",
        spike_detected_last_24h="No",
        campaign_likelihood="Low",
    ),
    # mimikatz.exe — source: mimikatz_sha.json (MDE File API)
    FileIntelligence(
        file_hash="61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1",
        determination_type="Malware",
        determination_value="HackTool:Win64/Mimikatz!MSR",
        global_prevalence=60138,
        global_first_observed="2022-09-19",
        global_last_observed="2026-04-22",
        file_publisher=None,
        file_product_name=None,
        is_pe_file=True,
        top_file_names_json=json.dumps(["mimikatz.exe"]),
        org_prevalence=1,
        org_first_seen="2026-03-26",
        org_last_seen="2026-04-20",
        seen_before="Yes",
        first_seen_internally="2026-03-26",
        last_seen_internally="2026-04-20",
        number_of_affected_devices="1",
        affected_devices_json=json.dumps(["chrisr-lab-ws08.lab.local"]),
        total_internal_detections="1",
        seen_across_customers="Yes",
        number_of_customer_environments="200+",
        first_observed_across_customers="2022-09-19",
        spike_detected_last_24h="No",
        campaign_likelihood="High",
    ),
]

DEVICE_CONTEXTS = [
    DeviceContext(
        device_id="afd75be34dbbae255be8f9b9a0730bca80f4d0d7",
        device_name="chrisr-lab-ws08.lab.local",
        tenant_id=TENANT_ID,
        os_platform="Windows10",
        os_version="22H2",
        device_type="Workstation",
        risk_level="High",
        exposure_level="High",
        last_logged_on_user="chrisr",
        failed_logons_last_24h=0,
        suspicious_processes_last_24h=0,
        beaconing_detected=False,
        credential_dumping_detected=False,
        last_seen=datetime(2026, 4, 21, 18, 12, 19),
        first_seen=datetime(2025, 8, 8, 10, 3, 5),
        last_ip_address="10.112.0.125",
        last_external_ip_address="94.127.60.71",
        health_status="Active",
        device_value="Normal",
        rbac_group_name="TRS LAB",
        rbac_group_id=220,
        is_aad_joined=False,
        aad_device_id=None,
        onboarding_status="Onboarded",
        managed_by="MicrosoftDefenderForEndpoint",
        os_processor="x64",
        os_build=19045,
        os_architecture="64-bit",
        machine_tags_json=json.dumps([]),
        ip_addresses_json=json.dumps([
            {"ipAddress": "10.112.0.125", "macAddress": "005056A5BF63", "type": "Ethernet", "operationalStatus": "Up"},
            {"ipAddress": "fe80::be43:8b33:19f2:8c42", "macAddress": "005056A5BF63", "type": "Ethernet", "operationalStatus": "Up"},
            {"ipAddress": "127.0.0.1", "macAddress": None, "type": "SoftwareLoopback", "operationalStatus": "Up"},
            {"ipAddress": "::1", "macAddress": None, "type": "SoftwareLoopback", "operationalStatus": "Up"},
        ]),
        vm_metadata_json=None,
    ),
]

USER_CONTEXTS = [
    UserContext(
        user_id="USR-CHRISR",
        user_principal_name="chrisr@lab.local",
        display_name="Chris R.",
        tenant_id=TENANT_ID,
        account_enabled=True,
        risk_level="High",
        sign_in_risk_level="Medium",
        failed_logins_last_24h=0,
        impossible_travel_detected=False,
        mfa_enabled=False,
        privileged_roles_json=json.dumps(["Local Administrator"]),
        last_sign_in=datetime(2026, 4, 20, 14, 49, 51),
    ),
]

CAMPAIGN_CONTEXTS = []

MALWARE_ANALYSES = []

KQL_QUERIES = [
    # ---- Aikaantivm / winPEASx64.exe (alert dad50712b6-...) ----
    KQLQuery(
        query_name="winPEASx64.exe execution history",
        query_description="Find all executions of winPEASx64.exe on the affected device and its parent process chain.",
        kql_statement=(
            "DeviceProcessEvents\n"
            "| where DeviceName == 'chrisr-lab-ws08.lab.local'\n"
            "| where FileName == 'winPEASx64.exe' or InitiatingProcessFileName == 'winPEASx64.exe'\n"
            "| where Timestamp between (datetime(2026-04-20 14:00) .. datetime(2026-04-20 16:00))\n"
            "| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName, SHA256\n"
            "| sort by Timestamp asc"
        ),
        related_entity_type="alert",
        related_entity_id="dad50712b6-e83b-41c8-827e-8af5873236be_1",
        execution_timestamp=datetime(2026, 4, 20, 15, 30, 0),
        result_count=2,
        result_columns_json=json.dumps(["Timestamp", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName", "SHA256"]),
        result_rows_json=json.dumps([
            ["2026-04-20 15:03:06", "winPEASx64.exe", 'winPEASx64.exe', "chrisr", "powershell.exe", "a5e3ded4dff907d728cdb22d85f0ebfe65895189bc1b13983d6687d46476efe0"],
            ["2026-04-20 15:05:07", "winPEASx64.exe", 'winPEASx64.exe', "chrisr", "powershell.exe", "a5e3ded4dff907d728cdb22d85f0ebfe65895189bc1b13983d6687d46476efe0"],
        ]),
    ),
    KQLQuery(
        query_name="Files dropped to C:\\ProgramData\\legit",
        query_description="Identify all file creation events in the suspicious staging directory used to host winPEASx64.exe.",
        kql_statement=(
            "DeviceFileEvents\n"
            "| where DeviceName == 'chrisr-lab-ws08.lab.local'\n"
            r"| where FolderPath startswith @'C:\ProgramData\legit'" + "\n"
            "| where Timestamp between (datetime(2026-04-20 14:00) .. datetime(2026-04-20 16:00))\n"
            "| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, AccountName\n"
            "| sort by Timestamp asc"
        ),
        related_entity_type="alert",
        related_entity_id="dad50712b6-e83b-41c8-827e-8af5873236be_1",
        execution_timestamp=datetime(2026, 4, 20, 15, 35, 0),
        result_count=1,
        result_columns_json=json.dumps(["Timestamp", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName", "AccountName"]),
        result_rows_json=json.dumps([
            ["2026-04-20 15:02:50", "winPEASx64.exe", r"C:\ProgramData\legit", "a5e3ded4dff907d728cdb22d85f0ebfe65895189bc1b13983d6687d46476efe0", "powershell.exe", "chrisr"],
        ]),
    ),
    # ---- Mimikatz / lateral movement (alert da411feb4c-...) ----
    KQLQuery(
        query_name="mimikatz.exe process tree",
        query_description="Show the full process chain for mimikatz.exe to understand how it was launched and what it targeted.",
        kql_statement=(
            "DeviceProcessEvents\n"
            "| where DeviceName == 'chrisr-lab-ws08.lab.local'\n"
            "| where FileName in ('mimikatz.exe', 'lsass.exe', 'powershell.exe')\n"
            "| where Timestamp between (datetime(2026-04-20 14:00) .. datetime(2026-04-20 16:00))\n"
            "| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName, SHA256\n"
            "| sort by Timestamp asc"
        ),
        related_entity_type="alert",
        related_entity_id="da411feb4c-4ffd-4162-9d5d-f7799f1baf4b_1",
        execution_timestamp=datetime(2026, 4, 20, 15, 20, 0),
        result_count=3,
        result_columns_json=json.dumps(["Timestamp", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName", "SHA256"]),
        result_rows_json=json.dumps([
            ["2026-04-20 14:49:51", "mimikatz.exe", '"mimikatz.exe"', "chrisr", "powershell.exe", "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1"],
            ["2026-04-20 14:50:02", "lsass.exe", "lsass.exe", "SYSTEM", "wininit.exe", "055a1226a769948a79ed0972bdee2d91937c4b521e0b9046f9b8ccc63d110115"],
            ["2026-04-20 15:14:22", "mimikatz.exe", '"mimikatz.exe"', "chrisr", "powershell.exe", "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1"],
        ]),
    ),
    KQLQuery(
        query_name="chrisr lateral movement (Apr 20)",
        query_description="Identify network logon and remote execution events from chrisr on the day of the mimikatz detection.",
        kql_statement=(
            "IdentityLogonEvents\n"
            "| where AccountUpn == 'chrisr@lab.local'\n"
            "| where Timestamp between (datetime(2026-04-20 14:00) .. datetime(2026-04-20 17:00))\n"
            "| project Timestamp, DeviceName, DestinationDeviceName, LogonType, Protocol, ActionType\n"
            "| sort by Timestamp asc"
        ),
        related_entity_type="alert",
        related_entity_id="da411feb4c-4ffd-4162-9d5d-f7799f1baf4b_1",
        execution_timestamp=datetime(2026, 4, 20, 15, 25, 0),
        result_count=3,
        result_columns_json=json.dumps(["Timestamp", "DeviceName", "DestinationDeviceName", "LogonType", "Protocol", "ActionType"]),
        result_rows_json=json.dumps([
            ["2026-04-20 14:49:51", "chrisr-lab-ws08.lab.local", "chrisr-lab-ws08.lab.local", "Interactive", "Kerberos", "LogonSuccess"],
            ["2026-04-20 15:03:06", "chrisr-lab-ws08.lab.local", "chrisr-lab-ws08.lab.local", "Interactive", "Kerberos", "LogonSuccess"],
            ["2026-04-20 15:14:22", "chrisr-lab-ws08.lab.local", "chrisr-lab-ws08.lab.local", "Interactive", "Kerberos", "LogonSuccess"],
        ]),
    ),
]


def seed():
    init_db()
    with Session(engine) as session:
        # Only seed if the database is empty
        existing = session.exec(select(Incident)).first()
        if existing:
            print("Database already seeded, skipping.")
            return

        for incident in INCIDENTS:
            session.add(incident)
        for fi in FILE_INTELLIGENCE:
            session.add(fi)
        for dc in DEVICE_CONTEXTS:
            session.add(dc)
        for uc in USER_CONTEXTS:
            session.add(uc)
        for cc in CAMPAIGN_CONTEXTS:
            session.add(cc)
        for ma in MALWARE_ANALYSES:
            session.add(ma)
        for kql in KQL_QUERIES:
            session.add(kql)

        session.commit()
        print("Seed data inserted successfully.")


if __name__ == "__main__":
    seed()
