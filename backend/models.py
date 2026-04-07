from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
import json


class Tenant(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True, unique=True)   # Azure AD tenant GUID
    display_name: str
    client_id: Optional[str] = None       # If None, falls back to AZURE_CLIENT_ID env var
    client_secret: Optional[str] = None   # If None, falls back to AZURE_CLIENT_SECRET env var
    is_active: bool = True
    last_synced_at: Optional[datetime] = None


class Incident(SQLModel, table=True):
    id: str = Field(primary_key=True)
    title: str
    detection_timestamp: str
    severity: str
    device_name: str
    user: str
    file_name: str
    file_hash: str
    microsoft_signature: str
    quarantine_status: str
    log_source: str
    source_ip: str
    destination_ip: str
    status: str = "Open"
    logs_json: str = "[]"
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    # MDE / multi-tenant fields (optional for backward compat with seed data)
    tenant_id: Optional[str] = None
    mde_alert_id: Optional[str] = None
    mde_incident_id: Optional[str] = None
    description: Optional[str] = None
    mitre_techniques_json: str = "[]"

    @property
    def logs(self) -> list[str]:
        return json.loads(self.logs_json)


class FileIntelligence(SQLModel, table=True):

    file_hash: str = Field(primary_key=True)

    # VirusTotal
    vt_detection_ratio: Optional[str] = None
    vt_first_submission: Optional[str] = None
    vt_last_analysis: Optional[str] = None
    vt_file_type: Optional[str] = None
    vt_popular_threat_labels_json: str = "[]"
    vt_reputation_score: Optional[str] = None
    vt_meaningful_name: Optional[str] = None
    vt_tags_json: str = "[]"

    # Microsoft Reputation
    ms_classification: str
    ms_threat_family: str
    ms_prevalence: str
    ms_global_detection_level: str
    ms_cloud_protection_level: str

    # Internal Sightings
    seen_before: str
    first_seen_internally: str
    last_seen_internally: str
    number_of_affected_devices: str
    affected_devices_json: str = "[]"
    total_internal_detections: str

    # Cross-Customer Observations
    seen_across_customers: str
    number_of_customer_environments: str
    first_observed_across_customers: str
    spike_detected_last_24h: str
    campaign_likelihood: str

    # Detection Frequency
    df_classification: str
    df_threat_family: str
    df_prevalence: str
    df_global_detection_level: str
    df_cloud_protection_level: str

    def to_api_response(self) -> dict:
        return {
            "fileHash": self.file_hash,
            "virusTotal": {
                "detectionRatio": self.vt_detection_ratio,
                "firstSubmission": self.vt_first_submission,
                "lastAnalysis": self.vt_last_analysis,
                "fileType": self.vt_file_type,
                "popularThreatLabels": json.loads(self.vt_popular_threat_labels_json),
                "reputationScore": self.vt_reputation_score,
                "meaningfulName": self.vt_meaningful_name,
                "tags": json.loads(self.vt_tags_json),
            },
            "microsoftReputation": {
                "classification": self.ms_classification,
                "threatFamily": self.ms_threat_family,
                "prevalence": self.ms_prevalence,
                "globalDetectionLevel": self.ms_global_detection_level,
                "cloudProtectionLevel": self.ms_cloud_protection_level,
            },
            "internalSightings": {
                "seenBefore": self.seen_before,
                "firstSeenInternally": self.first_seen_internally,
                "lastSeenInternally": self.last_seen_internally,
                "numberOfAffectedDevices": self.number_of_affected_devices,
                "affectedDevices": json.loads(self.affected_devices_json),
                "totalInternalDetections": self.total_internal_detections,
            },
            "crossCustomerObservations": {
                "seenAcrossMultipleCustomers": self.seen_across_customers,
                "numberOfCustomerEnvironments": self.number_of_customer_environments,
                "firstObservedAcrossCustomers": self.first_observed_across_customers,
                "spikeDetectedInLast24Hours": self.spike_detected_last_24h,
                "campaignLikelihood": self.campaign_likelihood,
            },
            "detectionFrequency": {
                "classification": self.df_classification,
                "threatFamily": self.df_threat_family,
                "prevalence": self.df_prevalence,
                "globalDetectionLevel": self.df_global_detection_level,
                "cloudProtectionLevel": self.df_cloud_protection_level,
            },
        }


class DeviceContext(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    device_id: str = Field(index=True, unique=True)
    device_name: str
    tenant_id: str

    os_platform: str
    os_version: str
    device_type: str

    risk_level: str
    exposure_level: str

    last_logged_on_user: str
    failed_logons_last_24h: int
    suspicious_processes_last_24h: int

    beaconing_detected: bool
    credential_dumping_detected: bool

    last_seen: datetime


class UserContext(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    user_id: str = Field(index=True, unique=True)
    user_principal_name: str
    display_name: str
    tenant_id: str

    account_enabled: bool
    risk_level: str
    sign_in_risk_level: str

    failed_logins_last_24h: int
    impossible_travel_detected: bool
    mfa_enabled: bool

    privileged_roles_json: str = "[]"

    last_sign_in: datetime


class CampaignContext(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    campaign_id: str = Field(index=True, unique=True)

    campaign_likelihood: str
    spike_detected_last_24h: bool

    number_of_affected_devices: int
    number_of_affected_users: int
    number_of_customer_environments: int

    first_observed: datetime
    last_observed: datetime

    related_hashes_json: str = "[]"
    related_ips_json: str = "[]"
    related_techniques_json: str = "[]"


class MalwareAnalysis(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    file_hash: str = Field(index=True)

    sandbox_score: str
    behavior_summary: str

    processes_spawned_json: str = "[]"
    registry_changes_json: str = "[]"
    network_connections_json: str = "[]"

    persistence_detected: bool
    credential_access_detected: bool
    command_and_control_detected: bool

    analysis_timestamp: datetime


class KQLQuery(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    query_name: str
    query_description: str

    kql_statement: str

    related_entity_type: str  # file / device / user / network
    related_entity_id: str

    execution_timestamp: datetime
    result_count: int

    result_columns_json: str = "[]"
    result_rows_json: str = "[]"
