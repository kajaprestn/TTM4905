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
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    microsoft_signature: Optional[str] = None
    quarantine_status: Optional[str] = None
    log_source: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
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

    # Alert classification (from alert API)
    classification: Optional[str] = None         # TruePositive/FalsePositive/Unknown
    determination: Optional[str] = None          # Malware/Phishing/CleanProcess/NotAvailable
    category: Optional[str] = None               # CredentialAccess/Execution/Discovery/etc.
    detection_source: Optional[str] = None       # MTP/AzureATP/CustomDetection/MDE
    threat_name: Optional[str] = None            # threatName (distinct from threatFamilyName)
    assigned_to: Optional[str] = None            # assignedTo

    # Alert timeline
    first_event_time: Optional[str] = None       # firstEventTime
    last_event_time: Optional[str] = None        # lastEventTime
    last_update_time: Optional[str] = None       # lastUpdateTime
    resolved_time: Optional[str] = None          # resolvedTime

    # Device identifiers
    machine_id: Optional[str] = None             # machineId
    rbac_group_name: Optional[str] = None        # rbacGroupName

    # Evidence: process chain
    parent_process_name: Optional[str] = None    # parentProcessFileName
    parent_process_path: Optional[str] = None    # parentProcessFilePath

    # Evidence: network/url
    evidence_url: Optional[str] = None           # url from evidence

    # Evidence: registry
    registry_key: Optional[str] = None
    registry_hive: Optional[str] = None
    registry_value: Optional[str] = None

    # Analyst comments from Defender
    comments_json: str = "[]"                    # comments[] array

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

    # MDE File API (clean_sha.json fields)
    sha1: Optional[str] = None
    md5: Optional[str] = None
    global_prevalence: Optional[int] = None       # globalPrevalence
    global_first_observed: Optional[str] = None   # globalFirstObserved
    global_last_observed: Optional[str] = None    # globalLastObserved
    file_size: Optional[int] = None               # size (bytes)
    file_type: Optional[str] = None               # fileType
    is_pe_file: Optional[bool] = None             # isPeFile
    file_publisher: Optional[str] = None          # filePublisher
    file_product_name: Optional[str] = None       # fileProductName
    signer: Optional[str] = None                  # signer
    issuer: Optional[str] = None                  # issuer
    is_valid_certificate: Optional[bool] = None   # isValidCertificate
    determination_type: Optional[str] = None      # determinationType (replaces ms_classification)
    determination_value: Optional[str] = None     # determinationValue (replaces ms_threat_family)
    org_prevalence: Optional[int] = None          # organizationPrevalence
    org_first_seen: Optional[str] = None          # orgFirstSeen
    org_last_seen: Optional[str] = None           # orgLastSeen
    top_file_names_json: str = "[]"               # topFileNames

    # Internal Sightings
    seen_before: Optional[str] = None
    first_seen_internally: Optional[str] = None
    last_seen_internally: Optional[str] = None
    number_of_affected_devices: Optional[str] = None
    affected_devices_json: str = "[]"
    total_internal_detections: Optional[str] = None

    # Cross-Customer Observations
    seen_across_customers: Optional[str] = None
    number_of_customer_environments: Optional[str] = None
    first_observed_across_customers: Optional[str] = None
    spike_detected_last_24h: Optional[str] = None
    campaign_likelihood: Optional[str] = None

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
            "mdeFileInfo": {
                "sha1": self.sha1,
                "md5": self.md5,
                "globalPrevalence": self.global_prevalence,
                "globalFirstObserved": self.global_first_observed,
                "globalLastObserved": self.global_last_observed,
                "fileSize": self.file_size,
                "fileType": self.file_type,
                "isPeFile": self.is_pe_file,
                "filePublisher": self.file_publisher,
                "fileProductName": self.file_product_name,
                "signer": self.signer,
                "issuer": self.issuer,
                "isValidCertificate": self.is_valid_certificate,
                "determinationType": self.determination_type,
                "determinationValue": self.determination_value,
                "orgPrevalence": self.org_prevalence,
                "orgFirstSeen": self.org_first_seen,
                "orgLastSeen": self.org_last_seen,
                "topFileNames": json.loads(self.top_file_names_json),
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

    last_logged_on_user: Optional[str] = None
    failed_logons_last_24h: Optional[int] = None
    suspicious_processes_last_24h: Optional[int] = None

    beaconing_detected: bool
    credential_dumping_detected: bool

    last_seen: datetime

    # From MDE Machine API (clean_machine.json)
    first_seen: Optional[datetime] = None          # firstSeen
    last_ip_address: Optional[str] = None          # lastIpAddress
    last_external_ip_address: Optional[str] = None # lastExternalIpAddress
    health_status: Optional[str] = None            # healthStatus (Active/Inactive/ImpairedCommunication)
    device_value: Optional[str] = None             # deviceValue (Normal/Low/High)
    rbac_group_name: Optional[str] = None          # rbacGroupName
    rbac_group_id: Optional[int] = None            # rbacGroupId
    is_aad_joined: Optional[bool] = None           # isAadJoined
    aad_device_id: Optional[str] = None            # aadDeviceId
    machine_tags_json: str = "[]"                  # machineTags
    onboarding_status: Optional[str] = None        # onboardingStatus
    managed_by: Optional[str] = None               # managedBy
    os_processor: Optional[str] = None             # osProcessor
    os_build: Optional[int] = None                 # osBuild
    os_architecture: Optional[str] = None          # osArchitecture
    ip_addresses_json: str = "[]"                  # ipAddresses[]
    vm_metadata_json: Optional[str] = None         # vmMetadata (JSON)


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
    file_hash: Optional[str] = Field(default=None, index=True)

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


class IpIntelligence(SQLModel, table=True):
    """MDE IP statistics from GET /api/ips/{ip}/stats (clean_ip.json)."""
    ip_address: str = Field(primary_key=True)
    org_prevalence: Optional[str] = None
    organization_prevalence: Optional[int] = None
    org_first_seen: Optional[str] = None
    org_last_seen: Optional[str] = None


class MachineAction(SQLModel, table=True):
    """MDE Machine Action from GET /api/machineactions (clean_machineActions.json)."""
    id: str = Field(primary_key=True)
    type: str                                      # Isolate / RunAntiVirusScan / etc.
    title: Optional[str] = None
    requestor: str
    requestor_comment: str
    status: str                                    # Pending/InProgress/Succeeded/Failed/Cancelled
    machine_id: str = Field(index=True)
    computer_dns_name: str
    creation_datetime_utc: str
    last_update_datetime_utc: str
    cancellation_requestor: Optional[str] = None
    cancellation_comment: Optional[str] = None
    cancellation_datetime_utc: Optional[str] = None
    error_h_result: Optional[int] = None
    scope: Optional[str] = None
    external_id: Optional[str] = None
    request_source: Optional[str] = None
    related_file_info_json: Optional[str] = None
    commands_json: str = "[]"
