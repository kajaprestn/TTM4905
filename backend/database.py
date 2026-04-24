import sqlite3
from sqlmodel import SQLModel, create_engine, Session

DATABASE_URL = "sqlite:///alerts.db"
engine = create_engine(DATABASE_URL)


def init_db():
    SQLModel.metadata.create_all(engine)


def migrate_db():
    """Safely add any new columns to existing tables without losing data."""
    conn = sqlite3.connect("alerts.db")
    cur = conn.cursor()

    # New columns added to the incident table
    incident_columns = {
        "tenant_id": "TEXT",
        "mde_alert_id": "TEXT",
        "mde_incident_id": "TEXT",
        "description": "TEXT",
        "mitre_techniques_json": "TEXT DEFAULT '[]'",
        "classification": "TEXT",
        "determination": "TEXT",
        "category": "TEXT",
        "detection_source": "TEXT",
        "threat_name": "TEXT",
        "assigned_to": "TEXT",
        "first_event_time": "TEXT",
        "last_event_time": "TEXT",
        "last_update_time": "TEXT",
        "resolved_time": "TEXT",
        "machine_id": "TEXT",
        "rbac_group_name": "TEXT",
        "parent_process_name": "TEXT",
        "parent_process_path": "TEXT",
        "evidence_url": "TEXT",
        "registry_key": "TEXT",
        "registry_hive": "TEXT",
        "registry_value": "TEXT",
        "comments_json": "TEXT DEFAULT '[]'",
    }
    cur.execute("PRAGMA table_info(incident)")
    existing = {row[1] for row in cur.fetchall()}
    for col, col_type in incident_columns.items():
        if col not in existing:
            cur.execute(f"ALTER TABLE incident ADD COLUMN {col} {col_type}")

    # New columns added to the fileintelligence table
    fi_columns = {
        "sha1": "TEXT",
        "md5": "TEXT",
        "global_prevalence": "INTEGER",
        "global_first_observed": "TEXT",
        "global_last_observed": "TEXT",
        "file_size": "INTEGER",
        "file_type": "TEXT",
        "is_pe_file": "INTEGER",
        "file_publisher": "TEXT",
        "file_product_name": "TEXT",
        "signer": "TEXT",
        "issuer": "TEXT",
        "is_valid_certificate": "INTEGER",
        "determination_type": "TEXT",
        "determination_value": "TEXT",
        "org_prevalence": "INTEGER",
        "org_first_seen": "TEXT",
        "org_last_seen": "TEXT",
        "top_file_names_json": "TEXT DEFAULT '[]'",
    }
    cur.execute("PRAGMA table_info(fileintelligence)")
    existing_fi = {row[1] for row in cur.fetchall()}
    for col, col_type in fi_columns.items():
        if col not in existing_fi:
            cur.execute(f"ALTER TABLE fileintelligence ADD COLUMN {col} {col_type}")

    # New columns added to the devicecontext table
    dc_columns = {
        "first_seen": "TEXT",
        "last_ip_address": "TEXT",
        "last_external_ip_address": "TEXT",
        "health_status": "TEXT",
        "device_value": "TEXT",
        "rbac_group_name": "TEXT",
        "rbac_group_id": "INTEGER",
        "is_aad_joined": "INTEGER",
        "aad_device_id": "TEXT",
        "machine_tags_json": "TEXT DEFAULT '[]'",
        "onboarding_status": "TEXT",
        "managed_by": "TEXT",
        "os_processor": "TEXT",
        "os_build": "INTEGER",
        "os_architecture": "TEXT",
        "ip_addresses_json": "TEXT DEFAULT '[]'",
        "vm_metadata_json": "TEXT",
    }
    cur.execute("PRAGMA table_info(devicecontext)")
    existing_dc = {row[1] for row in cur.fetchall()}
    for col, col_type in dc_columns.items():
        if col not in existing_dc:
            cur.execute(f"ALTER TABLE devicecontext ADD COLUMN {col} {col_type}")

    conn.commit()
    conn.close()


def get_session():
    with Session(engine) as session:
        yield session
