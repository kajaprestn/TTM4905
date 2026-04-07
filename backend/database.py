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
    }
    cur.execute("PRAGMA table_info(incident)")
    existing = {row[1] for row in cur.fetchall()}
    for col, col_type in incident_columns.items():
        if col not in existing:
            cur.execute(f"ALTER TABLE incident ADD COLUMN {col} {col_type}")

    conn.commit()
    conn.close()


def get_session():
    with Session(engine) as session:
        yield session
