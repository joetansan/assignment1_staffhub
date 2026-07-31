import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from werkzeug.security import generate_password_hash

from config import DATABASE_PATH


def connect_db() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def reset_database() -> None:
    if DATABASE_PATH.exists():
        DATABASE_PATH.unlink()

    conn = connect_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL,
            department TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            department TEXT NOT NULL,
            actor_username TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    password_hash = generate_password_hash("Password123!")

    users = [
        ("alice", password_hash, "Alice Tan", "Employee", "alice.tan@example.edu", "HR"),
        ("ben", password_hash, "Ben Lim", "Employee", "ben.lim@example.edu", "IT"),
        ("maya", password_hash, "Maya Wong", "Manager", "maya.wong@example.edu", "IT"),
        ("mina", password_hash, "Mina Koh", "Manager", "mina.koh@example.edu", "HR"),
        ("adam", password_hash, "Adam Lee", "Admin", "adam.lee@example.edu", "Corporate"),
    ]

    cur.executemany(
        """
        INSERT INTO users (username, password_hash, full_name, role, email, department)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        users,
    )

    now = datetime.now().replace(microsecond=0)
    records = [
        (1, "Laptop replacement request", "IT Support", "My staff laptop battery drains quickly.", "Medium", "Open", now - timedelta(days=8)),
        (2, "Projector issue in seminar room", "Facilities", "The projector in Room B-204 flickers during lessons.", "High", "Open", now - timedelta(days=6)),
        (2, "VPN access problem", "IT Support", "I cannot access the internal VPN after password reset.", "High", "Pending Review", now - timedelta(days=4)),
        (1, "Payroll enquiry", "HR", "I need clarification on an allowance entry.", "Low", "Closed", now - timedelta(days=3)),
    ]

    for owner_id, title, category, description, priority, status, created_at in records:
        created = created_at.isoformat(sep=" ")
        cur.execute(
            """
            INSERT INTO records (owner_id, title, category, description, priority, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (owner_id, title, category, description, priority, status, created, created),
        )

    audit_events = [
        ("LOGIN", "Info", "IT", "ben", "User logged in successfully.", now - timedelta(days=3, hours=2)),
        ("INVALID_INPUT", "Warning", "HR", "alice", "Record submission rejected due to invalid input.", now - timedelta(days=2, hours=5)),
        ("RESTRICTED_ACTION", "Warning", "IT", "ben", "Restricted action attempted on a protected workflow.", now - timedelta(days=1, hours=3)),
        ("ADMIN_ACTION", "Info", "Corporate", "adam", "Administrative maintenance action completed.", now - timedelta(hours=9)),
        ("ACCESS_DENIED", "Warning", "HR", "alice", "Access to a protected management area was denied.", now - timedelta(hours=2)),
    ]

    cur.executemany(
        """
        INSERT INTO audit_events (event_type, severity, department, actor_username, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (event_type, severity, department, actor_username, message, created_at.isoformat(sep=" "))
            for event_type, severity, department, actor_username, message, created_at in audit_events
        ],
    )

    conn.commit()
    conn.close()
    print(f"Database initialised at {DATABASE_PATH}")


if __name__ == "__main__":
    reset_database()
