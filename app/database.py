import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "tracemail.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_sub TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            name TEXT,
            picture TEXT,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def upsert_user(google_sub, email, name, picture):
    conn = get_connection()
    existing = conn.execute(
        "SELECT id, role FROM users WHERE google_sub = ?",
        (google_sub,),
    ).fetchone()

    if existing:
        conn.execute(
            """UPDATE users
               SET email=?, name=?, picture=?, last_login=CURRENT_TIMESTAMP
               WHERE google_sub=?""",
            (email, name, picture, google_sub),
        )
        user_id = existing["id"]
        role = existing["role"]
    else:
        conn.execute(
            """INSERT INTO users
               (google_sub, email, name, picture, role)
               VALUES (?, ?, ?, ?, 'viewer')""",
            (google_sub, email, name, picture),
        )
        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        role = "viewer"

    conn.commit()
    conn.close()
    return {"id": user_id, "google_sub": google_sub, "email": email,
            "name": name, "picture": picture, "role": role}

def get_user_by_id(user_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT id, email, name, picture, role FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None
