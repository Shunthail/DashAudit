import json
import sqlite3
from pathlib import Path
from contextlib import closing

DATABASE = Path(__file__).parent / "data" / "audits.sqlite3"


def connect():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS audits (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)"
    )
    return connection


def list_audits():
    with closing(connect()) as connection:
        return [
            dict(json.loads(payload), id=identifier)
            for identifier, payload in connection.execute(
                "SELECT id, payload FROM audits ORDER BY id DESC"
            )
        ]


def save_audit(audit):
    with closing(connect()) as connection:
        cursor = connection.execute(
            "INSERT INTO audits (payload) VALUES (?)", (json.dumps(audit),)
        )
        connection.commit()
        return dict(audit, id=cursor.lastrowid)
