from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from nids.core.event import Event

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "nids.db"

# limita implicita de AFISARE (nu de stocare - nimic nu se sterge din DB
# niciodata, vezi jos). LogsPanel reconstruieste tabelul integral la
# fiecare 2s, deci un numar prea mare ar putea incepe sa incetineasca UI-ul
# dupa saptamani de utilizare - 2000 acopera generos utilizarea normala
# fara riscul asta. userul poate cere oricand mai mult explicit (ex: export)
DEFAULT_DISPLAY_LIMIT = 2000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL
)
"""

# coloane adaugate ulterior (identitatea conexiunii, pentru re-analiza ML
# din Loguri) - ALTER TABLE, nu recreare, ca sa nu pierdem istoricul deja
# salvat de utilizator pe disc (fisierul data/nids.db e local, nu e in git)
_NEW_COLUMNS: dict[str, str] = {
    "dest_ip": "TEXT",
    "src_port": "INTEGER",
    "dest_port": "INTEGER",
    "protocol": "TEXT",
    "assessment_json": "TEXT",
}

_SELECT_COLUMNS = (
    "timestamp, event_type, source_ip, severity, description, "
    "dest_ip, src_port, dest_port, protocol, assessment_json, id"
)


@dataclass
class StoredEvent:
    timestamp: str
    event_type: str
    source_ip: str
    severity: str
    description: str
    dest_ip: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    protocol: str | None = None
    assessment_json: str | None = None
    # id-ul din SQLite (PRIMARY KEY) - identitate stabila a randului,
    # folosita de LogsPanel ca sa poata pastra selectia corecta cand
    # tabelul se reconstruieste la refresh (vezi bug real gasit de user:
    # fara asta, selectia ramanea pe INDEXUL de rand, nu pe eveniment -
    # un eveniment nou aparut impingea totul cu un rand mai jos si
    # selectia "aluneca" pe alt eveniment). -1 = nesalvat inca/sintetic
    # (constructie directa in teste, nu vine din DB)
    id: int = -1


class EventStore:
    """persistenta evenimentelor + jurnal de audit (orice actiune,
    automata sau manuala - vezi CONTEXT-nids.md). SQLite, un singur
    fisier local, fara server. check_same_thread=False + lock propriu
    pentru ca poate fi scrisa atat din thread-ul UI cat si, ulterior,
    din alte thread-uri de fundal"""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        with self._lock:
            self._conn.execute(_SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        existing = {row[1] for row in self._conn.execute("PRAGMA table_info(events)").fetchall()}
        for name, sql_type in _NEW_COLUMNS.items():
            if name not in existing:
                self._conn.execute(f"ALTER TABLE events ADD COLUMN {name} {sql_type}")

    def save(self, event: Event, timestamp: datetime | None = None) -> None:
        timestamp = timestamp or datetime.now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO events "
                "(timestamp, event_type, source_ip, severity, description, "
                "dest_ip, src_port, dest_port, protocol, assessment_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    timestamp.isoformat(timespec="seconds"),
                    event.event_type,
                    event.source_ip,
                    event.severity.value,
                    event.description,
                    event.dest_ip,
                    event.src_port,
                    event.dest_port,
                    event.protocol,
                    event.assessment_json,
                ),
            )
            self._conn.commit()

    def recent(self, limit: int = DEFAULT_DISPLAY_LIMIT) -> list[StoredEvent]:
        with self._lock:
            cursor = self._conn.execute(
                f"SELECT {_SELECT_COLUMNS} FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
        return [StoredEvent(*row) for row in rows]

    def distinct_sources(self) -> list[str]:
        """toate IP-urile sursa care au cel putin un eveniment - pentru
        cronologia de incident (vezi CONTEXT-nids.md: "gruparea
        evenimentelor individuale intr-o naratiune temporala per IP")"""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT DISTINCT source_ip FROM events ORDER BY source_ip"
            )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def events_for_source(
        self, source_ip: str, limit: int = DEFAULT_DISPLAY_LIMIT
    ) -> list[StoredEvent]:
        """istoricul unei singure surse, in ordine CRONOLOGICA (cele mai
        vechi primele) - o naratiune, nu doar o lista plata de alerte"""
        with self._lock:
            cursor = self._conn.execute(
                f"SELECT {_SELECT_COLUMNS} FROM events WHERE source_ip = ? "
                "ORDER BY id ASC LIMIT ?",
                (source_ip, limit),
            )
            rows = cursor.fetchall()
        return [StoredEvent(*row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
