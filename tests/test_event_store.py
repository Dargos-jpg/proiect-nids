import sqlite3
from datetime import datetime

from nids.core.event import Event, Severity
from nids.storage.event_store import EventStore


def _event(source_ip: str = "10.0.0.1") -> Event:
    return Event(
        event_type="port scan",
        source_ip=source_ip,
        severity=Severity.MEDIUM,
        description="5 porturi distincte",
    )


def test_save_and_recent_round_trip(tmp_path):
    store = EventStore(tmp_path / "test.db")

    store.save(_event(), timestamp=datetime(2026, 1, 1, 12, 0, 0))

    rows = store.recent()
    assert len(rows) == 1
    assert rows[0].source_ip == "10.0.0.1"
    assert rows[0].event_type == "port scan"
    assert rows[0].severity == "medie"
    assert rows[0].timestamp == "2026-01-01T12:00:00"


def test_recent_returns_the_sqlite_row_id(tmp_path):
    """id-ul stabil (PRIMARY KEY) e necesar UI-ului (LogsPanel) ca sa
    poata pastra selectia corecta cand tabelul se reconstruieste la
    refresh - vezi bug real gasit de user"""
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))

    rows = store.recent()

    assert rows[0].id != rows[1].id
    assert all(row.id > 0 for row in rows)


def test_recent_orders_newest_first(tmp_path):
    store = EventStore(tmp_path / "test.db")

    store.save(_event("10.0.0.1"), timestamp=datetime(2026, 1, 1, 12, 0, 0))
    store.save(_event("10.0.0.2"), timestamp=datetime(2026, 1, 1, 12, 0, 1))

    rows = store.recent()
    assert [r.source_ip for r in rows] == ["10.0.0.2", "10.0.0.1"]


def test_recent_respects_limit(tmp_path):
    store = EventStore(tmp_path / "test.db")
    for _ in range(5):
        store.save(_event())

    assert len(store.recent(limit=3)) == 3


def test_persists_across_reopen(tmp_path):
    db_path = tmp_path / "test.db"
    store = EventStore(db_path)
    store.save(_event())
    store.close()

    reopened = EventStore(db_path)
    assert len(reopened.recent()) == 1


def test_distinct_sources(tmp_path):
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))
    store.save(_event("10.0.0.1"))

    assert store.distinct_sources() == ["10.0.0.1", "10.0.0.2"]


def test_events_for_source_is_chronological_and_filtered(tmp_path):
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"), timestamp=datetime(2026, 1, 1, 12, 0, 0))
    store.save(_event("10.0.0.2"), timestamp=datetime(2026, 1, 1, 12, 0, 1))
    store.save(_event("10.0.0.1"), timestamp=datetime(2026, 1, 1, 12, 0, 2))

    rows = store.events_for_source("10.0.0.1")

    assert len(rows) == 2
    assert rows[0].timestamp == "2026-01-01T12:00:00"
    assert rows[1].timestamp == "2026-01-01T12:00:02"


def test_events_for_source_unknown_returns_empty(tmp_path):
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))

    assert store.events_for_source("10.0.0.99") == []


def test_save_and_recent_round_trip_connection_identity(tmp_path):
    store = EventStore(tmp_path / "test.db")
    event = Event(
        event_type="anomalie noua",
        source_ip="10.0.0.1",
        severity=Severity.HIGH,
        description="test",
        dest_ip="10.0.0.2",
        src_port=5000,
        dest_port=443,
        protocol="tcp",
    )

    store.save(event)

    row = store.recent()[0]
    assert row.dest_ip == "10.0.0.2"
    assert row.src_port == 5000
    assert row.dest_port == 443
    assert row.protocol == "tcp"


def test_events_without_connection_identity_have_none_fields(tmp_path):
    store = EventStore(tmp_path / "test.db")
    store.save(_event())  # port scan - fara identitate de conexiune

    row = store.recent()[0]
    assert row.dest_ip is None
    assert row.src_port is None
    assert row.dest_port is None
    assert row.protocol is None


def test_migrates_old_schema_without_losing_existing_events(tmp_path):
    """simuleaza un fisier .db creat inainte de acest camp - trebuie sa
    ramana citibil, fara sa piarda evenimentele deja salvate de user"""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
        "event_type TEXT NOT NULL, source_ip TEXT NOT NULL, severity TEXT NOT NULL, "
        "description TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO events (timestamp, event_type, source_ip, severity, description) "
        "VALUES ('2026-01-01T12:00:00', 'port scan', '10.0.0.1', 'medie', 'vechi')"
    )
    conn.commit()
    conn.close()

    store = EventStore(db_path)

    rows = store.recent()
    assert len(rows) == 1
    assert rows[0].source_ip == "10.0.0.1"
    assert rows[0].dest_ip is None

    store.save(_event("10.0.0.2"))
    assert len(store.recent()) == 2
