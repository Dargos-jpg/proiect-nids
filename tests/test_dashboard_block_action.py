from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from nids.core.event import Event, Severity
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore
from nids.ui.widgets.dashboard_panel import DashboardPanel
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _fake_block_manager() -> tuple[BlockManager, list, list]:
    added: list[str] = []
    removed: list[str] = []
    manager = BlockManager(add_rule=added.append, remove_rule=removed.append)
    return manager, added, removed


def _make_panel(block_manager: BlockManager, tmp_path) -> DashboardPanel:
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        block_manager, event_store, SignaturesPanel(), TrafficPanel(), LogsPanel(event_store)
    )


def _event(source_ip: str = "10.0.0.9") -> Event:
    return Event(
        event_type="port scan",
        source_ip=source_ip,
        severity=Severity.MEDIUM,
        description="test",
    )


def test_event_item_carries_event_data(tmp_path):
    _app()
    manager, _, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path)

    panel._show_events("fisier.pcap", [_event()])

    stored = panel._event_list.item(0).data(Qt.ItemDataRole.UserRole)
    assert stored.source_ip == "10.0.0.9"


def test_block_event_source_calls_block_manager(tmp_path):
    _app()
    manager, added, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path)

    panel._block_event_source(_event("10.0.0.9"))

    assert added == ["10.0.0.9"]
    assert manager.is_blocked("10.0.0.9")


def test_block_event_source_logs_audit_event(tmp_path):
    _app()
    manager, _, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path)

    panel._block_event_source(_event("10.0.0.9"))

    logged = panel._event_store.recent()
    assert len(logged) == 1
    assert logged[0].event_type == "blocare manuala"
    assert logged[0].source_ip == "10.0.0.9"


def test_block_event_source_carries_connection_identity_to_the_new_event(tmp_path):
    """regresie: userul a semnalat ca vrea sa poata analiza cu ML chiar
    din randul de "blocare manuala" din Loguri, nu doar din evenimentul
    original care a declansat blocarea - inainte, evenimentul nou de
    "blocare manuala" nu mostenea nimic din conexiunea originala"""
    _app()
    manager, _, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path)
    original = Event(
        event_type="anomalie noua",
        source_ip="10.0.0.9",
        severity=Severity.HIGH,
        description="test",
        dest_ip="10.0.0.2",
        src_port=5000,
        dest_port=443,
        protocol="tcp",
        assessment_json='{"fake": "assessment"}',
    )

    panel._block_event_source(original)

    logged = panel._event_store.recent()[0]
    assert logged.dest_ip == "10.0.0.2"
    assert logged.src_port == 5000
    assert logged.dest_port == 443
    assert logged.protocol == "tcp"
    assert logged.assessment_json == '{"fake": "assessment"}'


def test_block_event_source_handles_firewall_failure_without_crashing(tmp_path):
    """regresie: cand add_rule esueaza (ex: netsh fara drepturi de
    Administrator), CalledProcessError nu mai trebuie sa scape pana la
    slot-ul Qt si sa crape aplicatia - trebuie prins si afisat clar"""
    _app()

    def failing_add_rule(ip: str) -> None:
        raise RuntimeError("netsh a refuzat (fara drepturi de Administrator)")

    manager = BlockManager(add_rule=failing_add_rule, remove_rule=lambda ip: None)
    panel = _make_panel(manager, tmp_path)

    panel._block_event_source(_event("10.0.0.9"))  # nu trebuie sa arunce

    assert not manager.is_blocked("10.0.0.9")
    assert "Administrator" in panel._status_label.text()


def test_block_event_source_logs_failed_attempt(tmp_path):
    _app()

    def failing_add_rule(ip: str) -> None:
        raise RuntimeError("netsh a refuzat")

    manager = BlockManager(add_rule=failing_add_rule, remove_rule=lambda ip: None)
    panel = _make_panel(manager, tmp_path)

    panel._block_event_source(_event("10.0.0.9"))

    logged = panel._event_store.recent()
    assert len(logged) == 1
    assert logged[0].event_type == "blocare esuata"
    assert logged[0].source_ip == "10.0.0.9"
