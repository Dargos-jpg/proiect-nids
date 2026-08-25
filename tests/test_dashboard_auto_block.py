from PySide6.QtWidgets import QApplication

from nids.core.event import Event, Severity
from nids.core.ml_combination import BOTH_ATTACK_EVENT_TYPE
from nids.core.response_settings import ResponseSettings
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


def _make_panel(block_manager: BlockManager, tmp_path, settings: ResponseSettings) -> DashboardPanel:
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        block_manager,
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
        None,
        settings,
    )


def _both_attack_event(source_ip: str = "10.0.0.9") -> Event:
    return Event(
        event_type=BOTH_ATTACK_EVENT_TYPE,
        source_ip=source_ip,
        severity=Severity.HIGH,
        description="modelul expert si modelul local sunt de acord: atac",
        dest_ip="10.0.0.2",
        src_port=5000,
        dest_port=443,
        protocol="tcp",
        assessment_json='{"fake": "assessment"}',
    )


def _local_only_event(source_ip: str = "10.0.0.9") -> Event:
    return Event(
        event_type="anomalie noua (doar model local)",
        source_ip=source_ip,
        severity=Severity.HIGH,
        description="doar modelul local semnaleaza",
    )


def test_auto_block_disabled_by_default_does_not_block(tmp_path):
    _app()
    manager, added, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path, ResponseSettings())

    panel._maybe_auto_block(_both_attack_event())

    assert added == []
    assert not manager.is_blocked("10.0.0.9")


def test_auto_block_enabled_blocks_both_attack_event(tmp_path):
    _app()
    manager, added, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path, ResponseSettings(auto_block_enabled=True))

    panel._maybe_auto_block(_both_attack_event())

    assert added == ["10.0.0.9"]
    assert manager.is_blocked("10.0.0.9")


def test_auto_block_ignores_non_both_attack_events(tmp_path):
    """doar BOTH_ATTACK declanseaza blocare automata - un LOCAL_ONLY, chiar
    HIGH, nu e destul de sigur pentru actiune automata fara om in bucla"""
    _app()
    manager, added, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path, ResponseSettings(auto_block_enabled=True))

    panel._maybe_auto_block(_local_only_event())

    assert added == []
    assert not manager.is_blocked("10.0.0.9")


def test_auto_block_logs_audit_event_with_connection_identity(tmp_path):
    _app()
    manager, _, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path, ResponseSettings(auto_block_enabled=True))

    panel._maybe_auto_block(_both_attack_event())

    logged = panel._event_store.recent()[0]
    assert logged.event_type == "blocare automata"
    assert logged.source_ip == "10.0.0.9"
    assert logged.dest_ip == "10.0.0.2"
    assert logged.assessment_json == '{"fake": "assessment"}'


def test_auto_block_skips_already_blocked_ip_without_duplicate_log(tmp_path):
    """evita sa umple Loguri cu "blocare automata" la fiecare conexiune
    noua de la un IP deja blocat - block() e deja idempotent, dar fara
    verificarea is_blocked() am tot salva evenimente redundante"""
    _app()
    manager, added, _ = _fake_block_manager()
    panel = _make_panel(manager, tmp_path, ResponseSettings(auto_block_enabled=True))
    panel._maybe_auto_block(_both_attack_event())

    panel._maybe_auto_block(_both_attack_event())

    assert added == ["10.0.0.9"]  # add_rule apelat o singura data
    assert len(panel._event_store.recent()) == 1


def test_auto_block_handles_firewall_failure_without_crashing(tmp_path):
    _app()

    def failing_add_rule(ip: str) -> None:
        raise RuntimeError("netsh a refuzat")

    manager = BlockManager(add_rule=failing_add_rule, remove_rule=lambda ip: None)
    panel = _make_panel(manager, tmp_path, ResponseSettings(auto_block_enabled=True))

    panel._maybe_auto_block(_both_attack_event())  # nu trebuie sa arunce

    assert not manager.is_blocked("10.0.0.9")
    logged = panel._event_store.recent()[0]
    assert logged.event_type == "blocare automata esuata"


def test_auto_block_setting_read_live_mid_session(tmp_path):
    """spre deosebire de MlSettings, ResponseSettings.auto_block_enabled
    se citeste live la fiecare tick, nu doar la pornirea monitorizarii -
    userul poate porni/opri din Raspuns fara sa reporneasca sesiunea"""
    _app()
    manager, added, _ = _fake_block_manager()
    settings = ResponseSettings(auto_block_enabled=False)
    panel = _make_panel(manager, tmp_path, settings)

    panel._maybe_auto_block(_both_attack_event())
    assert added == []

    settings.auto_block_enabled = True
    panel._maybe_auto_block(_both_attack_event())

    assert added == ["10.0.0.9"]
