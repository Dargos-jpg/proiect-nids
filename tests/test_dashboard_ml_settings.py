import time

from PySide6.QtWidgets import QApplication

from nids.core.ml_settings import MlSettings
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


def _fake_block_manager() -> BlockManager:
    return BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None)


def _fake_capture_live(on_packet, interface=None, stop_event=None):
    while stop_event is not None and not stop_event.is_set():
        time.sleep(0.02)


def _wait_until(app: QApplication, condition, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert condition(), "conditia nu a fost indeplinita in timp util"


def _make_panel(tmp_path, monkeypatch, settings: MlSettings) -> DashboardPanel:
    monkeypatch.setattr(
        "nids.ml.local.learning.DEFAULT_STATE_PATH", tmp_path / "local_state.joblib"
    )
    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", _fake_capture_live)
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        _fake_block_manager(),
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
        settings,
    )


def test_start_monitoring_applies_configured_ml_settings(tmp_path, monkeypatch):
    """DashboardPanel._start_monitoring() citeste MlSettings-ul curent
    (setat din MlPanel) - la fel cum citeste pragul de port scan din
    SignaturesPanel. verifica firul complet, nu doar transmiterea izolata
    a fiecarui parametru"""
    app = _app()
    settings = MlSettings(
        min_training_samples=77,
        retrain_every=13,
        max_buffer_size=444,
        contamination=0.15,
        n_estimators=50,
        strict_reporting=True,
        evaluation_interval_ms=2000,
    )
    panel = _make_panel(tmp_path, monkeypatch, settings)

    panel._start_monitoring()

    assert panel._live_hybrid._strict_reporting is True
    manager = panel._live_hybrid.local_manager
    assert manager._min_training_samples == 77
    assert manager._retrain_every == 13
    assert manager._max_buffer_size == 444
    assert manager._contamination == 0.15
    assert manager._n_estimators == 50
    assert panel._ml_timer.interval() == 2000

    panel._stop_monitoring()
    _wait_until(app, lambda: panel._thread is None)


def test_start_monitoring_with_default_settings_matches_previous_behavior(tmp_path, monkeypatch):
    app = _app()
    panel = _make_panel(tmp_path, monkeypatch, MlSettings())

    panel._start_monitoring()

    assert panel._live_hybrid._strict_reporting is False
    manager = panel._live_hybrid.local_manager
    assert manager._contamination is None
    assert manager._n_estimators == 100
    assert panel._ml_timer.interval() == 5000

    panel._stop_monitoring()
    _wait_until(app, lambda: panel._thread is None)
