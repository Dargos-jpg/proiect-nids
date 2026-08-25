import time
from pathlib import Path

from PySide6.QtWidgets import QApplication

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


def _make_panel(tmp_path: Path, monkeypatch) -> DashboardPanel:
    # altfel LocalModelManager.load_or_new() ar citi/scrie calea reala
    # de pe disc, facand testele nedeterministe intre rulari
    monkeypatch.setattr(
        "nids.ml.local.learning.DEFAULT_STATE_PATH", tmp_path / "local_state.joblib"
    )
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None),
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
    )


def _idle_capture(on_packet, interface=None, stop_event=None):
    while stop_event is not None and not stop_event.is_set():
        time.sleep(0.02)


def _wait_until(app: QApplication, condition, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert condition(), "conditia nu a fost indeplinita in timp util"


def test_simulate_without_monitoring_shows_hint(tmp_path, monkeypatch):
    _app()
    panel = _make_panel(tmp_path, monkeypatch)

    panel._on_simulate_clicked()

    assert "porneste monitorizarea" in panel._status_label.text()
    assert panel._simulation_thread is None


def test_simulate_while_monitoring_runs_and_updates_status(tmp_path, monkeypatch):
    app = _app()
    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", _idle_capture)
    monkeypatch.setattr(
        "nids.ui.simulation_thread.run_port_scan_simulation", lambda: "192.168.1.50"
    )

    panel = _make_panel(tmp_path, monkeypatch)
    panel._start_monitoring()

    panel._on_simulate_clicked()
    assert panel._simulate_button.isEnabled() is False

    _wait_until(app, lambda: panel._simulation_thread is None)

    assert "192.168.1.50" in panel._status_label.text()
    assert panel._simulate_button.isEnabled() is True

    panel._stop_monitoring()
    _wait_until(app, lambda: panel._thread is None)
