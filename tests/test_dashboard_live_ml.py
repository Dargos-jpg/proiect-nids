import time
from pathlib import Path

from PySide6.QtWidgets import QApplication

from nids.capture.packet_meta import PacketMeta
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


def _packet(dst_port: int) -> PacketMeta:
    return PacketMeta(
        timestamp=0.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="tcp",
        length=100,
        src_port=5000,
        dst_port=dst_port,
    )


def _idle_capture(on_packet, interface=None, stop_event=None):
    """nu genereaza pachete singura - testul le trimite manual prin
    _on_live_packet, doar sta pana e oprita, ca un thread real"""
    while stop_event is not None and not stop_event.is_set():
        time.sleep(0.02)


def _wait_until(app: QApplication, condition, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert condition(), "conditia nu a fost indeplinita in timp util"


def test_ml_tick_adds_event_to_dashboard(tmp_path, monkeypatch):
    """simuleaza o conexiune, forteaza predictia expert la 'atac' si
    verifica ca evaluarea ML periodica ajunge in lista din Dashboard,
    nu doar in logica interna a LiveHybridAnalyzer"""
    app = _app()
    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", _idle_capture)
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.core.live_hybrid.explain_connection", lambda expert, record: [])

    panel = _make_panel(tmp_path, monkeypatch)
    panel._expert_model = object()  # doar ca sa nu fie None

    panel._start_monitoring()
    panel._on_live_packet(_packet(80))
    panel._on_ml_evaluation_tick()

    assert panel._event_list.count() == 1
    assert "invata" in panel._event_list.item(0).text()
    assert len(panel._event_store.recent()) == 1

    panel._stop_monitoring()
    _wait_until(app, lambda: panel._thread is None)


def test_ml_status_reflects_learning_progress(tmp_path, monkeypatch):
    app = _app()
    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", _idle_capture)
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [0] * len(records),
    )

    panel = _make_panel(tmp_path, monkeypatch)
    panel._expert_model = object()

    assert panel.local_model_status() is None

    panel._start_monitoring()
    panel._on_live_packet(_packet(80))
    panel._on_ml_evaluation_tick()

    status = panel.local_model_status()
    assert status is not None
    assert status.is_learning is True
    assert status.samples_collected == 1

    panel._stop_monitoring()
    _wait_until(app, lambda: panel._thread is None)
