import time
from pathlib import Path

from PySide6.QtWidgets import QApplication

from nids.ml.local.learning import LocalModelManager
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore
from nids.ui.widgets.dashboard_panel import DashboardPanel
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel
from tests.factories import make_record


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _idle_capture(on_packet, interface=None, stop_event=None):
    while stop_event is not None and not stop_event.is_set():
        time.sleep(0.02)


def _wait_until(app: QApplication, condition, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert condition(), "conditia nu a fost indeplinita in timp util"


def _make_panel(tmp_path: Path, monkeypatch) -> DashboardPanel:
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


def test_shutdown_saves_active_local_model_before_closing(tmp_path, monkeypatch):
    """regresie: inchiderea ferestrei semnala thread-ul sa se opreasca,
    dar nu astepta - procesul putea muri inainte ca salvarea asincrona
    (declansata de semnalul finished) sa apuce sa ruleze, pierzand tot
    progresul modelului local. shutdown() trebuie sa astepte efectiv si
    sa salveze direct, nu sa se bazeze pe semnal"""
    app = _app()
    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", _idle_capture)

    state_path = tmp_path / "local_state.joblib"
    monkeypatch.setattr("nids.ml.local.learning.DEFAULT_STATE_PATH", state_path)

    panel = _make_panel(tmp_path, monkeypatch)
    panel._start_monitoring()

    # simuleaza un model local deja antrenat (fara sa astepte 50 de
    # conexiuni reale) - inlocuim direct managerul cu unul deja activ
    trained_manager = LocalModelManager(min_training_samples=3)
    for _ in range(3):
        trained_manager.process(make_record())
    assert trained_manager.is_learning is False
    panel._live_hybrid.local_manager = trained_manager

    panel.shutdown()

    assert state_path.exists(), "modelul local ar fi trebuit salvat sincron la shutdown()"
    restored = LocalModelManager.load(state_path)
    assert restored.is_learning is False
    assert restored.samples_collected == 3

    _wait_until(app, lambda: panel._thread is None)


def test_shutdown_without_active_local_model_does_not_write_file(tmp_path, monkeypatch):
    app = _app()
    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", _idle_capture)

    state_path = tmp_path / "local_state.joblib"
    monkeypatch.setattr("nids.ml.local.learning.DEFAULT_STATE_PATH", state_path)

    panel = _make_panel(tmp_path, monkeypatch)
    panel._start_monitoring()

    panel.shutdown()

    assert not state_path.exists()
    _wait_until(app, lambda: panel._thread is None)


def test_shutdown_without_monitoring_running_does_not_crash(tmp_path, monkeypatch):
    _app()
    panel = _make_panel(tmp_path, monkeypatch)

    panel.shutdown()  # nu trebuie sa crape daca nimic nu ruleaza
