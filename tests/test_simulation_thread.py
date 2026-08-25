from PySide6.QtWidgets import QApplication

from nids.ui.simulation_thread import SimulationThread


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_thread_emits_finished_ok(monkeypatch):
    _app()
    monkeypatch.setattr(
        "nids.ui.simulation_thread.run_port_scan_simulation", lambda: "192.168.1.5"
    )

    thread = SimulationThread()
    results = []
    thread.finished_ok.connect(results.append)

    thread.run()

    assert results == ["192.168.1.5"]


def test_thread_emits_error_on_exception(monkeypatch):
    _app()

    def raise_error():
        raise RuntimeError("boom")

    monkeypatch.setattr("nids.ui.simulation_thread.run_port_scan_simulation", raise_error)

    thread = SimulationThread()
    errors = []
    thread.error.connect(errors.append)

    thread.run()

    assert errors == ["boom"]
