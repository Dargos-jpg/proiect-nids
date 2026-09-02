import time

from PySide6.QtWidgets import QApplication

from nids.honeypot.listener import HoneypotHit
from nids.storage.event_store import EventStore
from nids.ui.widgets.honeypot_panel import HoneypotPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _wait_until(app: QApplication, condition, timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert condition(), "conditia nu a fost indeplinita in timp util"


def test_ports_parses_comma_separated_list(tmp_path):
    _app()
    panel = HoneypotPanel(EventStore(tmp_path / "test.db"))

    panel._ports_edit.setText("2222, 8080,  3306")

    assert panel.ports() == [2222, 8080, 3306]


def test_ports_ignores_invalid_tokens(tmp_path):
    _app()
    panel = HoneypotPanel(EventStore(tmp_path / "test.db"))

    panel._ports_edit.setText("2222, abc, , 70000, 8080")

    assert panel.ports() == [2222, 8080]


def test_ports_empty_text_returns_empty_list(tmp_path):
    _app()
    panel = HoneypotPanel(EventStore(tmp_path / "test.db"))

    panel._ports_edit.setText("")

    assert panel.ports() == []


def test_start_with_no_valid_ports_shows_message_and_does_not_start(tmp_path):
    _app()
    panel = HoneypotPanel(EventStore(tmp_path / "test.db"))
    panel._ports_edit.setText("")

    panel._on_toggle_clicked()

    assert "port valid" in panel._status_label.text()
    assert panel._thread is None


def test_full_lifecycle_logs_hit_and_stops_cleanly(tmp_path, monkeypatch):
    """porneste (thread real, run_honeypot inlocuit) -> primeste un hit
    -> verifica ca ajunge in EventStore -> opreste curat"""
    app = _app()

    def fake_run_honeypot(ports, on_hit, on_bind_error, stop_event):
        on_hit(HoneypotHit(src_ip="1.2.3.4", src_port=1111, dst_port=2222, received_preview=""))
        while not stop_event.is_set():
            time.sleep(0.02)

    monkeypatch.setattr("nids.ui.honeypot_thread.run_honeypot", fake_run_honeypot)

    event_store = EventStore(tmp_path / "test.db")
    panel = HoneypotPanel(event_store)
    panel._ports_edit.setText("2222")

    panel._on_toggle_clicked()
    _wait_until(app, lambda: len(event_store.recent()) == 1)

    logged = event_store.recent()[0]
    assert logged.event_type == "conexiune la honeypot"
    assert logged.source_ip == "1.2.3.4"
    assert panel._toggle_button.text() == "Opreste honeypot"
    assert not panel._ports_edit.isEnabled()

    panel._on_toggle_clicked()
    _wait_until(app, lambda: panel._thread is None)

    assert panel._toggle_button.text() == "Porneste honeypot"
    assert panel._ports_edit.isEnabled()
    assert panel._status_label.text() == "honeypot oprit"


def test_bind_error_message_survives_thread_finishing(tmp_path, monkeypatch):
    """regresie: daca toate porturile esueaza la bind, thread-ul se
    termina aproape imediat - mesajul de eroare nu trebuie suprascris de
    genericul "honeypot oprit" """
    app = _app()

    def fake_run_honeypot(ports, on_hit, on_bind_error, stop_event):
        on_bind_error(2222, "port deja folosit")

    monkeypatch.setattr("nids.ui.honeypot_thread.run_honeypot", fake_run_honeypot)

    event_store = EventStore(tmp_path / "test.db")
    panel = HoneypotPanel(event_store)
    panel._ports_edit.setText("2222")

    panel._on_toggle_clicked()
    _wait_until(app, lambda: panel._thread is None)

    assert "port deja folosit" in panel._status_label.text()
