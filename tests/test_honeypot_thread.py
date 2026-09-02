from PySide6.QtWidgets import QApplication

from nids.honeypot.listener import HoneypotHit
from nids.ui.honeypot_thread import HoneypotThread


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_thread_emits_hit_detected(monkeypatch):
    _app()

    def fake_run_honeypot(ports, on_hit, on_bind_error, stop_event):
        on_hit(HoneypotHit(src_ip="1.2.3.4", src_port=1111, dst_port=2222, received_preview=""))

    monkeypatch.setattr("nids.ui.honeypot_thread.run_honeypot", fake_run_honeypot)

    thread = HoneypotThread([2222])
    received = []
    thread.hit_detected.connect(received.append)

    thread.run()

    assert len(received) == 1
    assert received[0].dst_port == 2222


def test_thread_emits_bind_error(monkeypatch):
    _app()

    def fake_run_honeypot(ports, on_hit, on_bind_error, stop_event):
        on_bind_error(2222, "port deja folosit")

    monkeypatch.setattr("nids.ui.honeypot_thread.run_honeypot", fake_run_honeypot)

    thread = HoneypotThread([2222])
    errors = []
    thread.bind_error.connect(lambda port, msg: errors.append((port, msg)))

    thread.run()

    assert errors == [(2222, "port deja folosit")]


def test_stop_sets_the_stop_event(monkeypatch):
    _app()
    seen_stop_events = []

    def fake_run_honeypot(ports, on_hit, on_bind_error, stop_event):
        seen_stop_events.append(stop_event)

    monkeypatch.setattr("nids.ui.honeypot_thread.run_honeypot", fake_run_honeypot)

    thread = HoneypotThread([2222])
    thread.run()
    thread.stop()

    assert seen_stop_events[0].is_set()
