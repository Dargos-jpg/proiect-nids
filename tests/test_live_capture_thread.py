from PySide6.QtWidgets import QApplication

from nids.ui.live_capture_thread import LiveCaptureThread


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_thread_emits_packet_captured(monkeypatch):
    _app()

    def fake_capture_live(
        on_packet, on_arp=None, on_dns=None, on_payload=None, interface=None, stop_event=None
    ):
        on_packet("pkt1")
        on_packet("pkt2")

    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", fake_capture_live)

    thread = LiveCaptureThread()
    received = []
    thread.packet_captured.connect(received.append)

    thread.run()

    assert received == ["pkt1", "pkt2"]


def test_thread_emits_arp_frame_captured(monkeypatch):
    _app()

    def fake_capture_live(
        on_packet, on_arp=None, on_dns=None, on_payload=None, interface=None, stop_event=None
    ):
        on_arp("frame1")

    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", fake_capture_live)

    thread = LiveCaptureThread()
    received = []
    thread.arp_frame_captured.connect(received.append)

    thread.run()

    assert received == ["frame1"]


def test_thread_emits_dns_query_captured(monkeypatch):
    _app()

    def fake_capture_live(
        on_packet, on_arp=None, on_dns=None, on_payload=None, interface=None, stop_event=None
    ):
        on_dns("query1")

    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", fake_capture_live)

    thread = LiveCaptureThread()
    received = []
    thread.dns_query_captured.connect(received.append)

    thread.run()

    assert received == ["query1"]


def test_thread_emits_payload_sample_captured(monkeypatch):
    _app()

    def fake_capture_live(
        on_packet, on_arp=None, on_dns=None, on_payload=None, interface=None, stop_event=None
    ):
        on_payload("sample1")

    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", fake_capture_live)

    thread = LiveCaptureThread()
    received = []
    thread.payload_sample_captured.connect(received.append)

    thread.run()

    assert received == ["sample1"]


def test_thread_emits_error_on_exception(monkeypatch):
    _app()

    def fake_capture_live(
        on_packet, on_arp=None, on_dns=None, on_payload=None, interface=None, stop_event=None
    ):
        raise RuntimeError("boom")

    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", fake_capture_live)

    thread = LiveCaptureThread()
    errors = []
    thread.error.connect(errors.append)

    thread.run()

    assert errors == ["boom"]
