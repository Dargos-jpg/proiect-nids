from PySide6.QtWidgets import QApplication

from nids.core.event import Severity
from nids.ui.widgets.traffic_chart import TrafficChartPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_record_packet_accumulates_into_current_second():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet()
    panel.record_packet()
    panel.record_packet()
    panel._tick()

    x, y = panel._curve.getData()
    assert list(y) == [3]
    assert list(x) == [0]


def test_multiple_ticks_accumulate_separate_seconds():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet()
    panel._tick()
    panel.record_packet()
    panel.record_packet()
    panel._tick()

    x, y = panel._curve.getData()
    assert list(y) == [1, 2]
    assert list(x) == [-1, 0]


def test_window_is_capped_at_60_seconds():
    _app()
    panel = TrafficChartPanel()

    for _ in range(70):
        panel.record_packet()
        panel._tick()

    x, y = panel._curve.getData()
    assert len(y) == 60


def test_record_event_creates_marker():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet()
    panel._tick()
    panel.record_event(Severity.HIGH)
    panel._redraw()

    data = panel._markers.data
    assert len(data) == 1


def test_event_evicted_after_window_expires():
    _app()
    panel = TrafficChartPanel()

    panel.record_event(Severity.HIGH)
    for _ in range(61):
        panel._tick()

    assert panel._events == []


def test_clear_resets_everything():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet()
    panel._tick()
    panel.record_event(Severity.MEDIUM)

    panel.clear()

    x, y = panel._curve.getData()
    assert x is None or len(x) == 0
    assert panel._events == []
