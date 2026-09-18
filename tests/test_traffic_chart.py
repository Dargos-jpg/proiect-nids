from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QApplication

from nids.capture.packet_meta import PacketMeta
from nids.core.dns_lookup import AsnInfo, IpLookupResult
from nids.core.event import Severity
from nids.ui.widgets.traffic_chart import IpLookupResultsDialog, TrafficChartPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _packet(
    src_ip: str = "10.0.0.1", protocol: str = "tcp", length: int = 100
) -> PacketMeta:
    return PacketMeta(
        timestamp=0.0, src_ip=src_ip, dst_ip="10.0.0.2", protocol=protocol, length=length
    )


def test_record_packet_accumulates_into_current_second():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet(_packet())
    panel.record_packet(_packet())
    panel.record_packet(_packet())
    panel._tick()

    x, y = panel._curve.getData()
    assert list(y) == [3]
    assert list(x) == [0]


def test_multiple_ticks_accumulate_separate_seconds():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet(_packet())
    panel._tick()
    panel.record_packet(_packet())
    panel.record_packet(_packet())
    panel._tick()

    x, y = panel._curve.getData()
    assert list(y) == [1, 2]
    assert list(x) == [-1, 0]


def test_window_is_capped_at_60_seconds():
    _app()
    panel = TrafficChartPanel()

    for _ in range(70):
        panel.record_packet(_packet())
        panel._tick()

    x, y = panel._curve.getData()
    assert len(y) == 60


def test_record_event_creates_marker():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet(_packet())
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

    panel.record_packet(_packet())
    panel._tick()
    panel.record_event(Severity.MEDIUM)

    panel.clear()

    x, y = panel._curve.getData()
    assert x is None or len(x) == 0
    assert panel._events == []


# --- octeti/secunda ---


def test_bytes_per_second_accumulates_packet_lengths():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet(_packet(length=100))
    panel.record_packet(_packet(length=250))
    panel._tick()

    x, y = panel._bytes_curve.getData()
    assert list(y) == [350]


def test_clear_resets_bytes_per_second():
    _app()
    panel = TrafficChartPanel()
    panel.record_packet(_packet(length=100))
    panel._tick()

    panel.clear()

    x, y = panel._bytes_curve.getData()
    assert x is None or len(x) == 0


# --- distributie protocol ---


def test_protocol_counts_accumulate_across_session():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet(_packet(protocol="tcp"))
    panel.record_packet(_packet(protocol="tcp"))
    panel.record_packet(_packet(protocol="udp"))

    assert panel._protocol_counts == {"tcp": 2, "udp": 1}


def test_protocol_counts_survive_across_ticks_not_just_current_second():
    """spre deosebire de pachete/secunda, distributia pe protocol e
    CUMULATIVA pe toata sesiunea, nu o fereastra glisanta - nu trebuie sa
    dispara dupa un tick"""
    _app()
    panel = TrafficChartPanel()

    panel.record_packet(_packet(protocol="tcp"))
    panel._tick()
    panel.record_packet(_packet(protocol="udp"))
    panel._tick()

    assert panel._protocol_counts == {"tcp": 1, "udp": 1}


def test_clear_resets_protocol_counts():
    _app()
    panel = TrafficChartPanel()
    panel.record_packet(_packet(protocol="tcp"))

    panel.clear()

    assert panel._protocol_counts == {}


# --- top IP-uri sursa ---


def test_top_talkers_tracks_packet_count_per_source_ip():
    _app()
    panel = TrafficChartPanel()

    panel.record_packet(_packet(src_ip="10.0.0.1"))
    panel.record_packet(_packet(src_ip="10.0.0.1"))
    panel.record_packet(_packet(src_ip="10.0.0.9"))

    assert panel._src_ip_counts["10.0.0.1"] == 2
    assert panel._src_ip_counts["10.0.0.9"] == 1


def test_clear_resets_top_talkers():
    _app()
    panel = TrafficChartPanel()
    panel.record_packet(_packet(src_ip="10.0.0.1"))

    panel.clear()

    assert panel._src_ip_counts == {}


# --- selector de vederi ---


def test_view_selector_has_five_views():
    _app()
    panel = TrafficChartPanel()

    assert panel._view_selector.count() == 5


def test_switching_view_changes_visible_widget():
    _app()
    panel = TrafficChartPanel()

    panel._view_selector.setCurrentIndex(2)

    assert panel._stack.currentWidget() is panel._protocol_plot


def test_redraw_on_protocol_view_does_not_crash_when_empty():
    _app()
    panel = TrafficChartPanel()
    panel._view_selector.setCurrentIndex(2)

    panel._redraw()  # nu trebuie sa arunce cu 0 pachete inregistrate


def test_redraw_on_top_talkers_view_does_not_crash_when_empty():
    _app()
    panel = TrafficChartPanel()
    panel._view_selector.setCurrentIndex(3)

    panel._redraw()


# --- comparatie modele ---


def test_update_model_comparison_stores_both_count_dicts():
    _app()
    panel = TrafficChartPanel()

    panel.update_model_comparison({"ambele: atac": 3}, {"ambele: atac": 5})

    assert panel._old_agreement_counts == {"ambele: atac": 3}
    assert panel._modern_agreement_counts == {"ambele: atac": 5}


def test_clear_resets_model_comparison():
    _app()
    panel = TrafficChartPanel()
    panel.update_model_comparison({"ambele: atac": 3}, {"ambele: atac": 5})

    panel.clear()

    assert panel._old_agreement_counts == {}
    assert panel._modern_agreement_counts == {}


def test_redraw_on_comparison_view_does_not_crash_when_empty():
    _app()
    panel = TrafficChartPanel()
    panel._view_selector.setCurrentIndex(4)

    panel._redraw()


class _FakeReverseDnsThread(QThread):
    succeeded = Signal(dict)
    failed = Signal(str)

    def __init__(self, ips, parent=None) -> None:
        super().__init__(parent)
        self._ips = ips

    def run(self) -> None:
        self.succeeded.emit(
            {
                ip: IpLookupResult(hostname=f"host-{ip}.example.com", asn_info=None)
                for ip in self._ips
            }
        )


class _FakeFailingReverseDnsThread(QThread):
    succeeded = Signal(dict)
    failed = Signal(str)

    def __init__(self, ips, parent=None) -> None:
        super().__init__(parent)

    def run(self) -> None:
        self.failed.emit("eroare de retea")


def test_identify_button_does_nothing_without_talkers(monkeypatch):
    _app()
    panel = TrafficChartPanel()
    monkeypatch.setattr(
        "nids.ui.widgets.traffic_chart.ReverseDnsThread", _FakeReverseDnsThread
    )

    panel._on_identify_clicked()

    assert panel._dns_thread is None


def test_identify_button_resolves_top_talkers_and_shows_dialog(monkeypatch):
    _app()
    panel = TrafficChartPanel()
    panel.record_packet(_packet(src_ip="10.0.0.1"))
    monkeypatch.setattr(
        "nids.ui.widgets.traffic_chart.ReverseDnsThread", _FakeReverseDnsThread
    )
    monkeypatch.setattr(
        "nids.ui.widgets.traffic_chart.IpLookupResultsDialog.show", lambda self: None
    )

    panel._on_identify_clicked()
    panel._dns_thread.wait(2000)
    _app().processEvents()

    assert len(panel._lookup_dialogs) == 1
    assert panel._identify_button.isEnabled() is True
    panel._lookup_dialogs[0].close()


def test_identify_button_shows_error_message_on_failure(monkeypatch):
    _app()
    panel = TrafficChartPanel()
    panel.record_packet(_packet(src_ip="10.0.0.1"))
    monkeypatch.setattr(
        "nids.ui.widgets.traffic_chart.ReverseDnsThread", _FakeFailingReverseDnsThread
    )

    panel._on_identify_clicked()
    panel._dns_thread.wait(2000)
    _app().processEvents()

    assert "eroare" in panel._identify_button.text()


def test_redraw_on_comparison_view_with_data_does_not_crash():
    _app()
    panel = TrafficChartPanel()
    panel._view_selector.setCurrentIndex(4)

    panel.update_model_comparison(
        {"ambele: atac": 3, "doar expert": 1}, {"ambele: atac": 5, "doar local": 2}
    )


# --- IpLookupResultsDialog ---


def test_ip_lookup_dialog_shows_resolved_hostname():
    from PySide6.QtWidgets import QTableWidget

    _app()
    dialog = IpLookupResultsDialog(
        {"1.2.3.4": IpLookupResult(hostname="example.com", asn_info=None)}
    )

    table = dialog.findChild(QTableWidget)
    assert table.item(0, 0).text() == "1.2.3.4"
    assert table.item(0, 1).text() == "example.com"
    dialog.close()


def test_ip_lookup_dialog_shows_placeholder_for_unresolved_ip():
    from PySide6.QtWidgets import QTableWidget

    _app()
    dialog = IpLookupResultsDialog({"1.2.3.4": IpLookupResult(hostname=None, asn_info=None)})

    table = dialog.findChild(QTableWidget)
    assert table.item(0, 1).text() == "(fara inregistrare PTR)"
    dialog.close()


def test_ip_lookup_dialog_lists_all_ips():
    from PySide6.QtWidgets import QTableWidget

    _app()
    dialog = IpLookupResultsDialog(
        {
            "1.2.3.4": IpLookupResult(hostname="a.example.com", asn_info=None),
            "5.6.7.8": IpLookupResult(hostname=None, asn_info=None),
        }
    )

    table = dialog.findChild(QTableWidget)
    assert table.rowCount() == 2
    dialog.close()


def test_ip_lookup_dialog_shows_asn_info_when_available():
    from PySide6.QtWidgets import QTableWidget

    _app()
    dialog = IpLookupResultsDialog(
        {
            "8.8.8.8": IpLookupResult(
                hostname="dns.google",
                asn_info=AsnInfo(
                    asn="15169",
                    bgp_prefix="8.8.8.0/24",
                    country="US",
                    registry="arin",
                    organization="GOOGLE, US",
                ),
            )
        }
    )

    table = dialog.findChild(QTableWidget)
    assert table.item(0, 2).text() == "15169"
    assert table.item(0, 3).text() == "GOOGLE, US"
    assert table.item(0, 4).text() == "US"
    assert table.item(0, 5).text() == "8.8.8.0/24"
    dialog.close()


def test_ip_lookup_dialog_shows_placeholder_when_asn_info_missing():
    from PySide6.QtWidgets import QTableWidget

    _app()
    dialog = IpLookupResultsDialog({"1.2.3.4": IpLookupResult(hostname=None, asn_info=None)})

    table = dialog.findChild(QTableWidget)
    assert table.item(0, 2).text() == "-"
    assert table.item(0, 3).text() == "-"
    dialog.close()
