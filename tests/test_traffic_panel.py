from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication

from nids.capture.packet_meta import PacketMeta
from nids.ui.widgets.traffic_panel import TrafficPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _packet(src_ip: str = "10.0.0.1", dst_port: int = 80) -> PacketMeta:
    return PacketMeta(
        timestamp=1_700_000_000.0,
        src_ip=src_ip,
        dst_ip="10.0.0.2",
        protocol="tcp",
        length=120,
        src_port=5000,
        dst_port=dst_port,
    )


def test_add_packet_inserts_newest_first():
    _app()
    panel = TrafficPanel()

    panel.add_packet(_packet("10.0.0.1"))
    panel.add_packet(_packet("10.0.0.9"))

    assert panel._table.rowCount() == 2
    assert panel._table.item(0, 1).text() == "10.0.0.9"
    assert panel._table.item(1, 1).text() == "10.0.0.1"


def test_add_packet_caps_row_count():
    _app()
    panel = TrafficPanel()

    for _ in range(510):
        panel.add_packet(_packet())

    assert panel._table.rowCount() == 500


def test_load_packets_replaces_table():
    _app()
    panel = TrafficPanel()
    panel.add_packet(_packet("10.0.0.1"))

    panel.load_packets([_packet("10.0.0.5"), _packet("10.0.0.6")])

    assert panel._table.rowCount() == 2
    assert panel._table.item(0, 1).text() == "10.0.0.5"


def test_clear_empties_table():
    _app()
    panel = TrafficPanel()
    panel.add_packet(_packet())

    panel.clear()

    assert panel._table.rowCount() == 0


def test_row_item_carries_packet_data():
    _app()
    panel = TrafficPanel()
    pkt = _packet("10.0.0.7")

    panel.add_packet(pkt)

    stored = panel._table.item(0, 0).data(Qt.ItemDataRole.UserRole)
    assert stored is pkt


def test_packet_at_finds_packet_for_valid_row():
    _app()
    panel = TrafficPanel()
    pkt = _packet("10.0.0.7")
    panel.add_packet(pkt)

    row_center = panel._table.rowViewportPosition(0) + 5
    found = panel._packet_at(QPoint(5, row_center))

    assert found is pkt


def test_packet_at_returns_none_below_last_row():
    _app()
    panel = TrafficPanel()
    panel.add_packet(_packet())

    found = panel._packet_at(QPoint(5, 100_000))

    assert found is None


def test_filter_hides_non_matching_rows():
    _app()
    panel = TrafficPanel()
    panel.add_packet(_packet("10.0.0.1"))
    panel.add_packet(_packet("10.0.0.9"))

    panel._search_box.setText("10.0.0.9")

    assert panel._table.isRowHidden(0) is False  # 10.0.0.9, cel mai nou, randul 0
    assert panel._table.isRowHidden(1) is True  # 10.0.0.1, nu se potriveste


def test_filter_matches_any_column_not_just_source():
    _app()
    panel = TrafficPanel()
    panel.add_packet(_packet("10.0.0.1", dst_port=443))
    panel.add_packet(_packet("10.0.0.2", dst_port=8080))

    panel._search_box.setText("443")

    assert panel._table.isRowHidden(0) is True  # port 8080
    assert panel._table.isRowHidden(1) is False  # port 443


def test_clearing_filter_shows_all_rows_again():
    _app()
    panel = TrafficPanel()
    panel.add_packet(_packet("10.0.0.1"))
    panel.add_packet(_packet("10.0.0.9"))
    panel._search_box.setText("10.0.0.9")

    panel._search_box.setText("")

    assert all(not panel._table.isRowHidden(r) for r in range(panel._table.rowCount()))


def test_new_packet_respects_active_filter():
    _app()
    panel = TrafficPanel()
    panel.add_packet(_packet("10.0.0.1"))
    panel._search_box.setText("10.0.0.1")

    panel.add_packet(_packet("10.0.0.9"))

    assert panel._table.isRowHidden(0) is True  # 10.0.0.9, nou, nu se potriveste
    assert panel._table.isRowHidden(1) is False  # 10.0.0.1


def test_load_packets_applies_active_filter():
    _app()
    panel = TrafficPanel()
    panel._search_box.setText("10.0.0.5")

    panel.load_packets([_packet("10.0.0.5"), _packet("10.0.0.6")])

    assert panel._table.isRowHidden(0) is False
    assert panel._table.isRowHidden(1) is True


def test_analyze_requested_signal_carries_the_packet():
    """verifica doar contractul semnalului (folosit de DashboardPanel) -
    NU declanseaza QMenu.exec() real, care ar deschide un popup si ar
    bloca testul asteptand o interactiune care nu vine niciodata"""
    _app()
    panel = TrafficPanel()
    pkt = _packet("10.0.0.7")

    received = []
    panel.analyze_requested.connect(received.append)
    panel.analyze_requested.emit(pkt)

    assert received == [pkt]
