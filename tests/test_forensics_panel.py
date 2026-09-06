from PySide6.QtWidgets import QApplication

from nids.capture.packet_meta import PacketMeta
from nids.capture.payload_meta import PayloadSample
from nids.ui.widgets.forensics_panel import (
    ConnectionTimelineDialog,
    ForensicsPanel,
    hex_dump,
    packets_for_connection,
)


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _packet(
    src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2", dst_port=80, protocol="tcp", ts=0.0, flags=None
) -> PacketMeta:
    return PacketMeta(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        length=100,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
    )


def _sample(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, payload=b"hello") -> PayloadSample:
    return PayloadSample(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, payload=payload)


# --- hex_dump ---


def test_hex_dump_empty_returns_placeholder():
    assert hex_dump(b"") == "(fara date)"


def test_hex_dump_includes_offset_hex_and_ascii():
    dump = hex_dump(b"ABC")

    assert "00000000" in dump
    assert "41 42 43" in dump
    assert "ABC" in dump


def test_hex_dump_replaces_non_printable_with_dot():
    dump = hex_dump(bytes([0, 1, 65]))

    assert dump.endswith("..A") or "..A" in dump


def test_hex_dump_wraps_at_given_width():
    dump = hex_dump(bytes(range(20)), width=16)

    assert len(dump.splitlines()) == 2


# --- packets_for_connection ---


def test_packets_for_connection_matches_both_directions():
    request = _packet(ts=1.0)
    response = _packet(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=1.5)
    unrelated = _packet(src_ip="10.0.0.9", dst_ip="10.0.0.8", ts=2.0)

    matches = packets_for_connection([request, response, unrelated], request)

    assert matches == [request, response]


def test_packets_for_connection_orders_chronologically():
    first = _packet(ts=1.0)
    second = _packet(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.5)

    matches = packets_for_connection([first, second], first)

    assert matches == [second, first]


def test_packets_for_connection_ignores_different_protocol():
    tcp_pkt = _packet(protocol="tcp")
    udp_pkt = _packet(protocol="udp")

    matches = packets_for_connection([tcp_pkt, udp_pkt], tcp_pkt)

    assert matches == [tcp_pkt]


def test_packets_for_connection_returns_empty_for_no_matches():
    reference = _packet()

    matches = packets_for_connection([], reference)

    assert matches == []


# --- ConnectionTimelineDialog (construction only, non-modal, never .exec()) ---


def test_connection_timeline_dialog_builds_without_showing():
    _app()
    request = _packet(ts=1.0)
    response = _packet(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=1.5)

    dialog = ConnectionTimelineDialog([request, response], request)

    assert "10.0.0.1:5000" in dialog.windowTitle()
    dialog.close()


# --- ForensicsPanel ---


def test_add_sample_inserts_newest_first():
    _app()
    panel = ForensicsPanel()

    panel.add_sample(_sample(src_ip="10.0.0.1"))
    panel.add_sample(_sample(src_ip="10.0.0.9"))

    assert panel._table.rowCount() == 2
    assert panel._table.item(0, 1).text() == "10.0.0.9"


def test_load_samples_replaces_table():
    _app()
    panel = ForensicsPanel()
    panel.add_sample(_sample(src_ip="10.0.0.1"))

    panel.load_samples([_sample(src_ip="10.0.0.5"), _sample(src_ip="10.0.0.6")])

    assert panel._table.rowCount() == 2
    assert panel._table.item(0, 1).text() == "10.0.0.6"


def test_clear_empties_table():
    _app()
    panel = ForensicsPanel()
    panel.add_sample(_sample())

    panel.clear()

    assert panel._table.rowCount() == 0


def test_sample_at_returns_stored_sample():
    _app()
    panel = ForensicsPanel()
    sample = _sample()
    panel.add_sample(sample)

    assert panel._sample_at(0) is sample
    assert panel._sample_at(-1) is None


def test_double_click_opens_hex_dump_dialog(monkeypatch):
    """la fel ca la ConnectionInspectorDialog/QMenu - nu lasam un dialog
    real sa apara pe ecran in timpul testelor, doar verificam ca a fost
    construit si adaugat la lista"""
    _app()
    monkeypatch.setattr(
        "nids.ui.widgets.forensics_panel.HexDumpDialog.show", lambda self: None
    )
    panel = ForensicsPanel()
    panel.add_sample(_sample())

    panel._open_hex_dump(panel._sample_at(0))

    assert len(panel._hex_dialogs) == 1
    panel._hex_dialogs[0].close()
