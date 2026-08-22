from nids.capture.packet_meta import PacketMeta
from nids.core.analysis import StreamAnalyzer


def _packet(dst_port: int) -> PacketMeta:
    return PacketMeta(
        timestamp=0.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="tcp",
        length=60,
        src_port=40000,
        dst_port=dst_port,
    )


def test_stream_analyzer_emits_new_event_once_threshold_crossed():
    analyzer = StreamAnalyzer(port_scan_threshold=3)

    updates = [analyzer.process_packet(_packet(p)) for p in (20, 21, 22)]

    assert updates[0] is None
    assert updates[1] is None
    assert updates[2] is not None
    assert updates[2].is_new is True
    assert updates[2].pair == ("10.0.0.1", "10.0.0.2")
    assert updates[2].event.source_ip == "10.0.0.1"


def test_stream_analyzer_updates_same_pair_on_new_port_instead_of_new_event():
    analyzer = StreamAnalyzer(port_scan_threshold=3)

    for p in (20, 21, 22):
        analyzer.process_packet(_packet(p))

    update = analyzer.process_packet(_packet(23))

    assert update is not None
    assert update.is_new is False
    assert "sesizat de 2 ori" in update.event.description


def test_stream_analyzer_ignores_repeat_of_already_seen_port():
    analyzer = StreamAnalyzer(port_scan_threshold=3)

    for p in (20, 21, 22):
        analyzer.process_packet(_packet(p))

    update = analyzer.process_packet(_packet(22))

    assert update is None


def test_stream_analyzer_ignores_traffic_below_threshold():
    analyzer = StreamAnalyzer(port_scan_threshold=5)

    update = analyzer.process_packet(_packet(20))

    assert update is None
