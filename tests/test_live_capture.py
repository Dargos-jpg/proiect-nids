import threading

from nids.capture.live_capture import capture_live
from nids.capture.packet_meta import PacketMeta


def test_capture_live_wires_prn_and_reports_ip_packets(monkeypatch):
    fake_ip_packet = _FakePacket(has_ip=True)
    fake_non_ip_packet = _FakePacket(has_ip=False)

    def fake_sniff(iface=None, prn=None, count=0, timeout=None, store=False):
        assert iface == "eth0"
        assert count == 2
        assert timeout == 5
        assert store is False
        prn(fake_ip_packet)
        prn(fake_non_ip_packet)

    monkeypatch.setattr("nids.capture.live_capture.sniff", fake_sniff)
    monkeypatch.setattr(
        "nids.capture.live_capture.extract_meta",
        lambda pkt: PacketMeta(
            timestamp=0.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="tcp",
            length=60,
        ),
    )

    received: list[PacketMeta] = []
    capture_live(received.append, interface="eth0", count=2, timeout=5)

    assert len(received) == 1
    assert received[0].src_ip == "10.0.0.1"


def test_capture_live_polls_until_stop_event_set(monkeypatch):
    calls: list[float | None] = []
    stop_event = threading.Event()

    def fake_sniff(iface=None, prn=None, timeout=None, store=False, stop_filter=None):
        calls.append(timeout)
        if len(calls) >= 2:
            stop_event.set()

    monkeypatch.setattr("nids.capture.live_capture.sniff", fake_sniff)

    capture_live(lambda pkt: None, stop_event=stop_event)

    assert len(calls) == 2
    assert calls[0] == 1.0


class _FakePacket:
    def __init__(self, has_ip: bool) -> None:
        self._has_ip = has_ip

    def __contains__(self, layer) -> bool:
        from scapy.all import IP

        return self._has_ip if layer is IP else False
