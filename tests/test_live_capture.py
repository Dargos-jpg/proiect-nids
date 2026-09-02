import threading

from nids.capture.arp_meta import ArpFrame
from nids.capture.live_capture import capture_live
from nids.capture.packet_meta import PacketMeta
from nids.capture.payload_meta import PayloadSample


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


def test_capture_live_reports_arp_frames_via_on_arp(monkeypatch):
    fake_arp_packet = _FakePacket(has_arp=True)
    fake_ip_packet = _FakePacket(has_ip=True)

    def fake_sniff(iface=None, prn=None, count=0, timeout=None, store=False):
        prn(fake_arp_packet)
        prn(fake_ip_packet)

    monkeypatch.setattr("nids.capture.live_capture.sniff", fake_sniff)
    monkeypatch.setattr(
        "nids.capture.live_capture.extract_meta",
        lambda pkt: PacketMeta(
            timestamp=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="tcp", length=60
        ),
    )
    monkeypatch.setattr(
        "nids.capture.live_capture.extract_arp_frame",
        lambda pkt: ArpFrame(
            timestamp=0.0, sender_ip="10.0.0.9", sender_mac="aa:bb", target_ip="10.0.0.1", is_reply=True
        ),
    )

    ip_received: list[PacketMeta] = []
    arp_received: list[ArpFrame] = []
    capture_live(ip_received.append, on_arp=arp_received.append)

    assert len(arp_received) == 1
    assert arp_received[0].sender_ip == "10.0.0.9"
    assert len(ip_received) == 1


def test_capture_live_without_on_arp_ignores_arp_frames(monkeypatch):
    fake_arp_packet = _FakePacket(has_arp=True)

    def fake_sniff(iface=None, prn=None, count=0, timeout=None, store=False):
        prn(fake_arp_packet)

    monkeypatch.setattr("nids.capture.live_capture.sniff", fake_sniff)

    capture_live(lambda pkt: None)  # nu trebuie sa arunce, desi nu s-a dat on_arp


def test_capture_live_reports_payload_samples_via_on_payload(monkeypatch):
    fake_ip_packet = _FakePacket(has_ip=True)

    def fake_sniff(iface=None, prn=None, count=0, timeout=None, store=False):
        prn(fake_ip_packet)

    monkeypatch.setattr("nids.capture.live_capture.sniff", fake_sniff)
    monkeypatch.setattr(
        "nids.capture.live_capture.extract_meta",
        lambda pkt: PacketMeta(
            timestamp=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="tcp", length=60
        ),
    )
    monkeypatch.setattr(
        "nids.capture.live_capture.extract_payload_sample",
        lambda pkt: PayloadSample(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, payload=b"data"
        ),
    )

    payload_received: list[PayloadSample] = []
    capture_live(lambda pkt: None, on_payload=payload_received.append)

    assert len(payload_received) == 1
    assert payload_received[0].payload == b"data"


def test_capture_live_without_on_payload_does_not_call_extract(monkeypatch):
    fake_ip_packet = _FakePacket(has_ip=True)

    def fake_sniff(iface=None, prn=None, count=0, timeout=None, store=False):
        prn(fake_ip_packet)

    monkeypatch.setattr("nids.capture.live_capture.sniff", fake_sniff)
    monkeypatch.setattr(
        "nids.capture.live_capture.extract_meta",
        lambda pkt: PacketMeta(
            timestamp=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="tcp", length=60
        ),
    )

    capture_live(lambda pkt: None)  # nu trebuie sa arunce, desi nu s-a dat on_payload


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
    def __init__(self, has_ip: bool = False, has_arp: bool = False) -> None:
        self._has_ip = has_ip
        self._has_arp = has_arp

    def __contains__(self, layer) -> bool:
        from scapy.all import ARP, IP

        if layer is IP:
            return self._has_ip
        if layer is ARP:
            return self._has_arp
        return False
