from scapy.all import ARP, Ether

from nids.capture.arp_meta import extract_arp_frame


def _arp_packet(psrc: str, hwsrc: str, pdst: str, op: int = 2):
    return Ether() / ARP(psrc=psrc, hwsrc=hwsrc, pdst=pdst, op=op)


def test_extract_arp_frame_reads_sender_and_target():
    pkt = _arp_packet("10.0.0.5", "aa:bb:cc:dd:ee:ff", "10.0.0.1", op=2)

    frame = extract_arp_frame(pkt)

    assert frame.sender_ip == "10.0.0.5"
    assert frame.sender_mac == "aa:bb:cc:dd:ee:ff"
    assert frame.target_ip == "10.0.0.1"
    assert frame.is_reply is True


def test_extract_arp_frame_marks_request_as_not_reply():
    pkt = _arp_packet("10.0.0.5", "aa:bb:cc:dd:ee:ff", "10.0.0.1", op=1)

    frame = extract_arp_frame(pkt)

    assert frame.is_reply is False
