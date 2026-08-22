from pathlib import Path

from nids.capture.pcap_reader import read_pcap

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def test_read_pcap_extracts_metadata():
    packets = read_pcap(str(PCAP_PATH))

    assert len(packets) > 0

    first = packets[0]
    assert first.src_ip == "145.254.160.237"
    assert first.dst_ip == "65.208.228.223"
    assert first.protocol == "tcp"
    assert first.dst_port == 80
    assert first.length > 0
