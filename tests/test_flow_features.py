from pathlib import Path

from nids.capture.pcap_reader import read_pcap
from nids.ml.features.flow import extract_flows

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def test_extract_flows_conserves_packet_and_byte_counts():
    packets = read_pcap(str(PCAP_PATH))
    flows = extract_flows(packets)

    assert len(flows) > 0
    assert sum(f.packet_count for f in flows) == len(packets)
    assert sum(f.total_bytes for f in flows) == sum(p.length for p in packets)


def test_extract_flows_groups_known_http_connection():
    packets = read_pcap(str(PCAP_PATH))
    flows = extract_flows(packets)

    http_flow = next(
        f
        for f in flows
        if f.src_ip == "145.254.160.237"
        and f.dst_ip == "65.208.228.223"
        and f.dst_port == 80
    )

    assert http_flow.protocol == "tcp"
    assert http_flow.packet_count > 1
    assert http_flow.total_bytes > 0
    assert http_flow.duration >= 0
    assert http_flow.mean_packet_size == http_flow.total_bytes / http_flow.packet_count
    assert http_flow.packets_per_second > 0


def test_extract_flows_empty_input():
    assert extract_flows([]) == []
