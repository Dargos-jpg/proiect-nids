from pathlib import Path

from nids.capture.packet_meta import PacketMeta
from nids.capture.pcap_reader import read_pcap
from nids.ml.features.connection import extract_connections

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def _pkt(
    ts: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    length: int,
    tcp_flags: str | None,
    protocol: str = "tcp",
    is_fragmented: bool = False,
) -> PacketMeta:
    return PacketMeta(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        length=length,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        is_fragmented=is_fragmented,
    )


def test_groups_both_directions_into_one_connection():
    packets = [
        _pkt(0.0, "10.0.0.1", 5000, "10.0.0.2", 80, 60, "S"),
        _pkt(0.01, "10.0.0.2", 80, "10.0.0.1", 5000, 60, "SA"),
        _pkt(0.02, "10.0.0.1", 5000, "10.0.0.2", 80, 500, "PA"),
        _pkt(0.03, "10.0.0.2", 80, "10.0.0.1", 5000, 1000, "PA"),
        _pkt(0.04, "10.0.0.1", 5000, "10.0.0.2", 80, 60, "FA"),
    ]

    connections = extract_connections(packets)

    assert len(connections) == 1
    conn = connections[0]
    assert conn.src_ip == "10.0.0.1"
    assert conn.dst_ip == "10.0.0.2"
    assert conn.dst_port == 80
    assert conn.service == "http"
    assert conn.src_bytes == 60 + 500 + 60
    assert conn.dst_bytes == 60 + 1000
    assert conn.duration == 0.04
    assert conn.flag == "SF"
    assert conn.land is False


def test_connection_with_only_syn_is_s0():
    packets = [_pkt(0.0, "10.0.0.1", 5000, "10.0.0.2", 80, 60, "S")]

    conn = extract_connections(packets)[0]

    assert conn.flag == "S0"


def test_connection_with_reset_is_rej():
    packets = [
        _pkt(0.0, "10.0.0.1", 5000, "10.0.0.2", 80, 60, "S"),
        _pkt(0.01, "10.0.0.2", 80, "10.0.0.1", 5000, 60, "R"),
    ]

    conn = extract_connections(packets)[0]

    assert conn.flag == "REJ"


def test_land_attack_same_endpoint():
    packets = [_pkt(0.0, "10.0.0.1", 80, "10.0.0.1", 80, 60, "S")]

    conn = extract_connections(packets)[0]

    assert conn.land is True


def test_urgent_and_wrong_fragment_counted():
    packets = [
        _pkt(0.0, "10.0.0.1", 5000, "10.0.0.2", 80, 60, "S"),
        _pkt(0.01, "10.0.0.1", 5000, "10.0.0.2", 80, 60, "PAU", is_fragmented=True),
    ]

    conn = extract_connections(packets)[0]

    assert conn.urgent == 1
    assert conn.wrong_fragment == 1


def test_extract_connections_on_real_pcap_matches_known_flow():
    packets = read_pcap(str(PCAP_PATH))
    connections = extract_connections(packets)

    http_conn = next(
        c
        for c in connections
        if {c.src_ip, c.dst_ip} == {"145.254.160.237", "65.208.228.223"}
        and c.dst_port == 80
    )

    assert http_conn.protocol == "tcp"
    assert http_conn.service == "http"
    assert http_conn.src_bytes > 0
    assert http_conn.dst_bytes > 0
    assert http_conn.duration >= 0
