from pathlib import Path

from nids.core.event import Severity
from nids.core.hybrid_analysis import analyze_pcap_hybrid
from nids.ml.expert.model import ExpertModel

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def test_analyze_pcap_hybrid_runs_end_to_end_without_crashing():
    expert = ExpertModel.load()

    events = analyze_pcap_hybrid(str(PCAP_PATH), expert)

    assert isinstance(events, list)
    for event in events:
        assert isinstance(event.severity, Severity)
        assert isinstance(event.source_ip, str)


def test_analyze_pcap_hybrid_normal_traffic_has_no_port_scan():
    expert = ExpertModel.load()

    events = analyze_pcap_hybrid(str(PCAP_PATH), expert)

    assert not any(e.event_type == "port scan" for e in events)


def test_analyze_pcap_hybrid_flags_sensitive_port_contact():
    expert = ExpertModel.load()

    events = analyze_pcap_hybrid(str(PCAP_PATH), expert, sensitive_ports={80})

    assert any(e.event_type == "contact port sensibil" for e in events)


def test_analyze_pcap_hybrid_accepts_port_scan_window():
    expert = ExpertModel.load()

    events = analyze_pcap_hybrid(str(PCAP_PATH), expert, port_scan_window=5.0)

    assert not any(e.event_type == "port scan" for e in events)


def test_analyze_pcap_hybrid_flags_brute_force_with_low_threshold():
    expert = ExpertModel.load()

    events = analyze_pcap_hybrid(
        str(PCAP_PATH), expert, brute_force_threshold=1, brute_force_ports={80}
    )

    assert any(e.event_type == "brute-force" for e in events)


def test_analyze_pcap_hybrid_handles_files_without_arp_or_dns():
    expert = ExpertModel.load()

    events = analyze_pcap_hybrid(str(PCAP_PATH), expert)

    assert not any(e.event_type == "ARP spoofing" for e in events)
    assert not any(e.event_type == "posibil DNS tunneling" for e in events)


def test_analyze_pcap_hybrid_normal_traffic_has_no_payload_signature_matches():
    expert = ExpertModel.load()

    events = analyze_pcap_hybrid(str(PCAP_PATH), expert)

    assert not any(e.event_type == "semnatura malware in payload" for e in events)
