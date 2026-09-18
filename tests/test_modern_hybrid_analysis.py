from pathlib import Path

from nids.core.event import Severity
from nids.ml.modern.hybrid_analysis import analyze_pcap_modern_hybrid
from nids.ml.modern.model import ModernExpertModel

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def test_analyze_pcap_modern_hybrid_runs_end_to_end_without_crashing():
    expert = ModernExpertModel.load()

    events = analyze_pcap_modern_hybrid(str(PCAP_PATH), expert)

    assert isinstance(events, list)
    for event in events:
        assert isinstance(event.severity, Severity)
        assert isinstance(event.source_ip, str)


def test_analyze_pcap_modern_hybrid_normal_traffic_has_no_port_scan():
    expert = ModernExpertModel.load()

    events = analyze_pcap_modern_hybrid(str(PCAP_PATH), expert)

    assert not any(e.event_type == "port scan" for e in events)


def test_analyze_pcap_modern_hybrid_flags_sensitive_port_contact():
    expert = ModernExpertModel.load()

    events = analyze_pcap_modern_hybrid(str(PCAP_PATH), expert, sensitive_ports={80})

    assert any(e.event_type == "contact port sensibil" for e in events)


def test_analyze_pcap_modern_hybrid_flags_brute_force_with_low_threshold():
    expert = ModernExpertModel.load()

    events = analyze_pcap_modern_hybrid(
        str(PCAP_PATH), expert, brute_force_threshold=1, brute_force_ports={80}
    )

    assert any(e.event_type == "brute-force" for e in events)


def test_analyze_pcap_modern_hybrid_handles_files_without_arp_or_dns():
    expert = ModernExpertModel.load()

    events = analyze_pcap_modern_hybrid(str(PCAP_PATH), expert)

    assert not any(e.event_type == "ARP spoofing" for e in events)
    assert not any(e.event_type == "posibil DNS tunneling" for e in events)
