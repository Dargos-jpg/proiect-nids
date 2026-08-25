from pathlib import Path

from nids.core.analysis import analyze_pcap

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def test_analyze_pcap_on_normal_traffic_has_no_events():
    events = analyze_pcap(str(PCAP_PATH))

    assert events == []


def test_analyze_pcap_flags_sensitive_port_contact():
    events = analyze_pcap(str(PCAP_PATH), sensitive_ports={80})

    assert any(e.event_type == "contact port sensibil" for e in events)


def test_analyze_pcap_accepts_port_scan_window_without_changing_normal_traffic():
    events = analyze_pcap(str(PCAP_PATH), port_scan_window=5.0)

    assert events == []
