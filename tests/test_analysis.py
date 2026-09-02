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


def test_analyze_pcap_flags_brute_force_with_low_threshold():
    events = analyze_pcap(str(PCAP_PATH), brute_force_threshold=1, brute_force_ports={80})

    assert any(e.event_type == "brute-force" for e in events)


def test_analyze_pcap_default_brute_force_settings_do_not_flag_normal_traffic():
    events = analyze_pcap(str(PCAP_PATH))

    assert not any(e.event_type == "brute-force" for e in events)


def test_analyze_pcap_handles_files_without_arp_frames():
    """http.cap nu are trafic ARP - read_pcap_arp() + detect_arp_spoofing()
    trebuie sa nu produca nimic, fara sa arunce"""
    events = analyze_pcap(str(PCAP_PATH))

    assert not any(e.event_type == "ARP spoofing" for e in events)


def test_analyze_pcap_handles_files_without_dns_queries():
    """http.cap nu are trafic DNS - read_pcap_dns_queries() +
    detect_dns_tunneling() trebuie sa nu produca nimic, fara sa arunce"""
    events = analyze_pcap(str(PCAP_PATH))

    assert not any(e.event_type == "posibil DNS tunneling" for e in events)


def test_analyze_pcap_normal_http_traffic_has_no_payload_signature_matches():
    events = analyze_pcap(str(PCAP_PATH))

    assert not any(e.event_type == "semnatura malware in payload" for e in events)


def test_analyze_pcap_payload_signatures_can_be_disabled():
    events = analyze_pcap(str(PCAP_PATH), payload_signatures_enabled=False)

    assert not any(e.event_type == "semnatura malware in payload" for e in events)
