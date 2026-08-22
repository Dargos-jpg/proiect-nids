from pathlib import Path

from nids.core.analysis import analyze_pcap

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def test_analyze_pcap_on_normal_traffic_has_no_events():
    events = analyze_pcap(str(PCAP_PATH))

    assert events == []
