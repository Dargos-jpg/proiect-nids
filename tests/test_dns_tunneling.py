from nids.capture.dns_meta import DnsQuery
from nids.core.event import Severity
from nids.signatures.dns_tunneling import (
    DnsTunnelEvent,
    DnsTunnelTracker,
    detect_dns_tunneling,
    event_from_dns_tunnel,
)

_HIGH_ENTROPY_LABEL = "a3f9c2e8b1d4f6a7c9e2b5d8f1a4c7e9b2d5f8a1"  # 40 caractere, entropie ~3.82
_LOW_ENTROPY_LONG_LABEL = "a" * 40  # lung, dar entropie 0
_HIGH_ENTROPY_SHORT_LABEL = "aB3xK9pQ2z"  # entropie ~3.32, dar doar 10 caractere


def _query(name: str, src_ip: str = "10.0.0.1") -> DnsQuery:
    return DnsQuery(timestamp=0.0, src_ip=src_ip, query_name=name, query_type="A")


def test_normal_domain_is_not_flagged():
    events = detect_dns_tunneling([_query("www.example.com")])

    assert events == []


def test_long_high_entropy_label_is_flagged():
    events = detect_dns_tunneling([_query(f"{_HIGH_ENTROPY_LABEL}.exfil.example.com")])

    assert len(events) == 1
    assert events[0].src_ip == "10.0.0.1"


def test_hyphenated_legitimate_service_domains_are_not_flagged():
    """regresie: fals-pozitive REALE gasite de user pe trafic real -
    "launcher-public-service-prod06.ol.epicgames.com" (entropie 4.01) si
    "service-aggregation-layer-subs.juno.ea.com" (entropie 3.78) - ambele
    peste pragul de entropie SI de lungime, dar sunt nume de servicii
    legitime, nu date encodate. tunneling-ul real (base32/hex) nu
    foloseste niciodata cratima"""
    events = detect_dns_tunneling(
        [
            _query("launcher-public-service-prod06.ol.epicgames.com"),
            _query("service-aggregation-layer-subs.juno.ea.com"),
        ]
    )

    assert events == []


def test_long_low_entropy_label_is_not_flagged():
    """lungime mare, dar text repetitiv (entropie mica) - nu arata a date
    encodate, deci nu trebuie semnalat doar pe baza lungimii"""
    events = detect_dns_tunneling([_query(f"{_LOW_ENTROPY_LONG_LABEL}.example.com")])

    assert events == []


def test_short_high_entropy_label_is_not_flagged():
    """entropie mare, dar prea scurta ca sa insemne ceva statistic"""
    events = detect_dns_tunneling([_query(f"{_HIGH_ENTROPY_SHORT_LABEL}.example.com")])

    assert events == []


def test_custom_thresholds_can_relax_or_tighten_detection():
    query = _query(f"{_HIGH_ENTROPY_SHORT_LABEL}.example.com")

    assert detect_dns_tunneling([query], min_label_length=5, min_entropy=3.0) != []
    assert detect_dns_tunneling([query], min_label_length=5, min_entropy=5.0) == []


def test_same_query_reported_once():
    queries = [_query(f"{_HIGH_ENTROPY_LABEL}.exfil.example.com") for _ in range(3)]

    events = detect_dns_tunneling(queries)

    assert len(events) == 1


def test_different_query_names_reported_separately():
    events = detect_dns_tunneling(
        [
            _query(f"{_HIGH_ENTROPY_LABEL}.exfil.example.com"),
            _query(f"{_HIGH_ENTROPY_LABEL}2.exfil.example.com"),
        ]
    )

    assert len(events) == 2


def test_event_from_dns_tunnel_has_medium_severity_and_identity():
    evt = DnsTunnelEvent(src_ip="10.0.0.1", query_name="abc.example.com", reason="test reason")

    event = event_from_dns_tunnel(evt)

    assert event.severity == Severity.MEDIUM
    assert event.source_ip == "10.0.0.1"
    assert "abc.example.com" in event.description
    assert "test reason" in event.description


def test_tracker_flags_first_occurrence_and_ignores_repeats():
    tracker = DnsTunnelTracker()
    query = _query(f"{_HIGH_ENTROPY_LABEL}.exfil.example.com")

    first = tracker.process_query(query)
    second = tracker.process_query(query)

    assert first is not None
    assert second is None


def test_tracker_ignores_normal_domains():
    tracker = DnsTunnelTracker()

    event = tracker.process_query(_query("www.example.com"))

    assert event is None
