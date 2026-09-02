from nids.capture.payload_meta import PayloadSample
from nids.core.event import Severity
from nids.signatures.payload_signatures import (
    PayloadMatch,
    PayloadSignature,
    PayloadSignatureTracker,
    detect_payload_signatures,
    event_from_payload_match,
    scan_payload_sample,
)


def _sample(payload: bytes, src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2", dst_port: int = 80) -> PayloadSample:
    return PayloadSample(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, payload=payload)


def test_scan_detects_known_signature():
    match = scan_payload_sample(_sample(b"GET /../../../etc/passwd HTTP/1.1"))

    assert match is not None
    assert match.signature_name == "traversare director (Unix)"
    assert match.src_ip == "10.0.0.1"
    assert match.dst_port == 80


def test_scan_returns_none_for_benign_payload():
    match = scan_payload_sample(_sample(b"GET /index.html HTTP/1.1"))

    assert match is None


def test_scan_detects_sql_injection():
    match = scan_payload_sample(_sample(b"id=1 UNION SELECT username, password FROM users"))

    assert match is not None
    assert "SQL injection" in match.signature_name


def test_scan_detects_xss():
    match = scan_payload_sample(_sample(b"<script>alert(1)</script>"))

    assert match is not None
    assert "XSS" in match.signature_name


def test_scan_detects_eicar():
    eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    match = scan_payload_sample(_sample(eicar))

    assert match is not None
    assert "EICAR" in match.signature_name


def test_scan_respects_custom_signature_list():
    custom = [PayloadSignature("test", b"custom-pattern")]

    assert scan_payload_sample(_sample(b"contains custom-pattern here"), custom) is not None
    assert scan_payload_sample(_sample(b"nothing interesting"), custom) is None


def test_detect_payload_signatures_dedupes_same_match():
    samples = [_sample(b"UNION SELECT") for _ in range(3)]

    matches = detect_payload_signatures(samples)

    assert len(matches) == 1


def test_detect_payload_signatures_separates_different_destinations():
    matches = detect_payload_signatures(
        [_sample(b"UNION SELECT", dst_ip="10.0.0.2"), _sample(b"UNION SELECT", dst_ip="10.0.0.3")]
    )

    assert len(matches) == 2


def test_event_from_payload_match_has_high_severity_and_mentions_encryption_limit():
    match = PayloadMatch(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, signature_name="test sig")

    event = event_from_payload_match(match)

    assert event.severity == Severity.HIGH
    assert event.source_ip == "10.0.0.1"
    assert event.dest_ip == "10.0.0.2"
    assert event.dest_port == 80
    assert "HTTPS/TLS" in event.description


def test_tracker_flags_first_match_and_ignores_repeats():
    tracker = PayloadSignatureTracker()
    sample = _sample(b"UNION SELECT")

    first = tracker.process_sample(sample)
    second = tracker.process_sample(sample)

    assert first is not None
    assert second is None


def test_tracker_ignores_benign_payloads():
    tracker = PayloadSignatureTracker()

    assert tracker.process_sample(_sample(b"just normal http traffic")) is None
