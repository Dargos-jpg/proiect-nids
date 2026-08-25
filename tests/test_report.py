from nids.core.report import generate_html_report, save_report
from nids.storage.event_store import StoredEvent


def _event(source_ip: str = "10.0.0.1", severity: str = "ridicata") -> StoredEvent:
    return StoredEvent(
        timestamp="2026-01-01T12:00:00",
        event_type="port scan",
        source_ip=source_ip,
        severity=severity,
        description="5 porturi distincte",
    )


def test_report_contains_title_and_events():
    html = generate_html_report([_event()], title="Raport test")

    assert "Raport test" in html
    assert "10.0.0.1" in html
    assert "port scan" in html


def test_report_counts_by_severity():
    html = generate_html_report(
        [_event(severity="ridicata"), _event(severity="ridicata"), _event(severity="medie")]
    )

    assert ">2</div>severitate ridicata" in html
    assert ">1</div>severitate medie" in html
    assert ">0</div>severitate scazuta" in html


def test_report_escapes_html_in_description():
    malicious = StoredEvent(
        timestamp="2026-01-01T12:00:00",
        event_type="test",
        source_ip="10.0.0.1",
        severity="ridicata",
        description="<script>alert(1)</script>",
    )

    html = generate_html_report([malicious])

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_report_with_no_events_still_valid():
    html = generate_html_report([])

    assert "niciun eveniment" in html
    assert "0 evenimente" in html


def test_save_report_writes_file(tmp_path):
    path = tmp_path / "raport.html"

    save_report([_event()], path)

    assert path.exists()
    assert "10.0.0.1" in path.read_text(encoding="utf-8")
