from pathlib import Path

from PySide6.QtWidgets import QApplication

from nids.capture.pcap_reader import read_pcap
from nids.core.event import Event, Severity
from nids.core.inspect import assess_connection, assessment_to_json
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore, StoredEvent
from nids.ui.widgets.dashboard_panel import DashboardPanel, _find_matching_connection
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel
from tests.factories import make_record

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _make_panel(tmp_path: Path) -> DashboardPanel:
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None),
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
    )


def test_find_matching_connection_matches_either_direction():
    packets = read_pcap(str(PCAP_PATH))
    from nids.ml.features.nsl_kdd_style import extract_nsl_kdd_style_features

    records = extract_nsl_kdd_style_features(packets)

    # al doilea pachet e raspunsul serverului (directie inversa fata de primul)
    response_pkt = packets[1]
    match = _find_matching_connection(
        records,
        response_pkt.src_ip,
        response_pkt.src_port,
        response_pkt.dst_ip,
        response_pkt.dst_port,
        response_pkt.protocol,
    )

    assert match is not None
    assert {match.src_ip, match.dst_ip} == {response_pkt.src_ip, response_pkt.dst_ip}


def test_analyze_requested_without_traffic_shows_hint(tmp_path):
    _app()
    panel = _make_panel(tmp_path)

    panel._on_traffic_analyze_requested(read_pcap(str(PCAP_PATH))[0])

    assert "nu exista trafic" in panel._status_label.text()


def test_analyze_requested_opens_dialog_for_loaded_pcap(tmp_path, monkeypatch):
    # blocam afisarea reala - altfel ar aparea o fereastra vizibila pe
    # ecran in timpul rularii testelor
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.ConnectionInspectorDialog.show", lambda self: None
    )

    _app()
    panel = _make_panel(tmp_path)
    packets = read_pcap(str(PCAP_PATH))
    panel._all_packets = packets

    panel._on_traffic_analyze_requested(packets[0])

    assert len(panel._inspector_dialogs) == 1
    panel._inspector_dialogs[0].close()


def test_log_analyze_requested_opens_dialog_from_saved_assessment_without_packets(
    tmp_path, monkeypatch
):
    """regresie: analiza completa dintr-un rand din Loguri trebuie sa
    functioneze chiar daca traficul brut al sesiunii curente nu mai
    exista (ex: eveniment dintr-o sesiune anterioara) - atata timp cat
    are un assessment_json salvat, nu are nevoie de _all_packets deloc"""
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.ConnectionInspectorDialog.show", lambda self: None
    )

    _app()
    panel = _make_panel(tmp_path)
    panel._all_packets = []  # simuleaza o sesiune noua, fara pachetele vechi

    assessment = assess_connection(make_record(), expert=None, local_manager=None)
    event = Event(
        event_type="anomalie noua",
        source_ip="10.0.0.1",
        severity=Severity.HIGH,
        description="test",
        dest_ip="10.0.0.2",
        assessment_json=assessment_to_json(assessment),
    )
    panel._event_store.save(event)
    entry = panel._event_store.recent()[0]

    panel._on_log_analyze_requested(entry)

    assert len(panel._inspector_dialogs) == 1
    panel._inspector_dialogs[0].close()


def test_manual_block_event_can_be_analyzed_from_logs(tmp_path, monkeypatch):
    """end-to-end pentru regresia semnalata de user: blochezi manual o
    conexiune ML din Dashboard, apoi vrei sa poti deschide analiza
    completa direct din randul "blocare manuala" din Loguri (nu doar din
    evenimentul original)"""
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.ConnectionInspectorDialog.show", lambda self: None
    )

    _app()
    panel = _make_panel(tmp_path)
    assessment = assess_connection(make_record(), expert=None, local_manager=None)
    original = Event(
        event_type="anomalie noua",
        source_ip="10.0.0.9",
        severity=Severity.HIGH,
        description="test",
        dest_ip="10.0.0.2",
        assessment_json=assessment_to_json(assessment),
    )

    panel._block_event_source(original)

    block_entry = panel._event_store.recent()[0]
    assert block_entry.event_type == "blocare manuala"

    panel._on_log_analyze_requested(block_entry)

    assert len(panel._inspector_dialogs) == 1
    panel._inspector_dialogs[0].close()


def test_log_analyze_requested_without_assessment_or_identity_shows_message(tmp_path):
    _app()
    panel = _make_panel(tmp_path)
    entry = StoredEvent(
        timestamp="2026-01-01T00:00:00",
        event_type="port scan",
        source_ip="10.0.0.1",
        severity="medie",
        description="test",
    )

    panel._on_log_analyze_requested(entry)

    assert "nu are o conexiune ML asociata" in panel._status_label.text()
