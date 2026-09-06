from pathlib import Path

from PySide6.QtWidgets import QApplication

from nids.capture.packet_meta import PacketMeta
from nids.capture.payload_meta import PayloadSample
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore
from nids.ui.widgets.dashboard_panel import DashboardPanel
from nids.ui.widgets.forensics_panel import ForensicsPanel
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _packet(src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2", dst_port=80, ts=0.0) -> PacketMeta:
    return PacketMeta(
        timestamp=ts, src_ip=src_ip, dst_ip=dst_ip, protocol="tcp", length=100,
        src_port=src_port, dst_port=dst_port,
    )


def _make_panel(tmp_path: Path, forensics_panel: ForensicsPanel | None) -> DashboardPanel:
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None),
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
        forensics_panel=forensics_panel,
    )


def test_reconstruct_requested_without_traffic_shows_status_message(tmp_path):
    _app()
    panel = _make_panel(tmp_path, None)

    panel._on_traffic_reconstruct_requested(_packet())

    assert "nu s-au gasit" in panel._status_label.text()


def test_reconstruct_requested_opens_timeline_dialog_for_matching_packets(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.ConnectionTimelineDialog.show", lambda self: None
    )
    _app()
    panel = _make_panel(tmp_path, None)
    request = _packet(ts=1.0)
    response = _packet(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=1.5)
    panel._all_packets = [request, response]

    panel._on_traffic_reconstruct_requested(request)

    assert len(panel._timeline_dialogs) == 1
    panel._timeline_dialogs[0].close()


def test_live_payload_sample_is_forwarded_to_forensics_panel(tmp_path):
    _app()
    forensics_panel = ForensicsPanel()
    panel = _make_panel(tmp_path, forensics_panel)
    sample = PayloadSample(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, payload=b"GET /")

    panel._on_live_payload_sample(sample)

    assert forensics_panel._table.rowCount() == 1


def test_load_pcap_forwards_payload_samples_to_forensics_panel(tmp_path, monkeypatch):
    _app()
    forensics_panel = ForensicsPanel()
    panel = _make_panel(tmp_path, forensics_panel)
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.QFileDialog.getOpenFileName",
        lambda *a, **k: (str(PCAP_PATH), ""),
    )

    panel._on_load_clicked()

    # http.cap contine trafic HTTP real, deci macar un pachet cu payload
    assert forensics_panel._table.rowCount() > 0
