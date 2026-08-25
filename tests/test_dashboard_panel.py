from pathlib import Path

from PySide6.QtWidgets import QApplication

from nids.core.analysis import analyze_pcap
from nids.core.event import Event, Severity
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore
from nids.ui.widgets.dashboard_panel import DashboardPanel
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _fake_block_manager() -> BlockManager:
    return BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None)


def _make_panel(tmp_path: Path) -> DashboardPanel:
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        _fake_block_manager(),
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
    )


def test_show_events_populates_list(tmp_path):
    _app()
    panel = _make_panel(tmp_path)

    events = [
        Event(
            event_type="port scan",
            source_ip="10.0.0.1",
            severity=Severity.MEDIUM,
            description="test",
        )
    ]
    panel._show_events("fisier.pcap", events)

    assert panel._event_list.count() == 1
    assert "port scan" in panel._event_list.item(0).text()
    assert "fisier.pcap" in panel._status_label.text()
    assert len(panel._event_store.recent()) == 1


def test_show_events_with_no_events_updates_status(tmp_path):
    _app()
    panel = _make_panel(tmp_path)

    panel._show_events("fisier.pcap", [])

    assert panel._event_list.count() == 0
    assert "niciun eveniment" in panel._status_label.text()


def test_dashboard_end_to_end_with_real_pcap(tmp_path):
    _app()
    panel = _make_panel(tmp_path)

    events = analyze_pcap(str(PCAP_PATH))
    panel._show_events(str(PCAP_PATH), events)

    assert panel._event_list.count() == len(events)


def test_dashboard_loads_expert_model_on_init(tmp_path):
    _app()
    panel = _make_panel(tmp_path)

    assert panel._expert_model is not None


def test_dashboard_falls_back_when_expert_model_missing(tmp_path, monkeypatch):
    _app()

    def raise_not_found(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.ExpertModel.load", raise_not_found
    )
    panel = _make_panel(tmp_path)

    assert panel._expert_model is None


def test_dashboard_uses_hybrid_analysis_when_expert_model_available(tmp_path, monkeypatch):
    _app()
    panel = _make_panel(tmp_path)
    assert panel._expert_model is not None

    calls = []
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.analyze_pcap_hybrid",
        lambda path, expert, **kwargs: calls.append(("hybrid", path)) or [],
    )
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.analyze_pcap",
        lambda path, **kwargs: calls.append(("signatures_only", path)) or [],
    )
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.QFileDialog.getOpenFileName",
        lambda *a, **k: (str(PCAP_PATH), ""),
    )

    panel._on_load_clicked()

    assert calls == [("hybrid", str(PCAP_PATH))]


def test_dashboard_falls_back_to_signatures_only_without_expert_model(tmp_path, monkeypatch):
    _app()
    panel = _make_panel(tmp_path)
    panel._expert_model = None

    calls = []
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.analyze_pcap_hybrid",
        lambda path, expert, **kwargs: calls.append(("hybrid", path)) or [],
    )
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.analyze_pcap",
        lambda path, **kwargs: calls.append(("signatures_only", path)) or [],
    )
    monkeypatch.setattr(
        "nids.ui.widgets.dashboard_panel.QFileDialog.getOpenFileName",
        lambda *a, **k: (str(PCAP_PATH), ""),
    )

    panel._on_load_clicked()

    assert calls == [("signatures_only", str(PCAP_PATH))]
