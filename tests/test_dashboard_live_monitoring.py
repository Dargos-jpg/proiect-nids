import time

from PySide6.QtWidgets import QApplication

from nids.capture.packet_meta import PacketMeta
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore
from nids.ui.widgets.dashboard_panel import DashboardPanel
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _fake_block_manager() -> BlockManager:
    return BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None)


def _make_panel(tmp_path, monkeypatch) -> DashboardPanel:
    # altfel LocalModelManager.load_or_new() ar citi/scrie calea reala
    # de pe disc, facand testele nedeterministe intre rulari
    monkeypatch.setattr(
        "nids.ml.local.learning.DEFAULT_STATE_PATH", tmp_path / "local_state.joblib"
    )
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        _fake_block_manager(),
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
    )


def _fake_packet(dst_ip: str, dst_port: int) -> PacketMeta:
    return PacketMeta(
        timestamp=0.0,
        src_ip="10.0.0.1",
        dst_ip=dst_ip,
        protocol="tcp",
        length=60,
        src_port=1234,
        dst_port=dst_port,
    )


def _wait_until(app: QApplication, condition, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert condition(), "conditia nu a fost indeplinita in timp util"


def _make_fake_capture(dst_ip: str):
    # 2000-2005, deliberat in afara porturilor sensibile implicite
    # (22/23/445/3389) - testele astea vizeaza doar semnatura de port
    # scan, nu vor sa se amestece cu semnatura noua de porturi sensibile
    def fake_capture_live(on_packet, interface=None, stop_event=None):
        for port in range(2000, 2006):
            if stop_event is not None and stop_event.is_set():
                return
            on_packet(_fake_packet(dst_ip, port))
        while stop_event is not None and not stop_event.is_set():
            time.sleep(0.02)

    return fake_capture_live


def test_dashboard_live_monitoring_thread_wiring(tmp_path, monkeypatch):
    """simuleaza captura live (fara nevoie de Npcap/retea reala) ca sa
    verifice firul real de thread + semnale Qt intre thread si UI"""
    app = _app()

    monkeypatch.setattr(
        "nids.ui.live_capture_thread.capture_live", _make_fake_capture("10.0.0.2")
    )

    panel = _make_panel(tmp_path, monkeypatch)
    panel._start_monitoring()

    _wait_until(app, lambda: panel._packet_count >= 6)

    assert panel._packet_count == 6
    assert panel._event_list.count() == 1
    assert "sesizat de 2 ori" in panel._event_list.item(0).text()
    assert panel._monitor_button.text() == "Opreste monitorizare"

    panel._stop_monitoring()

    _wait_until(app, lambda: panel._thread is None)

    assert panel._monitor_button.text() == "Porneste monitorizare"
    assert panel._monitor_button.isEnabled()
    assert panel._load_button.isEnabled()


def test_dashboard_live_monitoring_flags_sensitive_port_immediately(tmp_path, monkeypatch):
    """un singur contact catre un port sensibil (implicit SSH/RDP/SMB/
    Telnet) trebuie semnalat imediat, chiar daca e mult sub pragul de
    port scan (implicit 5 porturi distincte)"""
    app = _app()

    def fake_capture_live(on_packet, interface=None, stop_event=None):
        on_packet(_fake_packet("10.0.0.2", 22))
        while stop_event is not None and not stop_event.is_set():
            time.sleep(0.02)

    monkeypatch.setattr("nids.ui.live_capture_thread.capture_live", fake_capture_live)

    panel = _make_panel(tmp_path, monkeypatch)
    panel._start_monitoring()

    _wait_until(app, lambda: panel._event_list.count() >= 1)

    assert "port sensibil" in panel._event_list.item(0).text()

    panel._stop_monitoring()
    _wait_until(app, lambda: panel._thread is None)


def test_dashboard_live_monitoring_restart_after_stop(tmp_path, monkeypatch):
    """regresie: pornire -> oprire -> pornire din nou trebuia sa nu mai
    raporteze nimic a doua oara (bug cu QThread reutilizat gresit)"""
    app = _app()

    monkeypatch.setattr(
        "nids.ui.live_capture_thread.capture_live", _make_fake_capture("10.0.0.2")
    )

    panel = _make_panel(tmp_path, monkeypatch)

    panel._start_monitoring()
    _wait_until(app, lambda: panel._packet_count >= 6)
    panel._stop_monitoring()
    _wait_until(app, lambda: panel._thread is None)

    monkeypatch.setattr(
        "nids.ui.live_capture_thread.capture_live", _make_fake_capture("10.0.0.3")
    )

    panel._start_monitoring()
    _wait_until(app, lambda: panel._packet_count >= 6)

    assert panel._packet_count == 6
    assert panel._event_list.count() == 1

    panel._stop_monitoring()
    _wait_until(app, lambda: panel._thread is None)
