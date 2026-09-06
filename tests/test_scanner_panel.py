import time

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QApplication

from nids.scanner.vulnerability_scan import PortScanResult
from nids.storage.event_store import EventStore
from nids.ui.widgets.scanner_panel import ScannerPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _wait_until(app: QApplication, condition, timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert condition(), "conditia nu a fost indeplinita in timp util"


class _FakeScanThread(QThread):
    succeeded = Signal(list)
    failed = Signal(str)

    def __init__(self, hosts, ports, parent=None) -> None:
        super().__init__(parent)
        self._hosts = hosts
        self._ports = ports

    def run(self) -> None:
        self.succeeded.emit(
            [PortScanResult(host=self._hosts[0], port=445, service="microsoft_ds", risk_notes=["risc cunoscut"])]
        )


class _FakeFailingScanThread(QThread):
    succeeded = Signal(list)
    failed = Signal(str)

    def __init__(self, hosts, ports, parent=None) -> None:
        super().__init__(parent)

    def run(self) -> None:
        self.failed.emit("adrese neprivate, refuzate: 8.8.8.8")


def test_targets_parses_comma_separated_list(tmp_path):
    _app()
    panel = ScannerPanel(EventStore(tmp_path / "test.db"))

    panel._targets_edit.setText("192.168.1.1, 192.168.1.2 ,  192.168.1.3")

    assert panel.targets() == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_scan_with_no_targets_shows_message(tmp_path):
    _app()
    panel = ScannerPanel(EventStore(tmp_path / "test.db"))
    panel._targets_edit.setText("")

    panel._on_scan_clicked()

    assert "adauga cel putin o adresa" in panel._status_label.text()
    assert panel._thread is None


def test_successful_scan_fills_table_and_saves_events(tmp_path, monkeypatch):
    app = _app()
    monkeypatch.setattr("nids.ui.widgets.scanner_panel.ScanThread", _FakeScanThread)
    event_store = EventStore(tmp_path / "test.db")
    panel = ScannerPanel(event_store)
    panel._targets_edit.setText("192.168.1.5")

    panel._on_scan_clicked()
    _wait_until(app, lambda: panel._table.rowCount() == 1)
    _wait_until(app, lambda: len(event_store.recent()) == 1)

    assert panel._table.item(0, 0).text() == "192.168.1.5"
    assert panel._table.item(0, 1).text() == "445"
    logged = event_store.recent()[0]
    assert logged.event_type == "scanare vulnerabilitati"
    _wait_until(app, lambda: panel._thread is None)
    assert panel._scan_button.isEnabled()


def test_failed_scan_shows_error_message(tmp_path, monkeypatch):
    app = _app()
    monkeypatch.setattr("nids.ui.widgets.scanner_panel.ScanThread", _FakeFailingScanThread)
    panel = ScannerPanel(EventStore(tmp_path / "test.db"))
    panel._targets_edit.setText("8.8.8.8")

    panel._on_scan_clicked()
    _wait_until(app, lambda: "esuata" in panel._status_label.text())

    assert "8.8.8.8" in panel._status_label.text()


def test_stop_waits_for_running_thread(tmp_path, monkeypatch):
    app = _app()
    monkeypatch.setattr("nids.ui.widgets.scanner_panel.ScanThread", _FakeScanThread)
    panel = ScannerPanel(EventStore(tmp_path / "test.db"))
    panel._targets_edit.setText("192.168.1.5")
    panel._on_scan_clicked()
    _wait_until(app, lambda: panel._table.rowCount() == 1)

    panel.stop()  # nu trebuie sa arunce, chiar daca thread-ul s-a terminat deja

    assert True
