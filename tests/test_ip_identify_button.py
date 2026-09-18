from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QApplication

from nids.core.dns_lookup import IpLookupResult
from nids.ui.widgets.ip_lookup_dialog import IpIdentifyButton, IpLookupResultsDialog


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class _FakeReverseDnsThread(QThread):
    succeeded = Signal(dict)
    failed = Signal(str)

    def __init__(self, ips, parent=None) -> None:
        super().__init__(parent)
        self._ips = ips

    def run(self) -> None:
        self.succeeded.emit(
            {ip: IpLookupResult(hostname=f"host-{ip}", asn_info=None) for ip in self._ips}
        )


class _FakeFailingReverseDnsThread(QThread):
    succeeded = Signal(dict)
    failed = Signal(str)

    def __init__(self, ips, parent=None) -> None:
        super().__init__(parent)

    def run(self) -> None:
        self.failed.emit("eroare de retea")


def test_click_with_fixed_ip_list_resolves_and_shows_dialog(monkeypatch):
    _app()
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.ReverseDnsThread", _FakeReverseDnsThread
    )
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.IpLookupResultsDialog.show", lambda self: None
    )
    button = IpIdentifyButton(["10.0.0.1", "10.0.0.2"])

    button.click()
    button._dns_thread.wait(2000)
    _app().processEvents()

    assert len(button._lookup_dialogs) == 1
    assert button.isEnabled() is True
    assert button.text() == "Identifica IP-uri"
    button._lookup_dialogs[0].close()


def test_click_deduplicates_ips_preserving_order(monkeypatch):
    _app()
    captured = {}

    class _CapturingThread(_FakeReverseDnsThread):
        def __init__(self, ips, parent=None) -> None:
            captured["ips"] = ips
            super().__init__(ips, parent)

    monkeypatch.setattr("nids.ui.widgets.ip_lookup_dialog.ReverseDnsThread", _CapturingThread)
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.IpLookupResultsDialog.show", lambda self: None
    )
    button = IpIdentifyButton(["10.0.0.1", "10.0.0.1", "10.0.0.2"])

    button.click()
    button._dns_thread.wait(2000)
    _app().processEvents()

    assert captured["ips"] == ["10.0.0.1", "10.0.0.2"]
    button._lookup_dialogs[0].close()


def test_click_with_callable_provider_evaluates_at_click_time(monkeypatch):
    _app()
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.ReverseDnsThread", _FakeReverseDnsThread
    )
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.IpLookupResultsDialog.show", lambda self: None
    )
    current_ips = []
    button = IpIdentifyButton(lambda: list(current_ips))

    button.click()
    assert button._dns_thread is None  # lista goala la click - nu porneste nimic

    current_ips.append("10.0.0.9")
    button.click()
    button._dns_thread.wait(2000)
    _app().processEvents()

    assert len(button._lookup_dialogs) == 1
    button._lookup_dialogs[0].close()


def test_click_does_nothing_without_ips(monkeypatch):
    _app()
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.ReverseDnsThread", _FakeReverseDnsThread
    )
    button = IpIdentifyButton([])

    button.click()

    assert button._dns_thread is None


def test_click_shows_error_message_on_failure(monkeypatch):
    _app()
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.ReverseDnsThread", _FakeFailingReverseDnsThread
    )
    button = IpIdentifyButton(["10.0.0.1"])

    button.click()
    button._dns_thread.wait(2000)
    _app().processEvents()

    assert "eroare" in button.text()


def test_custom_label_is_restored_after_success(monkeypatch):
    _app()
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.ReverseDnsThread", _FakeReverseDnsThread
    )
    monkeypatch.setattr(
        "nids.ui.widgets.ip_lookup_dialog.IpLookupResultsDialog.show", lambda self: None
    )
    button = IpIdentifyButton(["10.0.0.1"], label="Identifica")

    button.click()
    button._dns_thread.wait(2000)
    _app().processEvents()

    assert button.text() == "Identifica"
    button._lookup_dialogs[0].close()
