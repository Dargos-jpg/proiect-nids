from PySide6.QtWidgets import QApplication

from nids.signatures.port_scan import DEFAULT_PORT_THRESHOLD
from nids.signatures.sensitive_ports import DEFAULT_SENSITIVE_PORTS
from nids.ui.widgets.signatures_panel import SignaturesPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_default_threshold_matches_signature_default():
    _app()
    panel = SignaturesPanel()

    assert panel.threshold() == DEFAULT_PORT_THRESHOLD


def test_slider_changes_threshold_and_emits_signal():
    _app()
    panel = SignaturesPanel()

    received = []
    panel.threshold_changed.connect(received.append)
    panel._slider.setValue(10)

    assert panel.threshold() == 10
    assert received == [10]
    assert "10" in panel._title_label.text()


# --- fereastra de timp ---


def test_window_seconds_is_unlimited_by_default():
    _app()
    panel = SignaturesPanel()

    assert panel.window_seconds() is None
    assert panel._window_spin.isEnabled() is False


def test_unchecking_unlimited_enables_window_spin_and_returns_value():
    _app()
    panel = SignaturesPanel()

    panel._unlimited_window.setChecked(False)
    panel._window_spin.setValue(15)

    assert panel._window_spin.isEnabled() is True
    assert panel.window_seconds() == 15.0


def test_rechecking_unlimited_returns_none_again():
    _app()
    panel = SignaturesPanel()
    panel._unlimited_window.setChecked(False)

    panel._unlimited_window.setChecked(True)

    assert panel.window_seconds() is None
    assert panel._window_spin.isEnabled() is False


# --- porturi sensibile ---


def test_sensitive_ports_default_matches_signature_default():
    _app()
    panel = SignaturesPanel()

    assert panel.sensitive_ports() == DEFAULT_SENSITIVE_PORTS


def test_sensitive_ports_parses_comma_separated_list():
    _app()
    panel = SignaturesPanel()

    panel._sensitive_ports_edit.setText("22, 8080,  9999")

    assert panel.sensitive_ports() == {22, 8080, 9999}


def test_sensitive_ports_ignores_invalid_tokens():
    _app()
    panel = SignaturesPanel()

    panel._sensitive_ports_edit.setText("22, abc, , 70000, 443")

    assert panel.sensitive_ports() == {22, 443}


def test_sensitive_ports_empty_text_returns_empty_set():
    _app()
    panel = SignaturesPanel()

    panel._sensitive_ports_edit.setText("")

    assert panel.sensitive_ports() == set()


def test_sensitive_ports_status_label_updates():
    _app()
    panel = SignaturesPanel()

    panel._sensitive_ports_edit.setText("22")

    assert "22" in panel._sensitive_ports_status.text()
    assert "1 port" in panel._sensitive_ports_status.text()
