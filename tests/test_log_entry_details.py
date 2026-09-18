from PySide6.QtWidgets import QApplication, QLabel, QTextEdit

from nids.storage.event_store import StoredEvent
from nids.ui.widgets.ip_lookup_dialog import IpIdentifyButton
from nids.ui.widgets.log_entry_details import LogEntryDetailsDialog


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _all_label_text(dialog: LogEntryDetailsDialog) -> str:
    return " ".join(label.text() for label in dialog.findChildren(QLabel))


def _entry(**overrides) -> StoredEvent:
    base = dict(
        timestamp="2026-01-01T00:00:00",
        event_type="port scan",
        source_ip="10.0.0.1",
        severity="medie",
        description="70 porturi distincte contactate: " + ", ".join(str(p) for p in range(70)),
    )
    base.update(overrides)
    return StoredEvent(**base)


def test_shows_full_description_without_truncation():
    _app()
    entry = _entry()

    dialog = LogEntryDetailsDialog(entry)

    text_edit = dialog.findChild(QTextEdit)
    assert text_edit.toPlainText() == entry.description
    dialog.close()


def test_shows_event_type_and_severity_in_header():
    _app()
    entry = _entry(event_type="brute-force", severity="ridicata")

    dialog = LogEntryDetailsDialog(entry)

    text = _all_label_text(dialog)
    assert "brute-force" in text
    assert "ridicata" in text
    dialog.close()


def test_shows_source_ip():
    _app()
    entry = _entry(source_ip="192.168.1.50")

    dialog = LogEntryDetailsDialog(entry)

    assert "192.168.1.50" in _all_label_text(dialog)
    dialog.close()


def test_signature_event_without_ml_identity_shows_only_source():
    """port scan/brute-force nu au dest_ip/src_port - dialogul nu trebuie
    sa arunce, doar sa omita acele campuri"""
    _app()
    entry = _entry(dest_ip=None, src_port=None, dest_port=None, protocol=None)

    dialog = LogEntryDetailsDialog(entry)

    text = _all_label_text(dialog)
    assert "Destinatie" not in text
    assert "Port sursa" not in text
    dialog.close()


def test_ml_event_shows_full_connection_identity():
    _app()
    entry = _entry(
        event_type="anomalie noua",
        dest_ip="10.0.0.2",
        src_port=5000,
        dest_port=443,
        protocol="tcp",
    )

    dialog = LogEntryDetailsDialog(entry)

    text = _all_label_text(dialog)
    assert "10.0.0.2" in text
    assert "5000" in text
    assert "443" in text
    assert "tcp" in text
    dialog.close()


def test_identify_button_includes_source_and_destination_when_both_present():
    _app()
    entry = _entry(dest_ip="10.0.0.2")

    dialog = LogEntryDetailsDialog(entry)

    buttons = dialog.findChildren(IpIdentifyButton)
    assert len(buttons) == 1
    assert buttons[0]._ips_provider() == ["10.0.0.1", "10.0.0.2"]
    dialog.close()


def test_identify_button_includes_only_source_without_destination():
    """port scan/brute-force nu au dest_ip - butonul tot trebuie sa
    functioneze, doar pentru sursa"""
    _app()
    entry = _entry(dest_ip=None)

    dialog = LogEntryDetailsDialog(entry)

    buttons = dialog.findChildren(IpIdentifyButton)
    assert buttons[0]._ips_provider() == ["10.0.0.1"]
    dialog.close()
