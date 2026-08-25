from pathlib import Path

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication

from nids.core.event import Event, Severity
from nids.storage.event_store import EventStore
from nids.ui.widgets.logs_panel import LogsPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _event(source_ip: str) -> Event:
    return Event(
        event_type="port scan",
        source_ip=source_ip,
        severity=Severity.MEDIUM,
        description="test",
    )


def _ml_event(source_ip: str, dest_ip: str) -> Event:
    return Event(
        event_type="anomalie noua",
        source_ip=source_ip,
        severity=Severity.HIGH,
        description="model local vede ceva neobisnuit",
        dest_ip=dest_ip,
        src_port=5000,
        dest_port=443,
        protocol="tcp",
    )


def test_shows_all_events_by_default(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))

    panel = LogsPanel(store)

    assert panel._table.rowCount() == 2


def test_source_filter_lists_distinct_sources(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))

    panel = LogsPanel(store)

    items = [panel._source_filter.itemText(i) for i in range(panel._source_filter.count())]
    assert items == ["toate sursele", "10.0.0.1", "10.0.0.2"]


def test_selecting_a_source_filters_table(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))
    store.save(_event("10.0.0.1"))

    panel = LogsPanel(store)
    panel._source_filter.setCurrentText("10.0.0.1")

    assert panel._table.rowCount() == 2
    assert all(
        panel._table.item(row, 2).text() == "10.0.0.1" for row in range(panel._table.rowCount())
    )


def test_new_source_appears_after_refresh(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    panel = LogsPanel(store)

    store.save(_event("10.0.0.9"))
    panel._refresh()

    items = [panel._source_filter.itemText(i) for i in range(panel._source_filter.count())]
    assert "10.0.0.9" in items


def test_refresh_keeps_current_selection(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))
    panel = LogsPanel(store)
    panel._source_filter.setCurrentText("10.0.0.2")

    store.save(_event("10.0.0.9"))
    panel._refresh()

    assert panel._source_filter.currentText() == "10.0.0.2"
    assert panel._table.rowCount() == 1


def test_export_writes_all_events_when_no_filter(tmp_path, monkeypatch):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))
    panel = LogsPanel(store)

    out_path = tmp_path / "raport.html"
    monkeypatch.setattr(
        "nids.ui.widgets.logs_panel.QFileDialog.getSaveFileName",
        lambda *a, **k: (str(out_path), ""),
    )

    panel._on_export_clicked()

    content = out_path.read_text(encoding="utf-8")
    assert "10.0.0.1" in content
    assert "10.0.0.2" in content
    assert "toate evenimentele" in content


def test_export_writes_only_filtered_source(tmp_path, monkeypatch):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))
    panel = LogsPanel(store)
    panel._source_filter.setCurrentText("10.0.0.1")

    out_path = tmp_path / "raport.html"
    monkeypatch.setattr(
        "nids.ui.widgets.logs_panel.QFileDialog.getSaveFileName",
        lambda *a, **k: (str(out_path), ""),
    )

    panel._on_export_clicked()

    content = out_path.read_text(encoding="utf-8")
    assert "10.0.0.1" in content
    assert "10.0.0.2" not in content
    assert "cronologie 10.0.0.1" in content


def test_export_cancelled_does_not_write_file(tmp_path, monkeypatch):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    panel = LogsPanel(store)

    monkeypatch.setattr(
        "nids.ui.widgets.logs_panel.QFileDialog.getSaveFileName", lambda *a, **k: ("", "")
    )

    panel._on_export_clicked()

    assert not (tmp_path / "raport.html").exists()


def test_search_filters_rows_by_free_text(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))
    panel = LogsPanel(store)

    panel._search_box.setText("10.0.0.2")

    hidden = [panel._table.isRowHidden(r) for r in range(panel._table.rowCount())]
    visible_sources = [
        panel._table.item(r, 2).text()
        for r in range(panel._table.rowCount())
        if not hidden[r]
    ]
    assert visible_sources == ["10.0.0.2"]


def test_search_matches_description_column(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(
        Event(
            event_type="port scan",
            source_ip="10.0.0.1",
            severity=Severity.MEDIUM,
            description="conexiune neobisnuita catre 8.8.8.8",
        )
    )
    store.save(_event("10.0.0.2"))
    panel = LogsPanel(store)

    panel._search_box.setText("8.8.8.8")

    visible = [r for r in range(panel._table.rowCount()) if not panel._table.isRowHidden(r)]
    assert len(visible) == 1
    assert "8.8.8.8" in panel._table.item(visible[0], 4).text()


def test_clearing_search_shows_all_rows(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    store.save(_event("10.0.0.2"))
    panel = LogsPanel(store)
    panel._search_box.setText("10.0.0.2")

    panel._search_box.setText("")

    assert all(not panel._table.isRowHidden(r) for r in range(panel._table.rowCount()))


def test_refresh_reapplies_active_search(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    panel = LogsPanel(store)
    panel._search_box.setText("10.0.0.9")

    store.save(_event("10.0.0.9"))
    panel._refresh()

    hidden = {
        panel._table.item(r, 2).text(): panel._table.isRowHidden(r)
        for r in range(panel._table.rowCount())
    }
    assert hidden["10.0.0.9"] is False
    assert hidden["10.0.0.1"] is True


def test_entry_at_returns_stored_event_for_row(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    panel = LogsPanel(store)

    row_center = panel._table.rowViewportPosition(0) + 5
    entry = panel._entry_at(QPoint(5, row_center))

    assert entry is not None
    assert entry.source_ip == "10.0.0.1"


def test_entry_at_returns_none_below_last_row(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    panel = LogsPanel(store)

    entry = panel._entry_at(QPoint(5, 100_000))

    assert entry is None


def test_analyze_requested_signal_carries_stored_event(tmp_path):
    """verifica doar contractul semnalului (folosit de DashboardPanel) -
    NU declanseaza QMenu.exec() real, care ar deschide un popup si ar
    bloca testul asteptand o interactiune care nu vine niciodata"""
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_ml_event("10.0.0.1", "10.0.0.2"))
    panel = LogsPanel(store)
    entry = panel._table.item(0, 0).data(Qt.ItemDataRole.UserRole)

    received = []
    panel.analyze_requested.connect(received.append)
    panel.analyze_requested.emit(entry)

    assert len(received) == 1
    assert received[0].dest_ip == "10.0.0.2"


def test_stop_disables_the_refresh_timer(tmp_path):
    """regresie: fara stop(), timer-ul mai putea apuca sa ruleze un
    refresh DUPA ce EventStore.close() rula la inchiderea aplicatiei -
    sqlite3.ProgrammingError: Cannot operate on a closed database"""
    _app()
    store = EventStore(tmp_path / "test.db")
    panel = LogsPanel(store)
    assert panel._timer.isActive() is True

    panel.stop()

    assert panel._timer.isActive() is False


def test_selection_follows_same_event_when_pushed_down_by_new_row(tmp_path):
    """regresie: selectia ramanea pe INDEXUL de rand, nu pe eveniment -
    un eveniment nou (mai recent, deci pe randul 0) impingea evenimentul
    deja selectat cu un rand mai jos, iar selectia vizuala "aluneca" pe
    alt eveniment"""
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    panel = LogsPanel(store)
    panel._table.selectRow(0)

    store.save(_event("10.0.0.9"))
    panel._refresh_table()

    assert panel._table.item(0, 2).text() == "10.0.0.9"  # cel mai nou, randul 0 acum
    assert panel._table.item(1, 2).text() == "10.0.0.1"  # cel selectat, impins jos
    assert panel._table.item(1, 0).isSelected() is True
    assert panel._table.item(0, 0).isSelected() is False


def test_no_selection_stays_empty_after_refresh(tmp_path):
    _app()
    store = EventStore(tmp_path / "test.db")
    store.save(_event("10.0.0.1"))
    panel = LogsPanel(store)

    store.save(_event("10.0.0.9"))
    panel._refresh_table()

    assert panel._table.selectedItems() == []
