from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nids.core.report import save_report
from nids.storage.event_store import EventStore, StoredEvent

_COLUMNS = ["timp", "tip", "sursa", "severitate", "descriere"]
_REFRESH_INTERVAL_MS = 2000
_ALL_SOURCES = "toate sursele"


class LogsPanel(QWidget):
    """istoricul persistat de evenimente - audit trail. + cronologie de
    incident: filtrand pe o singura sursa, evenimentele apar in ordine
    CRONOLOGICA (cele mai vechi primele) - o naratiune, nu doar o lista
    plata de alerte, vezi CONTEXT-nids.md. citeste EventStore periodic
    (QTimer), la fel ca ResponsePanel"""

    analyze_requested = Signal(object)  # emite StoredEvent-ul randului selectat

    def __init__(self, event_store: EventStore) -> None:
        super().__init__()
        self._event_store = event_store
        self._search_text = ""

        self._source_filter = QComboBox()
        self._source_filter.addItem(_ALL_SOURCES)
        self._source_filter.currentTextChanged.connect(self._refresh_table)

        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("Cauta (sursa, tip, descriere)...")
        self._search_box.textChanged.connect(self._on_search_changed)

        self._export_button = QPushButton("Exporta raport HTML...")
        self._export_button.clicked.connect(self._on_export_clicked)

        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("Sursa:"))
        filter_bar.addWidget(self._source_filter)
        filter_bar.addWidget(self._search_box)
        filter_bar.addStretch()
        filter_bar.addWidget(self._export_button)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(
            len(_COLUMNS) - 1, QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)

        layout = QVBoxLayout(self)
        layout.addLayout(filter_bar)
        layout.addWidget(self._table)

        self._refresh()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(_REFRESH_INTERVAL_MS)

    def stop(self) -> None:
        """opreste timer-ul de refresh periodic - trebuie apelat inainte
        de EventStore.close() la inchiderea aplicatiei. BUG REAL gasit de
        user: fara asta, un refresh programat mai putea apuca sa ruleze
        DUPA ce conexiunea SQLite era deja inchisa (sqlite3.ProgrammingError:
        Cannot operate on a closed database) - vezi MainWindow.closeEvent()"""
        self._timer.stop()

    def _refresh(self) -> None:
        self._refresh_source_list()
        self._refresh_table()

    def _refresh_source_list(self) -> None:
        current = self._source_filter.currentText()
        expected = [_ALL_SOURCES] + self._event_store.distinct_sources()
        existing = [self._source_filter.itemText(i) for i in range(self._source_filter.count())]
        if existing == expected:
            return

        self._source_filter.blockSignals(True)
        self._source_filter.clear()
        self._source_filter.addItems(expected)
        index = self._source_filter.findText(current)
        self._source_filter.setCurrentIndex(index if index >= 0 else 0)
        self._source_filter.blockSignals(False)

    def _on_export_clicked(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Salveaza raport", "raport-nids.html", "HTML (*.html)"
        )
        if not path:
            return

        selected = self._source_filter.currentText()
        if not selected or selected == _ALL_SOURCES:
            events = self._event_store.recent(limit=10_000)
            title = "Raport NIDS - toate evenimentele"
        else:
            events = self._event_store.events_for_source(selected, limit=10_000)
            title = f"Raport NIDS - cronologie {selected}"

        save_report(events, Path(path), title=title)

    def _refresh_table(self) -> None:
        """BUG REAL gasit de user: tabelul se reconstruieste integral la
        fiecare refresh (2s) - Qt pastreaza selectia pe INDEXUL de rand,
        nu pe eveniment. cum cele mai noi randuri apar primele, un
        eveniment nou aparut impingea tot ce era mai vechi cu un rand mai
        jos, iar selectia "aluneca" vizual pe alt eveniment decat cel pe
        care userul chiar il selectase. fix: retine id-urile (StoredEvent.id,
        din SQLite) randurilor selectate INAINTE de reconstructie, re-aplica
        selectia DUPA, pe randul unde a ajuns acum acelasi id"""
        selected = self._source_filter.currentText()
        if not selected or selected == _ALL_SOURCES:
            rows = self._event_store.recent()
        else:
            rows = self._event_store.events_for_source(selected)

        selected_ids = self._selected_entry_ids()

        self._table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            time_item = QTableWidgetItem(entry.timestamp)
            time_item.setData(Qt.ItemDataRole.UserRole, entry)
            self._table.setItem(row, 0, time_item)
            self._table.setItem(row, 1, QTableWidgetItem(entry.event_type))
            self._table.setItem(row, 2, QTableWidgetItem(entry.source_ip))
            self._table.setItem(row, 3, QTableWidgetItem(entry.severity))
            self._table.setItem(row, 4, QTableWidgetItem(entry.description))

        self._restore_selection(selected_ids)
        self._apply_search_filter()

    def _selected_entry_ids(self) -> set[int]:
        ids: set[int] = set()
        for item in self._table.selectedItems():
            if item.column() != 0:
                continue
            entry = item.data(Qt.ItemDataRole.UserRole)
            if entry is not None:
                ids.add(entry.id)
        return ids

    def _restore_selection(self, ids: set[int]) -> None:
        if not ids:
            return
        self._table.clearSelection()
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            entry = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            if entry is not None and entry.id in ids:
                self._table.selectRow(row)

    # --- cautare libera (in plus fata de filtrul de sursa) ---

    def _on_search_changed(self, text: str) -> None:
        self._search_text = text.strip().lower()
        self._apply_search_filter()

    def _apply_search_filter(self) -> None:
        for row in range(self._table.rowCount()):
            self._table.setRowHidden(row, not self._row_matches(row))

    def _row_matches(self, row: int) -> bool:
        if not self._search_text:
            return True
        for column in range(self._table.columnCount()):
            item = self._table.item(row, column)
            if item is not None and self._search_text in item.text().lower():
                return True
        return False

    # --- deschidere analiza completa ML pentru un rand ---

    def _entry_at(self, position) -> StoredEvent | None:
        row = self._table.rowAt(position.y())
        if row < 0:
            return None
        item = self._table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _on_context_menu(self, position) -> None:
        entry = self._entry_at(position)
        if entry is None:
            return

        menu = QMenu(self)
        action = menu.addAction("Analizeaza aceasta conexiune cu ML")
        action.triggered.connect(lambda: self.analyze_requested.emit(entry))
        menu.exec(self._table.viewport().mapToGlobal(position))
