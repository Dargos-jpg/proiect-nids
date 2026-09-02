from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLineEdit,
    QMenu,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nids.capture.packet_meta import PacketMeta

_COLUMNS = ["timp", "sursa", "port sursa", "destinatie", "port dest", "protocol", "dimensiune"]
# 500 (limita initiala) insemna doar ~5 secunde de istoric la un volum
# real de trafic (~100 pachete/secunda, semnalat de user) - imposibil sa
# gasesti manual ceva acolo dupa ce trec cateva secunde. 5000 acopera
# ~50s la acelasi volum - suficient sa prinzi rezultatul unui test rulat
# manual, fara sa incarce vizibil UI-ul (filtrarea ramane O(randuri),
# rapida chiar si la acest volum)
_MAX_ROWS = 5000


class TrafficPanel(QWidget):
    """traficul brut, pachet cu pachet - spre deosebire de Dashboard/
    Loguri, care arata doar evenimentele (alertele). un NIDS real nu
    arata tot traficul in jurnalul de alerte (ar fi ilizibil la volum
    mare), dar userul tot vrea sa poata vedea "cu ochii lui" ca aplicatia
    chiar proceseaza trafic. limitat la ultimele _MAX_ROWS pachete, ca
    sesiunile lungi de monitorizare sa nu incetineasca UI-ul"""

    analyze_requested = Signal(object)  # emite PacketMeta-ul randului selectat

    def __init__(self) -> None:
        super().__init__()

        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText(
            "Cauta (IP sursa/destinatie, port, protocol)..."
        )
        self._search_box.textChanged.connect(self._apply_filter)
        self._filter_text = ""

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
        layout.addWidget(self._search_box)
        layout.addWidget(self._table)

    def clear(self) -> None:
        self._table.setRowCount(0)

    def add_packet(self, pkt: PacketMeta) -> None:
        """pentru monitorizare live - un pachet nou apare sus, cele mai
        vechi cad de la coada cand se depaseste _MAX_ROWS"""
        self._table.insertRow(0)
        self._fill_row(0, pkt)
        self._table.setRowHidden(0, not self._row_matches(0))

        if self._table.rowCount() > _MAX_ROWS:
            self._table.removeRow(self._table.rowCount() - 1)

    def load_packets(self, packets: list[PacketMeta]) -> None:
        """pentru un PCAP incarcat dintr-o data - inlocuieste tot"""
        shown = packets[-_MAX_ROWS:] if len(packets) > _MAX_ROWS else packets
        self._table.setRowCount(len(shown))
        for row, pkt in enumerate(shown):
            self._fill_row(row, pkt)
        self._apply_filter(self._filter_text)

    def _apply_filter(self, text: str) -> None:
        """filtrare client-side (setRowHidden), nu re-interogare - tabelul
        e deja limitat la _MAX_ROWS randuri, deci costul e neglijabil.
        cautare libera pe toate coloanele (IP, port, protocol), nu doar
        adresa - utilizatorul poate vrea sa caute si dupa un port anume"""
        self._filter_text = text.strip().lower()
        for row in range(self._table.rowCount()):
            self._table.setRowHidden(row, not self._row_matches(row))

    def _row_matches(self, row: int) -> bool:
        if not self._filter_text:
            return True
        for column in range(self._table.columnCount()):
            item = self._table.item(row, column)
            if item is not None and self._filter_text in item.text().lower():
                return True
        return False

    def _fill_row(self, row: int, pkt: PacketMeta) -> None:
        values = [
            datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S"),
            pkt.src_ip,
            str(pkt.src_port) if pkt.src_port is not None else "-",
            pkt.dst_ip,
            str(pkt.dst_port) if pkt.dst_port is not None else "-",
            pkt.protocol,
            str(pkt.length),
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 0:
                item.setData(Qt.ItemDataRole.UserRole, pkt)
            self._table.setItem(row, column, item)

    def _packet_at(self, position) -> PacketMeta | None:
        row = self._table.rowAt(position.y())
        if row < 0:
            return None
        item = self._table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _on_context_menu(self, position) -> None:
        pkt = self._packet_at(position)
        if pkt is None:
            return

        menu = QMenu(self)
        action = menu.addAction("Analizeaza aceasta conexiune cu ML")
        action.triggered.connect(lambda: self.analyze_requested.emit(pkt))
        menu.exec(self._table.viewport().mapToGlobal(position))
