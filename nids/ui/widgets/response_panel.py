from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nids.response.manager import BlockManager

_ACTIVE_COLUMNS = ["IP", "motiv", "expira la"]
_HISTORY_COLUMNS = ["IP", "motiv", "blocat la", "incheiat la", "incheiat prin"]
_REFRESH_INTERVAL_MS = 1000


class ResponsePanel(QWidget):
    """arata blocarile IP active si permite deblocare manuala, + un
    istoric al blocarilor din aceasta sesiune (inclusiv cele deja
    expirate/ridicate) - fara istoric, un block care expira dispare pur
    si simplu din tabel, fara nicio urma vizibila ca s-a intamplat ceva
    (userul a semnalat asta ca fiind neclar). citeste BlockManager
    periodic (QTimer, ruleaza pe thread-ul UI) in loc sa fie notificata
    direct din threading.Timer-ul de expirare, care ruleaza pe alt thread
    - widget-urile Qt nu pot fi atinse decat din thread-ul UI"""

    def __init__(self, block_manager: BlockManager) -> None:
        super().__init__()
        self._block_manager = block_manager

        self._table = QTableWidget(0, len(_ACTIVE_COLUMNS))
        self._table.setHorizontalHeaderLabels(_ACTIVE_COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        unblock_button = QPushButton("Deblocheaza selectia")
        unblock_button.clicked.connect(self._on_unblock_clicked)

        button_bar = QHBoxLayout()
        button_bar.addWidget(unblock_button)
        button_bar.addStretch()

        self._history_table = QTableWidget(0, len(_HISTORY_COLUMNS))
        self._history_table.setHorizontalHeaderLabels(_HISTORY_COLUMNS)
        self._history_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        layout = QVBoxLayout(self)
        layout.addLayout(button_bar)
        layout.addWidget(self._table)
        layout.addWidget(QLabel("Istoric blocari (aceasta sesiune):"))
        layout.addWidget(self._history_table)

        self._refresh()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(_REFRESH_INTERVAL_MS)

    def _refresh(self) -> None:
        blocks = self._block_manager.active_blocks()
        self._table.setRowCount(len(blocks))
        for row, entry in enumerate(blocks):
            self._table.setItem(row, 0, QTableWidgetItem(entry.ip))
            self._table.setItem(row, 1, QTableWidgetItem(entry.reason))
            self._table.setItem(
                row, 2, QTableWidgetItem(entry.expires_at.strftime("%H:%M:%S"))
            )

        history = self._block_manager.history()
        self._history_table.setRowCount(len(history))
        for row, entry in enumerate(reversed(history)):  # cele mai recente primele
            self._history_table.setItem(row, 0, QTableWidgetItem(entry.ip))
            self._history_table.setItem(row, 1, QTableWidgetItem(entry.reason))
            self._history_table.setItem(
                row, 2, QTableWidgetItem(entry.blocked_at.strftime("%H:%M:%S"))
            )
            ended_text = entry.unblocked_at.strftime("%H:%M:%S") if entry.unblocked_at else "-"
            self._history_table.setItem(row, 3, QTableWidgetItem(ended_text))
            self._history_table.setItem(
                row, 4, QTableWidgetItem(entry.ended_by or "activa")
            )

    def _on_unblock_clicked(self) -> None:
        for item in self._table.selectedItems():
            if item.column() == 0:
                self._block_manager.unblock(item.text())
        self._refresh()
