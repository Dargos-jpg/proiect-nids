from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nids.scanner.vulnerability_scan import DEFAULT_SCAN_PORTS, PortScanResult, event_from_scan_result
from nids.storage.event_store import EventStore
from nids.ui.scan_thread import ScanThread

_COLUMNS = ["host", "port", "serviciu", "banner", "risc cunoscut"]
_DEFAULT_TARGETS_HINT = "ex: 192.168.1.1, 192.168.1.50"


class ScannerPanel(QWidget):
    """scanner de porturi/vulnerabilitati cunoscute, limitat STRICT la
    reteaua privata proprie (vezi is_scannable_target()) - tinte introduse
    explicit de user, nu descoperire automata a intregii retele (human-in-
    the-loop, la fel ca blocarea manuala de IP). self-continut, la fel ca
    HoneypotPanel - doar scrie in EventStore, nu are nevoie sa fie citit
    de alt panou"""

    def __init__(self, event_store: EventStore) -> None:
        super().__init__()
        self._event_store = event_store
        self._thread: ScanThread | None = None

        self._targets_edit = QLineEdit()
        self._targets_edit.setPlaceholderText(_DEFAULT_TARGETS_HINT)
        self._targets_edit.setToolTip(
            "adrese IP din reteaua locala (private), separate prin virgula - "
            "scanarea unei adrese publice e refuzata"
        )

        self._scan_button = QPushButton("Scaneaza")
        self._scan_button.clicked.connect(self._on_scan_clicked)

        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("Tinte:"))
        top_bar.addWidget(self._targets_edit)
        top_bar.addWidget(self._scan_button)

        self._status_label = QLabel("gata de scanare")
        self._status_label.setWordWrap(True)

        hint_label = QLabel(
            "scanare TCP connect simpla (ca Test-NetConnection), fara nimic ascuns/"
            "evaziv - doar porturi din reteaua LOCALA proprie, note de risc bazate "
            "pe caracteristici cunoscute ale protocolului, NU o baza de date de CVE-uri"
        )
        hint_label.setWordWrap(True)
        hint_label.setStyleSheet("color: #8a8a8a;")

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(
            len(_COLUMNS) - 1, QHeaderView.ResizeMode.Stretch
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout = QVBoxLayout(self)
        layout.addLayout(top_bar)
        layout.addWidget(self._status_label)
        layout.addWidget(hint_label)
        layout.addWidget(self._table)

    def stop(self) -> None:
        """asteapta (sincron, cu timeout) thread-ul de scanare sa se
        termine, daca mai ruleaza - altfel rezultatul ar putea ajunge in
        _on_scan_succeeded() (deci event_store.save()) DUPA ce MainWindow
        a inchis deja EventStore, acelasi tipar de bug deja gasit o data
        la LogsPanel (vezi BUGS.md - "Cannot operate on a closed database").
        scanarea e oricum scurta (cateva secunde), asteptarea la inchidere
        nu e vizibila in practica"""
        if self._thread is not None:
            self._thread.wait(3000)

    def targets(self) -> list[str]:
        return [t.strip() for t in self._targets_edit.text().split(",") if t.strip()]

    def _on_scan_clicked(self) -> None:
        targets = self.targets()
        if not targets:
            self._status_label.setText("adauga cel putin o adresa IP din reteaua locala")
            return

        self._table.setRowCount(0)
        self._scan_button.setEnabled(False)
        self._targets_edit.setEnabled(False)
        self._status_label.setText(f"se scaneaza: {', '.join(targets)}...")

        self._thread = ScanThread(targets, DEFAULT_SCAN_PORTS)
        self._thread.succeeded.connect(self._on_scan_succeeded)
        self._thread.failed.connect(self._on_scan_failed)
        self._thread.finished.connect(self._on_thread_finished)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _on_scan_succeeded(self, results: list[PortScanResult]) -> None:
        self._table.setRowCount(len(results))
        for row, result in enumerate(results):
            self._fill_row(row, result)
            self._event_store.save(event_from_scan_result(result))

        if results:
            self._status_label.setText(f"{len(results)} port(uri) deschis(e) gasit(e)")
        else:
            self._status_label.setText("niciun port deschis gasit din lista verificata")

    def _on_scan_failed(self, message: str) -> None:
        self._status_label.setText(f"scanare esuata: {message}")

    def _on_thread_finished(self) -> None:
        self._thread = None
        self._scan_button.setEnabled(True)
        self._targets_edit.setEnabled(True)

    def _fill_row(self, row: int, result: PortScanResult) -> None:
        values = [
            result.host,
            str(result.port),
            result.service,
            result.banner or "-",
            "; ".join(result.risk_notes) if result.risk_notes else "-",
        ]
        for column, value in enumerate(values):
            self._table.setItem(row, column, QTableWidgetItem(value))
