from __future__ import annotations

from collections.abc import Callable
from typing import Union

from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nids.core.dns_lookup import IpLookupResult
from nids.ui.reverse_dns_thread import ReverseDnsThread

IpsProvider = Union[list[str], Callable[[], list[str]]]


class IpLookupResultsDialog(QDialog):
    """rezultatul unei identificari de IP - cerut de user: "cine e concret
    acest IP", nu doxxing - doar informatie standard de retea, publica:
    DNS invers (PTR, echivalentul `nslookup`/`dig -x`) + AS/organizatie/
    tara/prefix BGP (Team Cymru, vezi nids/core/dns_lookup.py) - acopera
    si IP-urile fara PTR configurat. non-modal, la fel ca celelalte
    dialoguri din aplicatie. reutilizat atat pentru "Top IP-uri sursa"
    (TrafficChartPanel) cat si pentru IP-urile unei conexiuni/eveniment
    analizat (ConnectionInspectorDialog/LogEntryDetailsDialog)"""

    _COLUMNS = ["IP", "nume de host (PTR)", "AS", "organizatie / ISP", "tara", "prefix BGP"]

    def __init__(self, results: dict[str, IpLookupResult], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("IP-uri identificate")
        self.resize(1000, 320)

        table = QTableWidget(len(results), len(self._COLUMNS))
        table.setHorizontalHeaderLabels(self._COLUMNS)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        for row, (ip, result) in enumerate(results.items()):
            asn_info = result.asn_info
            table.setItem(row, 0, QTableWidgetItem(ip))
            table.setItem(row, 1, QTableWidgetItem(result.hostname or "(fara inregistrare PTR)"))
            table.setItem(row, 2, QTableWidgetItem(asn_info.asn if asn_info else "-"))
            table.setItem(row, 3, QTableWidgetItem(asn_info.organization if asn_info else "-"))
            table.setItem(row, 4, QTableWidgetItem(asn_info.country if asn_info else "-"))
            table.setItem(row, 5, QTableWidgetItem(asn_info.bgp_prefix if asn_info else "-"))

        # BUG REAL gasit de user: latimea implicita a coloanelor taia
        # continutul (mai ales prefixul BGP) - IP/AS/tara/prefix se
        # redimensioneaza dupa continutul lor efectiv (nu se schimba, nu
        # au nevoie de stretch), doar hostname-ul PTR si organizatia
        # (variaza mult in lungime) impart spatiul ramas
        header = table.horizontalHeader()
        for column in (0, 2, 4, 5):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        layout = QVBoxLayout(self)
        layout.addWidget(table)


class IpIdentifyButton(QPushButton):
    """buton reutilizabil "Identifica IP-uri" - porneste rezolvarea (PTR +
    Team Cymru) pe un thread separat si arata rezultatul in
    IpLookupResultsDialog. `ips` poate fi o lista fixa (IP-urile unei
    conexiuni deja cunoscute la construirea dialogului) sau o functie fara
    argumente care intoarce lista curenta (ex: top talkers, care se schimba
    in timp) - evaluata abia la click, nu la construire"""

    def __init__(self, ips: IpsProvider, parent: QWidget | None = None, label: str = "Identifica IP-uri") -> None:
        super().__init__(label, parent)
        self._ips_provider = ips if callable(ips) else (lambda fixed=list(ips): fixed)
        self._default_label = label
        self._dns_thread: ReverseDnsThread | None = None
        self._lookup_dialogs: list[IpLookupResultsDialog] = []
        self.setToolTip(
            "DNS invers (PTR) + AS/organizatie/tara/prefix BGP (Team Cymru) - "
            "informatie standard de retea, publica (ca nslookup/dig -x sau "
            "whois), nu date personale"
        )
        self.clicked.connect(self._on_clicked)

    def _on_clicked(self) -> None:
        # elimina duplicatele, pastrand ordinea (ex: sursa == destinatie e
        # posibil pentru trafic local, nu are sens sa apara de doua ori)
        ips = list(dict.fromkeys(self._ips_provider()))
        if not ips:
            return

        self.setEnabled(False)
        self.setText("se cauta...")

        self._dns_thread = ReverseDnsThread(ips, parent=self)
        self._dns_thread.succeeded.connect(self._on_resolved)
        self._dns_thread.failed.connect(self._on_failed)
        self._dns_thread.finished.connect(self._on_thread_finished)
        self._dns_thread.finished.connect(self._dns_thread.deleteLater)
        self._dns_thread.start()

    def _on_resolved(self, results: dict[str, IpLookupResult]) -> None:
        dialog = IpLookupResultsDialog(results, parent=self)
        self._lookup_dialogs.append(dialog)
        dialog.finished.connect(lambda: self._lookup_dialogs.remove(dialog))
        dialog.show()

    def _on_failed(self, message: str) -> None:
        self.setText(f"cautare esuata: {message}")

    def _on_thread_finished(self) -> None:
        self._dns_thread = None
        self.setEnabled(True)
        if self.text() == "se cauta...":
            self.setText(self._default_label)
