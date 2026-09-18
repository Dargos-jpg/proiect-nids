from __future__ import annotations

from PySide6.QtWidgets import QDialog, QLabel, QTextEdit, QVBoxLayout

from nids.storage.event_store import StoredEvent
from nids.ui.widgets.ip_lookup_dialog import IpIdentifyButton


class LogEntryDetailsDialog(QDialog):
    """"vezi detalii complete" pentru UN rand din Loguri - cerut de user
    dupa o sesiune reala de 2 ore (350k+ pachete, 90 de evenimente, 88
    port scan) unde descrierile lungi (liste de porturi) erau taiate in
    celula tabelului, pe un singur rand, fara nicio cale sa vezi tot
    textul. spre deosebire de "Analizeaza aceasta conexiune cu ML"
    (disponibil DOAR pentru evenimente cu identitate ML), acest dialog
    functioneaza pentru ORICE rand - semnaturi, actiuni manuale, orice"""

    def __init__(self, entry: StoredEvent, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Detalii eveniment")
        self.resize(560, 400)

        header = QLabel(f"{entry.timestamp}  -  {entry.event_type}  ({entry.severity})")
        header.setStyleSheet("font-weight: bold; font-size: 13px;")
        header.setWordWrap(True)

        identity_parts = [f"Sursa: {entry.source_ip}"]
        if entry.dest_ip is not None:
            identity_parts.append(f"Destinatie: {entry.dest_ip}")
        if entry.src_port is not None:
            identity_parts.append(f"Port sursa: {entry.src_port}")
        if entry.dest_port is not None:
            identity_parts.append(f"Port destinatie: {entry.dest_port}")
        if entry.protocol is not None:
            identity_parts.append(f"Protocol: {entry.protocol}")
        identity = QLabel(" | ".join(identity_parts))
        identity.setWordWrap(True)

        lookup_ips = [entry.source_ip]
        if entry.dest_ip is not None:
            lookup_ips.append(entry.dest_ip)
        identify_button = IpIdentifyButton(lookup_ips, parent=self)

        description_label = QLabel("Descriere completa:")

        description = QTextEdit()
        description.setReadOnly(True)
        description.setPlainText(entry.description)

        layout = QVBoxLayout(self)
        layout.addWidget(header)
        layout.addWidget(identity)
        layout.addWidget(identify_button)
        layout.addWidget(description_label)
        layout.addWidget(description)
