from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from nids.honeypot.listener import HoneypotHit, event_from_honeypot_hit
from nids.storage.event_store import EventStore
from nids.ui.honeypot_thread import HoneypotThread

_DEFAULT_PORTS = "2222, 8080, 3306"


class HoneypotPanel(QWidget):
    """serviciu-momeala: asculta pe porturi fara niciun scop legitim pe
    acest calculator - orice conexiune acolo e prin definitie suspecta,
    spre deosebire de semnaturi/ML unde exista mereu risc de fals-pozitiv.

    self-continut (nu are nevoie sa fie citit de alt panou, spre deosebire
    de SignaturesPanel/MlSettings/ResponseSettings) - configurarea
    porturilor ramane locala, doar scrie in EventStore ca orice alta sursa"""

    def __init__(self, event_store: EventStore) -> None:
        super().__init__()
        self._event_store = event_store
        self._thread: HoneypotThread | None = None
        self._hits = 0
        self._had_bind_error = False

        self._ports_edit = QLineEdit(_DEFAULT_PORTS)
        self._ports_edit.setToolTip(
            "porturi separate prin virgula pe care honeypot-ul asculta - "
            "alege porturi mari (>1024, nu cer drepturi de administrator) "
            "care nu sunt deja folosite de un serviciu real pe acest calculator"
        )

        self._toggle_button = QPushButton("Porneste honeypot")
        self._toggle_button.clicked.connect(self._on_toggle_clicked)

        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("Porturi:"))
        top_bar.addWidget(self._ports_edit)
        top_bar.addWidget(self._toggle_button)

        self._status_label = QLabel("honeypot oprit")
        self._status_label.setWordWrap(True)

        hint_label = QLabel(
            "orice conexiune pe porturile de mai jos e semnalata imediat, cu "
            "severitate ridicata - niciun serviciu real nu ruleaza acolo, deci "
            "nu exista risc de fals-pozitiv (spre deosebire de semnaturi/ML)"
        )
        hint_label.setWordWrap(True)
        hint_label.setStyleSheet("color: #8a8a8a;")

        layout = QVBoxLayout(self)
        layout.addLayout(top_bar)
        layout.addWidget(self._status_label)
        layout.addWidget(hint_label)
        layout.addStretch()

    def ports(self) -> list[int]:
        ports: list[int] = []
        for token in self._ports_edit.text().split(","):
            token = token.strip()
            if not token:
                continue
            try:
                port = int(token)
            except ValueError:
                continue
            if 0 < port <= 65535:
                ports.append(port)
        return ports

    def _on_toggle_clicked(self) -> None:
        if self._thread is None:
            self._start()
        else:
            self._stop()

    def _start(self) -> None:
        ports = self.ports()
        if not ports:
            self._status_label.setText("adauga cel putin un port valid")
            return

        self._hits = 0
        self._had_bind_error = False
        self._thread = HoneypotThread(ports)
        self._thread.hit_detected.connect(self._on_hit)
        self._thread.bind_error.connect(self._on_bind_error)
        self._thread.finished.connect(self._on_thread_finished)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

        self._toggle_button.setText("Opreste honeypot")
        self._ports_edit.setEnabled(False)
        self._status_label.setText(
            f"honeypot activ pe porturile: {', '.join(str(p) for p in ports)}"
        )

    def stop(self) -> None:
        """oprire fara asteptare - expusa public ca sa poata fi apelata
        din MainWindow.closeEvent(). spre deosebire de DashboardPanel.shutdown(),
        nu are nevoie sa astepte sincron: honeypot-ul nu are stare de
        salvat (niciun model, niciun buffer) - un thread care mai
        ruleaza cateva sute de ms la inchiderea aplicatiei e safe"""
        if self._thread is not None:
            self._thread.stop()

    def _stop(self) -> None:
        self._toggle_button.setEnabled(False)
        self._status_label.setText("se opreste honeypot-ul...")
        self.stop()

    def _on_thread_finished(self) -> None:
        self._thread = None
        self._toggle_button.setText("Porneste honeypot")
        self._toggle_button.setEnabled(True)
        self._ports_edit.setEnabled(True)
        # daca toate porturile au esuat la bind, thread-ul se termina
        # aproape imediat - nu suprascriem mesajul de eroare deja afisat
        # cu un generic "oprit", care ar ascunde de ce nu a pornit
        if not self._had_bind_error:
            self._status_label.setText("honeypot oprit")

    def _on_hit(self, hit: HoneypotHit) -> None:
        self._hits += 1
        self._event_store.save(event_from_honeypot_hit(hit))
        self._status_label.setText(
            f"honeypot activ - {self._hits} conexiune(i) prinsa(e) pana acum "
            f"(ultima: {hit.src_ip} -> port {hit.dst_port})"
        )

    def _on_bind_error(self, port: int, message: str) -> None:
        self._had_bind_error = True
        self._status_label.setText(f"nu s-a putut porni pe portul {port}: {message}")
