from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QScrollArea,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from nids.signatures.brute_force import (
    DEFAULT_ATTEMPT_THRESHOLD,
    DEFAULT_BRUTE_FORCE_PORTS,
    DEFAULT_WINDOW_SECONDS as DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
)
from nids.signatures.dns_tunneling import DEFAULT_MIN_ENTROPY, DEFAULT_MIN_LABEL_LENGTH
from nids.signatures.payload_signatures import DEFAULT_PAYLOAD_SIGNATURES
from nids.signatures.port_scan import DEFAULT_PORT_THRESHOLD
from nids.signatures.sensitive_ports import DEFAULT_SENSITIVE_PORTS

_MIN_THRESHOLD = 2
_MAX_THRESHOLD = 20
_DEFAULT_WINDOW_SECONDS = 30


def _parse_ports(text: str) -> set[int]:
    ports: set[int] = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 0 < port <= 65535:
            ports.add(port)
    return ports


class SignaturesPanel(QWidget):
    """control pentru pragul de sensibilitate al semnaturii de port
    scan - vezi CONTEXT-nids.md, "prag de sensibilitate ajustabil vizual
    (slider) - control direct asupra ratei fals-pozitive/fals-negative".
    prag mic = detecteaza mai usor, dar mai multe fals-pozitive; prag
    mare = mai sigur, dar poate rata scanari mai discrete.

    + fereastra de timp optionala pentru port scan (implicit fara limita,
    comportamentul original - cumulativ pe toata sesiunea) si semnatura
    separata pentru porturi "sensibile" (SSH/RDP/SMB etc.), care
    semnaleaza imediat, indiferent de pragul de mai sus - un atacator ce
    tinteste doar 1-2 porturi critice ar trece altfel neobservat"""

    threshold_changed = Signal(int)

    def __init__(self) -> None:
        super().__init__()

        self._title_label = QLabel(
            f"Prag port scan: {DEFAULT_PORT_THRESHOLD} porturi distincte"
        )

        self._slider = QSlider(Qt.Orientation.Horizontal)
        self._slider.setMinimum(_MIN_THRESHOLD)
        self._slider.setMaximum(_MAX_THRESHOLD)
        self._slider.setValue(DEFAULT_PORT_THRESHOLD)
        self._slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self._slider.valueChanged.connect(self._on_value_changed)

        hint_label = QLabel(
            "prag mic = mai sensibil (mai multe fals-pozitive)\n"
            "prag mare = mai putin sensibil (poate rata scanari discrete)"
        )
        hint_label.setStyleSheet("color: #8a8a8a;")

        # continutul (5 grupuri de setari) a crescut prea mult ca sa
        # stea direct in panou - fara scroll, inaltimea lui minima
        # dicta inaltimea minima a INTREGII zone de andocare din
        # dreapta (Semnaturi/ML/Raspuns/Honeypot sunt tab-uite impreuna),
        # blocand redimensionarea Logurilor de jos. bug real gasit de
        # user. cu scroll, panoul poate fi oricat de mic, continutul
        # ramane accesibil prin derulare
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.addWidget(self._title_label)
        content_layout.addWidget(self._slider)
        content_layout.addWidget(hint_label)
        content_layout.addWidget(self._build_window_group())
        content_layout.addWidget(self._build_sensitive_ports_group())
        content_layout.addWidget(self._build_brute_force_group())
        content_layout.addWidget(self._build_dns_tunneling_group())
        content_layout.addWidget(self._build_payload_signatures_group())
        content_layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidget(content)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setMinimumHeight(120)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)

    def threshold(self) -> int:
        return self._slider.value()

    def _on_value_changed(self, value: int) -> None:
        self._title_label.setText(f"Prag port scan: {value} porturi distincte")
        self.threshold_changed.emit(value)

    # --- fereastra de timp ---

    def _build_window_group(self) -> QGroupBox:
        group = QGroupBox("Fereastra de timp pentru port scan")
        form = QFormLayout(group)

        self._unlimited_window = QCheckBox("fara limita (cumulativ pe toata sesiunea)")
        self._unlimited_window.setChecked(True)
        self._unlimited_window.setToolTip(
            "implicit: orice N porturi distincte contactate oricand in "
            "sesiune declanseaza evenimentul. debifat: cere ca cele N "
            "porturi sa fie atinse intr-un interval scurt (mai aproape de "
            "o scanare reala, nu doar acumulare lenta de trafic normal)"
        )
        self._unlimited_window.toggled.connect(self._on_unlimited_window_toggled)

        self._window_spin = QSpinBox()
        self._window_spin.setRange(1, 3600)
        self._window_spin.setSuffix(" s")
        self._window_spin.setValue(_DEFAULT_WINDOW_SECONDS)
        self._window_spin.setEnabled(False)

        form.addRow(self._unlimited_window)
        form.addRow("Fereastra:", self._window_spin)
        return group

    def _on_unlimited_window_toggled(self, checked: bool) -> None:
        self._window_spin.setEnabled(not checked)

    def window_seconds(self) -> float | None:
        if self._unlimited_window.isChecked():
            return None
        return float(self._window_spin.value())

    # --- porturi sensibile ---

    def _build_sensitive_ports_group(self) -> QGroupBox:
        group = QGroupBox("Porturi sensibile (semnaleaza imediat, la primul contact)")
        layout = QVBoxLayout(group)

        self._sensitive_ports_edit = QLineEdit(
            ", ".join(str(p) for p in sorted(DEFAULT_SENSITIVE_PORTS))
        )
        self._sensitive_ports_edit.setToolTip(
            "lista de porturi separate prin virgula - orice conexiune catre "
            "unul din ele e semnalata imediat, indiferent de pragul de port "
            "scan de mai sus (ex: SSH 22, Telnet 23, SMB 445, RDP 3389)"
        )
        self._sensitive_ports_edit.textChanged.connect(self._on_sensitive_ports_changed)

        self._sensitive_ports_status = QLabel()
        self._sensitive_ports_status.setStyleSheet("color: #8a8a8a;")

        layout.addWidget(self._sensitive_ports_edit)
        layout.addWidget(self._sensitive_ports_status)
        self._update_sensitive_ports_status()
        return group

    def _on_sensitive_ports_changed(self, _text: str) -> None:
        self._update_sensitive_ports_status()

    def _update_sensitive_ports_status(self) -> None:
        ports = self.sensitive_ports()
        if ports:
            self._sensitive_ports_status.setText(
                f"{len(ports)} port(uri) active: {', '.join(str(p) for p in sorted(ports))}"
            )
        else:
            self._sensitive_ports_status.setText("nicio semnatura activa (lista goala)")

    def sensitive_ports(self) -> set[int]:
        return _parse_ports(self._sensitive_ports_edit.text())

    # --- brute-force ---

    def _build_brute_force_group(self) -> QGroupBox:
        group = QGroupBox("Brute-force (incercari repetate catre acelasi serviciu)")
        form = QFormLayout(group)

        self._brute_force_threshold_spin = QSpinBox()
        self._brute_force_threshold_spin.setRange(2, 100)
        self._brute_force_threshold_spin.setValue(DEFAULT_ATTEMPT_THRESHOLD)
        self._brute_force_threshold_spin.setToolTip(
            "numarul de incercari de conectare (porturi sursa distincte) "
            "catre acelasi serviciu, in fereastra de mai jos, care "
            "declanseaza evenimentul"
        )
        form.addRow("Prag incercari:", self._brute_force_threshold_spin)

        self._brute_force_window_spin = QSpinBox()
        self._brute_force_window_spin.setRange(1, 3600)
        self._brute_force_window_spin.setSuffix(" s")
        self._brute_force_window_spin.setValue(int(DEFAULT_BRUTE_FORCE_WINDOW_SECONDS))
        form.addRow("Fereastra:", self._brute_force_window_spin)

        self._brute_force_ports_edit = QLineEdit(
            ", ".join(str(p) for p in sorted(DEFAULT_BRUTE_FORCE_PORTS))
        )
        self._brute_force_ports_edit.setToolTip(
            "servicii tinta pentru detectia de brute-force (ex: SSH 22, "
            "FTP 21, Telnet 23, RDP 3389) - porturi separate prin virgula"
        )
        form.addRow("Porturi tinta:", self._brute_force_ports_edit)

        return group

    def brute_force_threshold(self) -> int:
        return self._brute_force_threshold_spin.value()

    def brute_force_window_seconds(self) -> float:
        return float(self._brute_force_window_spin.value())

    def brute_force_ports(self) -> set[int]:
        return _parse_ports(self._brute_force_ports_edit.text())

    # --- DNS tunneling ---

    def _build_dns_tunneling_group(self) -> QGroupBox:
        group = QGroupBox("DNS tunneling (etichete de subdomeniu suspecte)")
        form = QFormLayout(group)

        self._dns_min_length_spin = QSpinBox()
        self._dns_min_length_spin.setRange(5, 63)
        self._dns_min_length_spin.setValue(DEFAULT_MIN_LABEL_LENGTH)
        self._dns_min_length_spin.setToolTip(
            "lungimea minima a etichetei (partea dinaintea primului punct "
            "din numele interogat) ca sa fie luata in calcul - etichete "
            "scurte nu spun nimic statistic despre entropie"
        )
        form.addRow("Lungime minima:", self._dns_min_length_spin)

        self._dns_min_entropy_spin = QDoubleSpinBox()
        self._dns_min_entropy_spin.setRange(0.0, 6.0)
        self._dns_min_entropy_spin.setSingleStep(0.1)
        self._dns_min_entropy_spin.setValue(DEFAULT_MIN_ENTROPY)
        self._dns_min_entropy_spin.setToolTip(
            "entropie minima (biti/caracter) - text normal (nume alese de "
            "oameni) e de regula sub 3.0; date encodate base32/base64/hex "
            "(ce foloseste tunneling-ul) se apropie de 4+ - prag mai mic = "
            "mai sensibil, mai multe fals-pozitive posibile"
        )
        form.addRow("Entropie minima:", self._dns_min_entropy_spin)

        return group

    def dns_min_label_length(self) -> int:
        return self._dns_min_length_spin.value()

    def dns_min_entropy(self) -> float:
        return self._dns_min_entropy_spin.value()

    # --- semnaturi malware in payload ---

    def _build_payload_signatures_group(self) -> QGroupBox:
        group = QGroupBox(f"Semnaturi malware in payload ({len(DEFAULT_PAYLOAD_SIGNATURES)} pattern-uri)")
        layout = QVBoxLayout(group)

        self._payload_signatures_checkbox = QCheckBox("activa (cauta pattern-uri cunoscute in payload)")
        self._payload_signatures_checkbox.setChecked(True)
        layout.addWidget(self._payload_signatures_checkbox)

        hint_label = QLabel(
            "LIMITARE REALA: functioneaza doar pe trafic NECRIPTAT - traficul "
            "HTTPS/TLS (majoritatea traficului modern) ramane opac acestei "
            "semnaturi, la fel ca oricarui NIDS bazat pe retea, nu doar acestuia"
        )
        hint_label.setWordWrap(True)
        hint_label.setStyleSheet("color: #8a8a8a;")
        layout.addWidget(hint_label)

        return group

    def payload_signatures_enabled(self) -> bool:
        return self._payload_signatures_checkbox.isChecked()
