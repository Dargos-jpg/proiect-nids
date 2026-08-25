from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from nids.signatures.port_scan import DEFAULT_PORT_THRESHOLD
from nids.signatures.sensitive_ports import DEFAULT_SENSITIVE_PORTS

_MIN_THRESHOLD = 2
_MAX_THRESHOLD = 20
_DEFAULT_WINDOW_SECONDS = 30


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

        layout = QVBoxLayout(self)
        layout.addWidget(self._title_label)
        layout.addWidget(self._slider)
        layout.addWidget(hint_label)
        layout.addWidget(self._build_window_group())
        layout.addWidget(self._build_sensitive_ports_group())
        layout.addStretch()

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
        ports: set[int] = set()
        for token in self._sensitive_ports_edit.text().split(","):
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
