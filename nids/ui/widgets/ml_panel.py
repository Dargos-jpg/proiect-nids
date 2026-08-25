from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from nids.core.ml_settings import MlSettings

if TYPE_CHECKING:
    from nids.ui.widgets.dashboard_panel import DashboardPanel

_REFRESH_INTERVAL_MS = 1000
_DEFAULT_MANUAL_CONTAMINATION = 0.1


class MlPanel(QWidget):
    """status informativ al celor doua modele ML (fara controale, poll
    prin DashboardPanel - la fel ca ResponsePanel/LogsPanel) + setari
    pentru modelul local, singurul care se antreneaza continuu pe
    traficul utilizatorului (modelul expert e deja pre-antrenat, nimic
    de ajustat live acolo).

    setarile sunt citite doar la urmatoarea pornire a monitorizarii
    (DashboardPanel._start_monitoring), nu se aplica instant in mijlocul
    unei sesiuni deja pornite - acelasi comportament ca pragul de port
    scan din SignaturesPanel"""

    def __init__(self, dashboard: DashboardPanel, settings: MlSettings) -> None:
        super().__init__()
        self._dashboard = dashboard
        self._settings = settings

        self._expert_label = QLabel()
        self._local_label = QLabel()
        self._local_label.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addWidget(self._expert_label)
        layout.addWidget(self._local_label)
        layout.addWidget(self._build_settings_group())
        layout.addStretch()

        self._refresh()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(_REFRESH_INTERVAL_MS)

    def _refresh(self) -> None:
        if self._dashboard.expert_model_loaded():
            self._expert_label.setText("Model expert: incarcat (Random Forest, NSL-KDD)")
        else:
            self._expert_label.setText(
                "Model expert: LIPSA - ruleaza scripts/train_expert_model.py"
            )

        status = self._dashboard.local_model_status()
        if status is None:
            self._local_label.setText("Model local: monitorizarea live nu ruleaza momentan")
        elif status.is_learning:
            self._local_label.setText(
                "Model local: in modul invatare "
                f"({status.samples_collected}/{status.min_training_samples} conexiuni "
                "colectate, continua de la sesiunea anterioara daca exista)"
            )
        else:
            self._local_label.setText(
                "Model local: activ - antrenat pe ultimele "
                f"{status.samples_collected} conexiuni (fereastra glisanta, se "
                "reantreneaza periodic, continua intre sesiuni)"
            )

    # --- setari (aplicate la urmatoarea pornire a monitorizarii) ---

    def _build_settings_group(self) -> QGroupBox:
        group = QGroupBox("Setari model local (aplicate la urmatoarea pornire a monitorizarii)")
        form = QFormLayout(group)

        min_samples = QSpinBox()
        min_samples.setRange(5, 1000)
        min_samples.setValue(self._settings.min_training_samples)
        min_samples.setToolTip(
            "cate conexiuni trebuie colectate inainte ca modelul local sa "
            "iasa din modul invatare si sa inceapa sa evalueze"
        )
        min_samples.valueChanged.connect(self._on_min_training_samples_changed)
        form.addRow("Prag antrenare initiala:", min_samples)

        retrain_every = QSpinBox()
        retrain_every.setRange(1, 500)
        retrain_every.setValue(self._settings.retrain_every)
        retrain_every.setToolTip("dupa cate conexiuni noi se reantreneaza modelul local activ")
        retrain_every.valueChanged.connect(self._on_retrain_every_changed)
        form.addRow("Reantreneaza la fiecare N conexiuni:", retrain_every)

        buffer_size = QSpinBox()
        buffer_size.setRange(50, 20000)
        buffer_size.setSingleStep(50)
        buffer_size.setValue(self._settings.max_buffer_size)
        buffer_size.setToolTip(
            "cate conexiuni recente tine minte modelul local (fereastra "
            "glisanta) - cele mai vechi ies din fereastra pe masura ce intra altele noi"
        )
        buffer_size.valueChanged.connect(self._on_max_buffer_size_changed)
        form.addRow("Fereastra glisanta (conexiuni):", buffer_size)

        self._contamination_spin = QDoubleSpinBox()
        self._contamination_spin.setRange(0.01, 0.5)
        self._contamination_spin.setSingleStep(0.01)
        self._contamination_spin.setValue(self._settings.contamination or _DEFAULT_MANUAL_CONTAMINATION)
        self._contamination_spin.setEnabled(self._settings.contamination is not None)
        self._contamination_spin.valueChanged.connect(self._on_contamination_changed)

        self._auto_contamination = QCheckBox("automat (recomandat)")
        self._auto_contamination.setChecked(self._settings.contamination is None)
        self._auto_contamination.setToolTip(
            "contamination - rata asteptata de anomalii in trafic; controleaza "
            "cat de usor Isolation Forest marcheaza ceva drept anomalie. "
            "'automat' foloseste euristica implicita din sklearn"
        )
        self._auto_contamination.toggled.connect(self._on_auto_contamination_toggled)

        contamination_row = QHBoxLayout()
        contamination_row.addWidget(self._auto_contamination)
        contamination_row.addWidget(self._contamination_spin)
        form.addRow("Sensibilitate anomalii:", contamination_row)

        strict = QCheckBox("raporteaza doar cand ambele modele sunt de acord")
        strict.setChecked(self._settings.strict_reporting)
        strict.setToolTip(
            "implicit (nebifat): orice semnal, chiar de la un singur model, "
            "genereaza un eveniment. bifat: mai putine alerte, dar mai sigure - "
            "ignora cazurile in care doar un model semnaleaza"
        )
        strict.toggled.connect(self._on_strict_reporting_toggled)
        form.addRow(strict)

        interval = QSpinBox()
        interval.setRange(1, 60)
        interval.setSuffix(" s")
        interval.setValue(self._settings.evaluation_interval_ms // 1000)
        interval.setToolTip("cat de des sunt reevaluate conexiunile noi in monitorizarea live")
        interval.valueChanged.connect(self._on_evaluation_interval_changed)
        form.addRow("Interval reevaluare live:", interval)

        return group

    def _on_min_training_samples_changed(self, value: int) -> None:
        self._settings.min_training_samples = value

    def _on_retrain_every_changed(self, value: int) -> None:
        self._settings.retrain_every = value

    def _on_max_buffer_size_changed(self, value: int) -> None:
        self._settings.max_buffer_size = value

    def _on_auto_contamination_toggled(self, checked: bool) -> None:
        self._contamination_spin.setEnabled(not checked)
        self._settings.contamination = None if checked else self._contamination_spin.value()

    def _on_contamination_changed(self, value: float) -> None:
        if not self._auto_contamination.isChecked():
            self._settings.contamination = value

    def _on_strict_reporting_toggled(self, checked: bool) -> None:
        self._settings.strict_reporting = checked

    def _on_evaluation_interval_changed(self, value: int) -> None:
        self._settings.evaluation_interval_ms = value * 1000
