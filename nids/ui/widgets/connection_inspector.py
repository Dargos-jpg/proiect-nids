from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from nids.core.inspect import ConnectionAssessment
from nids.ml.features.nsl_kdd_style import to_feature_frame


def _verdict_label(prediction: int | None) -> str:
    if prediction is None:
        return "indisponibil"
    return "ATAC/ANOMALIE" if prediction == 1 else "normal"


def _make_table(headers: list[str], rows: list[tuple]) -> QTableWidget:
    table = QTableWidget(len(rows), len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.horizontalHeader().setSectionResizeMode(
        len(headers) - 1, QHeaderView.ResizeMode.Stretch
    )
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    for r, values in enumerate(rows):
        for c, value in enumerate(values):
            table.setItem(r, c, QTableWidgetItem(str(value)))
    return table


class ConnectionInspectorDialog(QDialog):
    """analiza completa la cerere a unei conexiuni - raspunde la "de ce
    (nu) a dat flag acest trafic". non-modal (userul poate continua sa
    monitorizeze cat timp se uita), o instanta separata per conexiune
    analizata"""

    def __init__(self, assessment: ConnectionAssessment, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Analiza conexiune")
        self.resize(560, 620)

        record = assessment.record

        header = QLabel(
            f"{record.src_ip}:{record.src_port}  →  {record.dst_ip}:{record.dst_port}  "
            f"({record.protocol_type} / {record.service})"
        )
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        header.setWordWrap(True)

        local_verdict = (
            "inca invata"
            if assessment.local_is_learning
            else _verdict_label(assessment.local_prediction)
        )
        verdict = QLabel(
            f"Model expert: {_verdict_label(assessment.expert_prediction)}"
            f"    |    Model local: {local_verdict}"
        )
        verdict.setStyleSheet("font-weight: bold;")

        explanation = QLabel(assessment.explanation)
        explanation.setWordWrap(True)

        expert_rows = [
            (c.feature, c.value, f"{c.importance:.1%}") for c in assessment.expert_top_features
        ]
        expert_table = _make_table(["feature", "valoare", "importanta"], expert_rows)

        local_rows = [
            (d.feature, f"{d.value:g}", f"{d.baseline_mean:.2f}", f"{d.z_score:+.2f}")
            for d in assessment.local_deviations
        ]
        local_table = _make_table(
            ["feature", "valoare", "medie normal", "deviatie (z-score)"], local_rows
        )

        categorical_rows = [
            (r.feature, r.value, f"{r.frequency:.0%}")
            for r in assessment.local_categorical_rarities
        ]
        categorical_table = _make_table(["feature", "valoare", "frecventa in buffer"], categorical_rows)

        raw_values = to_feature_frame([record]).iloc[0].to_dict()
        all_values_rows = sorted(raw_values.items())
        all_values_table = _make_table(["feature", "valoare"], all_values_rows)

        layout = QVBoxLayout(self)
        layout.addWidget(header)
        layout.addWidget(verdict)
        layout.addWidget(explanation)
        layout.addWidget(QLabel("De ce (model expert) - importanta globala a features:"))
        layout.addWidget(expert_table)
        layout.addWidget(
            QLabel(
                "Comparatie cu traficul normal (model local) - deviatie mare "
                "(|z| mare) = neobisnuit fata de reteaua ta:"
            )
        )
        layout.addWidget(local_table)
        layout.addWidget(
            QLabel(
                "Combinatii categorice (model local) - protocol/serviciu/stare - "
                "frecventa mica = combinatie rara in traficul tau, chiar daca valorile "
                "numerice de mai sus nu par extreme:"
            )
        )
        layout.addWidget(categorical_table)
        layout.addWidget(QLabel("Toate cele 28 de valori folosite de modele:"))
        layout.addWidget(all_values_table)
