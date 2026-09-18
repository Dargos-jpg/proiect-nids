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
from nids.core.ml_combination import severity_from_local_score
from nids.ml.features.nsl_kdd_style import to_feature_frame
from nids.ml.modern.inspect import ModernAssessment
from nids.ui.widgets.ip_lookup_dialog import IpIdentifyButton

_SEVERITY_LABEL = {"scazuta": "usor", "medie": "moderat", "ridicata": "sever"}


def _verdict_label(prediction: int | None) -> str:
    if prediction is None:
        return "indisponibil"
    return "ATAC/ANOMALIE" if prediction == 1 else "normal"


def _score_label(score: float | None) -> str:
    if score is None:
        return ""
    grade = _SEVERITY_LABEL[severity_from_local_score(score).value]
    return f" (scor anomalie: {score:+.3f}, {grade})"


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

    def __init__(
        self,
        assessment: ConnectionAssessment | None = None,
        parent=None,
        modern_assessment: ModernAssessment | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Analiza conexiune")
        self.resize(560, 620)

        layout = QVBoxLayout(self)

        if assessment is not None:
            self._add_primary_section(layout, assessment)
            if modern_assessment is not None:
                self._add_modern_section(layout, modern_assessment)
        elif modern_assessment is not None:
            # eveniment generat de pipeline-ul modern (principal din Faza
            # 6), redeschis dintr-o sesiune anterioara - traficul brut
            # original nu mai exista, deci modelul vechi nu poate fi
            # recalculat. modelul modern chiar are o "poza" salvata
            # (assessment_json, vezi ModernLiveHybridAnalyzer.evaluate())
            self._add_modern_only_section(layout, modern_assessment)
        else:
            layout.addWidget(QLabel("Nicio analiza disponibila pentru acest eveniment."))

    def _add_primary_section(self, layout: QVBoxLayout, assessment: ConnectionAssessment) -> None:
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
            else _verdict_label(assessment.local_prediction) + _score_label(assessment.local_anomaly_score)
        )
        verdict = QLabel(
            f"Model expert: {_verdict_label(assessment.expert_prediction)}"
            f"    |    Model local: {local_verdict}"
        )
        verdict.setStyleSheet("font-weight: bold;")

        identify_button = IpIdentifyButton([record.src_ip, record.dst_ip], parent=self)

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

        layout.addWidget(header)
        layout.addWidget(verdict)
        layout.addWidget(identify_button)
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

    def _add_modern_section(self, layout: QVBoxLayout, modern: ModernAssessment) -> None:
        """"a doua opinie" - modelul expert modern (CSE-CIC-IDS2018),
        antrenat pe date de retea din 2018, spre deosebire de modelul de
        mai sus (NSL-KDD, date din 1998-99). ruleaza COMPLET INDEPENDENT -
        nu participa la verdictul/acordul de mai sus, doar afisat alaturi,
        ca studiu de diferentiere intre cele doua seturi de date - vezi
        DATASET-COMPARISON.md"""
        separator = QLabel(
            "─── a doua opinie: modele MODERNE (CSE-CIC-IDS2018, 2018) ───"
        )
        separator.setStyleSheet("font-weight: bold; color: #8a8a8a;")

        hint = QLabel(
            "verdict INDEPENDENT, pe o schema de features diferita (72 vs 28) - "
            "nu participa la acordul de mai sus, doar comparatie"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8a8a8a;")

        layout.addWidget(separator)
        layout.addWidget(hint)
        self._render_modern_body(layout, modern)

    def _add_modern_only_section(self, layout: QVBoxLayout, modern: ModernAssessment) -> None:
        """cand modelul vechi nu poate fi recalculat (pachetele brute ale
        sesiunii originale nu mai exista), dar avem totusi o "poza" a
        modelului modern salvata - afisata ca sectiune PRINCIPALA (nu ca
        "a doua opinie", nu exista nimic altceva de aratat)"""
        record = modern.record

        header = QLabel(
            f"{record.src_ip}:{record.src_port}  →  {record.dst_ip}:{record.dst_port}  "
            f"({record.protocol})"
        )
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        header.setWordWrap(True)

        note = QLabel(
            "doar model expert MODERN disponibil pentru acest eveniment - traficul "
            "brut original nu mai exista (alta sesiune sau aplicatia repornita), "
            "deci modelul vechi (NSL-KDD) nu poate fi recalculat"
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #8a8a8a;")

        identify_button = IpIdentifyButton([record.src_ip, record.dst_ip], parent=self)

        layout.addWidget(header)
        layout.addWidget(note)
        layout.addWidget(identify_button)
        self._render_modern_body(layout, modern)

    def _render_modern_body(self, layout: QVBoxLayout, modern: ModernAssessment) -> None:
        modern_local_verdict = (
            "inca invata"
            if modern.local_is_learning
            else _verdict_label(modern.local_prediction) + _score_label(modern.local_anomaly_score)
        )
        verdict = QLabel(
            f"Model expert modern: {_verdict_label(modern.expert_prediction)}"
            f"    |    Model local modern: {modern_local_verdict}"
        )
        verdict.setStyleSheet("font-weight: bold;")

        modern_explanation = QLabel(modern.explanation)
        modern_explanation.setWordWrap(True)

        modern_rows = [
            (c.feature, c.value, f"{c.importance:.1%}") for c in modern.expert_top_features
        ]
        modern_table = _make_table(["feature", "valoare", "importanta"], modern_rows)

        modern_local_rows = [
            (d.feature, f"{d.value:g}", f"{d.baseline_mean:.2f}", f"{d.z_score:+.2f}")
            for d in modern.local_deviations
        ]
        modern_local_table = _make_table(
            ["feature", "valoare", "medie normal", "deviatie (z-score)"], modern_local_rows
        )

        layout.addWidget(verdict)
        layout.addWidget(modern_explanation)
        layout.addWidget(QLabel("De ce (model expert modern) - importanta globala a features:"))
        layout.addWidget(modern_table)
        layout.addWidget(QLabel("Comparatie cu traficul normal (model local modern):"))
        layout.addWidget(modern_local_table)
