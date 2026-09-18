from PySide6.QtWidgets import QApplication, QLabel, QTableWidget

from nids.core.inspect import assess_connection
from nids.ml.local.learning import LocalModelManager
from nids.ml.modern.inspect import assess_modern
from nids.ui.widgets.connection_inspector import ConnectionInspectorDialog
from nids.ui.widgets.ip_lookup_dialog import IpIdentifyButton
from tests.factories import make_cicflow_record, make_record


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _all_label_text(dialog: ConnectionInspectorDialog) -> str:
    return " ".join(label.text() for label in dialog.findChildren(QLabel))


def test_dialog_builds_without_expert_or_local_model():
    _app()
    assessment = assess_connection(make_record(), expert=None, local_manager=None)

    dialog = ConnectionInspectorDialog(assessment)

    assert "indisponibil" in _all_label_text(dialog)
    assert "10.0.0.1" in _all_label_text(dialog)
    dialog.deleteLater()


def test_dialog_shows_ip_identify_button_for_source_and_destination():
    _app()
    assessment = assess_connection(make_record(), expert=None, local_manager=None)

    dialog = ConnectionInspectorDialog(assessment)

    buttons = dialog.findChildren(IpIdentifyButton)
    assert len(buttons) == 1
    assert buttons[0]._ips_provider() == ["10.0.0.1", "10.0.0.2"]
    dialog.deleteLater()


def test_dialog_shows_local_learning_state():
    _app()
    local_manager = LocalModelManager(min_training_samples=1000)
    local_manager.process(make_record())
    assessment = assess_connection(make_record(), expert=None, local_manager=local_manager)

    dialog = ConnectionInspectorDialog(assessment)

    assert "inca invata" in _all_label_text(dialog)
    dialog.deleteLater()


def test_dialog_shows_expert_feature_table():
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    from nids.ml.expert.model import ExpertModel
    from nids.ml.expert.nsl_kdd import FEATURE_COLUMNS, prepare_features

    _app()

    def row(protocol_type, service, flag, label, **overrides):
        values = {name: 0 for name in FEATURE_COLUMNS}
        values.update(protocol_type=protocol_type, service=service, flag=flag)
        values.update(overrides)
        return [values[name] for name in FEATURE_COLUMNS] + [label, 20]

    train_df = pd.DataFrame(
        [
            row("tcp", "http", "SF", "normal", src_bytes=200),
            row("tcp", "private", "S0", "neptune", src_bytes=0),
        ],
        columns=FEATURE_COLUMNS + ["label", "difficulty"],
    )
    x_train, y_train = prepare_features(train_df)
    model = RandomForestClassifier(n_estimators=5, random_state=42)
    model.fit(x_train, y_train)
    expert = ExpertModel(model, list(x_train.columns))

    assessment = assess_connection(make_record(), expert=expert, local_manager=None)
    dialog = ConnectionInspectorDialog(assessment)

    tables = dialog.findChildren(QTableWidget)
    expert_table = tables[0]  # primul tabel randat e cel al modelului expert
    assert expert_table.rowCount() > 0
    assert expert_table.columnCount() == 3
    dialog.deleteLater()


def test_dialog_shows_anomaly_score_when_local_model_active():
    _app()
    local_manager = LocalModelManager(min_training_samples=5)
    for _ in range(5):
        local_manager.process(make_record())

    assessment = assess_connection(make_record(), expert=None, local_manager=local_manager)
    dialog = ConnectionInspectorDialog(assessment)

    assert "scor anomalie" in _all_label_text(dialog)
    dialog.deleteLater()


def test_dialog_omits_anomaly_score_while_learning():
    _app()
    local_manager = LocalModelManager(min_training_samples=1000)
    local_manager.process(make_record())

    assessment = assess_connection(make_record(), expert=None, local_manager=local_manager)
    dialog = ConnectionInspectorDialog(assessment)

    assert "scor anomalie" not in _all_label_text(dialog)
    dialog.deleteLater()


def test_dialog_shows_categorical_rarity_table():
    _app()
    local_manager = LocalModelManager(min_training_samples=5)
    for _ in range(5):
        local_manager.process(make_record(protocol_type="tcp", service="http", flag="SF"))

    assessment = assess_connection(
        make_record(protocol_type="udp", service="other", flag="SF"),
        expert=None,
        local_manager=local_manager,
    )
    dialog = ConnectionInspectorDialog(assessment)

    tables = dialog.findChildren(QTableWidget)
    # ordinea in layout: expert, local (numeric), categoric, toate valorile
    categorical_table = tables[2]
    assert categorical_table.columnCount() == 3
    assert categorical_table.rowCount() == 3  # protocol_type, service, flag

    values_in_table = {
        categorical_table.item(row, 0).text() for row in range(categorical_table.rowCount())
    }
    assert values_in_table == {"protocol_type", "service", "flag"}
    dialog.deleteLater()


def _tiny_modern_model():
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    from nids.ml.modern.model import ModernExpertModel

    x_train = pd.DataFrame({"flow_duration": [10, 5000], "totlen_fwd_pkts": [10, 6000]})
    model = RandomForestClassifier(n_estimators=5, random_state=42)
    model.fit(x_train, [1, 0])  # duration mica -> atac, ca predictia sa fie deterministica mai jos
    return ModernExpertModel(model, list(x_train.columns))


def test_dialog_without_modern_assessment_omits_second_opinion_section():
    _app()
    assessment = assess_connection(make_record(), expert=None, local_manager=None)

    dialog = ConnectionInspectorDialog(assessment)

    assert "a doua opinie" not in _all_label_text(dialog)
    dialog.deleteLater()


def test_dialog_with_modern_assessment_shows_second_opinion_section():
    _app()
    assessment = assess_connection(make_record(), expert=None, local_manager=None)
    modern = assess_modern(
        make_cicflow_record(flow_duration=10), expert=_tiny_modern_model(), local_manager=None
    )

    dialog = ConnectionInspectorDialog(assessment, modern_assessment=modern)

    text = _all_label_text(dialog)
    assert "a doua opinie" in text
    assert "ATAC/ANOMALIE" in text
    dialog.deleteLater()


def test_dialog_modern_section_shows_feature_table():
    _app()
    assessment = assess_connection(make_record(), expert=None, local_manager=None)
    modern = assess_modern(
        make_cicflow_record(flow_duration=10), expert=_tiny_modern_model(), local_manager=None
    )

    dialog = ConnectionInspectorDialog(assessment, modern_assessment=modern)

    tables = dialog.findChildren(QTableWidget)
    modern_table = tables[-2]  # penultimul: features expert modern (ultimul e local modern)
    assert modern_table.rowCount() > 0
    dialog.deleteLater()


def test_dialog_with_only_modern_assessment_shows_it_as_primary_content():
    """eveniment generat de pipeline-ul modern (principal din Faza 6),
    redeschis fara ca pachetele brute originale sa mai existe - modelul
    vechi nu poate fi recalculat deloc, doar cel modern e disponibil"""
    _app()
    modern = assess_modern(
        make_cicflow_record(src_ip="203.0.113.5", flow_duration=10),
        expert=_tiny_modern_model(),
        local_manager=None,
    )

    dialog = ConnectionInspectorDialog(modern_assessment=modern)

    text = _all_label_text(dialog)
    assert "203.0.113.5" in text
    assert "a doua opinie" not in text  # e continutul PRINCIPAL, nu o sectiune secundara
    assert "nu poate fi recalculat" in text
    tables = dialog.findChildren(QTableWidget)
    assert len(tables) == 2  # doar tabelele modelului modern (features + deviatii locale)
    dialog.deleteLater()


def test_dialog_without_any_assessment_shows_placeholder():
    _app()

    dialog = ConnectionInspectorDialog()

    assert "Nicio analiza disponibila" in _all_label_text(dialog)
    dialog.deleteLater()
