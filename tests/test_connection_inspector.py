from PySide6.QtWidgets import QApplication, QLabel, QTableWidget

from nids.core.inspect import assess_connection
from nids.ml.local.learning import LocalModelManager
from nids.ui.widgets.connection_inspector import ConnectionInspectorDialog
from tests.factories import make_record


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
