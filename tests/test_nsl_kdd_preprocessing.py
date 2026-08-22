import pandas as pd

from nids.ml.expert.nsl_kdd import FEATURE_COLUMNS, prepare_features

_COLUMNS = FEATURE_COLUMNS + ["label", "difficulty"]


def _row(protocol_type: str, service: str, flag: str, label: str) -> list:
    values = [0] * len(FEATURE_COLUMNS)
    values[FEATURE_COLUMNS.index("protocol_type")] = protocol_type
    values[FEATURE_COLUMNS.index("service")] = service
    values[FEATURE_COLUMNS.index("flag")] = flag
    return values + [label, 20]


def test_prepare_features_maps_label_to_binary():
    df = pd.DataFrame(
        [
            _row("tcp", "http", "SF", "normal"),
            _row("tcp", "private", "S0", "neptune"),
            _row("udp", "other", "SF", "normal"),
        ],
        columns=_COLUMNS,
    )

    x, y = prepare_features(df)

    assert list(y) == [0, 1, 0]
    assert "label" not in x.columns
    assert "difficulty" not in x.columns


def test_prepare_features_one_hot_encodes_categorical_columns():
    df = pd.DataFrame(
        [_row("tcp", "http", "SF", "normal"), _row("udp", "other", "SF", "normal")],
        columns=_COLUMNS,
    )

    x, _ = prepare_features(df)

    assert "protocol_type_tcp" in x.columns
    assert "protocol_type_udp" in x.columns
    assert "service_http" in x.columns
    assert "protocol_type" not in x.columns


def test_prepare_features_aligns_test_columns_to_train_columns():
    train_df = pd.DataFrame(
        [_row("tcp", "http", "SF", "normal"), _row("tcp", "private", "S0", "neptune")],
        columns=_COLUMNS,
    )
    test_df = pd.DataFrame(
        [_row("udp", "other", "SF", "normal")], columns=_COLUMNS
    )

    x_train, _ = prepare_features(train_df)
    x_test, _ = prepare_features(test_df, encoded_columns=list(x_train.columns))

    assert list(x_test.columns) == list(x_train.columns)
    # udp nu a existat in train -> nu are coloana proprie, ramane 0 peste tot
    assert "protocol_type_udp" not in x_test.columns
