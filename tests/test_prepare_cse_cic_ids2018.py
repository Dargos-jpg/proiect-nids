import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.prepare_cse_cic_ids2018 import _ClassPool, _clean_chunk


def _chunk(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def _row(label="Benign", timestamp="01/03/2018 08:17:11", flow_byts="100", **extra) -> dict:
    row = {"Timestamp": timestamp, "Flow Byts/s": flow_byts, "Dst Port": "80", "Label": label}
    row.update(extra)
    return row


# --- _clean_chunk ---


def test_clean_chunk_keeps_normal_rows():
    """regresie: Timestamp (string de tip data) nu trebuie sa respinga
    randuri normale doar pentru ca nu e convertibil direct la numar -
    bug real gasit la prima rulare (vezi BUGS.md), unde verificarea de
    finitudine includea din greseala coloana Timestamp"""
    chunk = _chunk([_row(), _row()])

    cleaned = _clean_chunk(chunk)

    assert len(cleaned) == 2


def test_clean_chunk_drops_timestamp_column():
    cleaned = _clean_chunk(_chunk([_row()]))

    assert "Timestamp" not in cleaned.columns


def test_clean_chunk_drops_duplicated_header_rows():
    chunk = _chunk([_row(), _row(label="Label")])

    cleaned = _clean_chunk(chunk)

    assert len(cleaned) == 1


def test_clean_chunk_drops_rows_with_infinity_or_nan():
    chunk = _chunk([_row(flow_byts="100"), _row(flow_byts="Infinity"), _row(flow_byts="NaN")])

    cleaned = _clean_chunk(chunk)

    assert len(cleaned) == 1


def test_clean_chunk_returns_empty_frame_when_all_rows_are_junk():
    cleaned = _clean_chunk(_chunk([_row(label="Label")]))

    assert cleaned.empty


# --- _ClassPool ---


def test_class_pool_keeps_everything_under_capacity():
    pool = _ClassPool(capacity=100, seed=42)

    pool.add(pd.DataFrame({"x": range(10)}))

    assert pool.seen == 10
    assert len(pool.finalize()) == 10


def test_class_pool_caps_at_capacity_when_over():
    pool = _ClassPool(capacity=10, seed=42)

    pool.add(pd.DataFrame({"x": range(100)}))

    assert pool.seen == 100
    assert len(pool.finalize()) == 10


def test_class_pool_tracks_total_seen_across_multiple_adds():
    pool = _ClassPool(capacity=1000, seed=42)

    pool.add(pd.DataFrame({"x": range(5)}))
    pool.add(pd.DataFrame({"x": range(5)}))

    assert pool.seen == 10
