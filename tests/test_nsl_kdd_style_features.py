from dataclasses import fields
from pathlib import Path

from nids.capture.pcap_reader import read_pcap
from nids.ml.expert.nsl_kdd import ALL_FEATURE_COLUMNS, FEATURE_COLUMNS
from nids.ml.features.nsl_kdd_style import (
    NslKddStyleFeatures,
    extract_nsl_kdd_style_features,
    to_feature_frame,
)

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def test_covers_exactly_28_of_the_41_nsl_kdd_columns():
    our_fields = {f.name for f in fields(NslKddStyleFeatures)} - {"src_ip", "dst_ip"}

    assert len(our_fields) == 28
    assert our_fields.issubset(set(ALL_FEATURE_COLUMNS))
    # modelul expert e antrenat exact pe acest subset - trebuie sa se
    # potriveasca perfect cu ce produce extractorul nostru
    assert our_fields == set(FEATURE_COLUMNS)


def test_extract_on_real_pcap_produces_sane_values():
    packets = read_pcap(str(PCAP_PATH))
    records = extract_nsl_kdd_style_features(packets)

    assert len(records) > 0

    http_record = next(
        r
        for r in records
        if {r.src_ip, r.dst_ip} == {"145.254.160.237", "65.208.228.223"}
    )

    assert http_record.protocol_type == "tcp"
    assert http_record.service == "http"
    assert http_record.src_bytes > 0
    assert http_record.dst_bytes > 0
    assert http_record.duration >= 0
    assert http_record.count >= 1
    assert 0.0 <= http_record.same_srv_rate <= 1.0
    assert 0.0 <= http_record.serror_rate <= 1.0


def test_to_feature_frame_has_exactly_feature_columns_and_no_ip_fields():
    packets = read_pcap(str(PCAP_PATH))
    records = extract_nsl_kdd_style_features(packets)

    frame = to_feature_frame(records)

    assert set(frame.columns) == set(FEATURE_COLUMNS)
    assert len(frame) == len(records)
    assert frame["land"].dtype.kind in "iub"  # int/unsigned/bool, nu bool Python brut
