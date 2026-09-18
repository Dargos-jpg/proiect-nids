from nids.capture.packet_meta import PacketMeta
from nids.core.event import Severity
from nids.ml.modern.learning import ModernLocalModelManager
from nids.ml.modern.live_hybrid import ModernLiveHybridAnalyzer


def _packet(
    src_ip: str, dst_ip: str, dst_port: int, src_port: int = 5000, ts: float = 0.0
) -> PacketMeta:
    return PacketMeta(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="tcp",
        length=100,
        src_port=src_port,
        dst_port=dst_port,
    )


def test_no_events_without_expert_model():
    analyzer = ModernLiveHybridAnalyzer(
        expert=None, local_manager=ModernLocalModelManager(min_training_samples=5)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    assert analyzer.evaluate() == []


def test_no_events_without_any_packets():
    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=5)
    )

    assert analyzer.evaluate() == []


def test_skips_already_evaluated_flows(monkeypatch):
    calls = []

    def fake_predict(expert, records):
        calls.append(len(records))
        return [1] * len(records)

    monkeypatch.setattr("nids.ml.modern.live_hybrid.predict_flows", fake_predict)
    monkeypatch.setattr("nids.ml.modern.live_hybrid.explain_flow", lambda expert, record: [])

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    analyzer.evaluate()
    analyzer.evaluate()

    assert calls == [1]


def test_same_destination_ip_different_port_is_evaluated_separately(monkeypatch):
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.ml.modern.live_hybrid.explain_flow", lambda expert, record: [])

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )

    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80, src_port=5000))
    first = analyzer.evaluate()

    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 443, src_port=5001))
    second = analyzer.evaluate()

    assert len(first) == 1
    assert len(second) == 1


def test_emits_event_when_expert_flags_and_local_still_learning(monkeypatch):
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.ml.modern.live_hybrid.explain_flow", lambda expert, record: [])

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    events = analyzer.evaluate()

    assert len(events) == 1
    assert events[0].event_type == "atac cunoscut (model local inca invata)"


def test_no_event_when_expert_says_normal_and_local_still_learning(monkeypatch):
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [0] * len(records),
    )

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    assert analyzer.evaluate() == []


def test_new_flow_after_previous_tick_is_evaluated(monkeypatch):
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.ml.modern.live_hybrid.explain_flow", lambda expert, record: [])

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))
    first = analyzer.evaluate()

    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.3", 22))
    second = analyzer.evaluate()

    assert len(first) == 1
    assert len(second) == 1


def test_event_carries_connection_identity_for_later_reanalysis(monkeypatch):
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.ml.modern.live_hybrid.explain_flow", lambda expert, record: [])

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 443, src_port=5000))

    events = analyzer.evaluate()

    assert len(events) == 1
    assert events[0].dest_ip == "10.0.0.2"
    assert events[0].src_port == 5000
    assert events[0].dest_port == 443
    assert events[0].protocol == "tcp"


def test_event_carries_full_assessment_snapshot_reconstructible_from_json(monkeypatch):
    """vezi test_live_hybrid.py - acelasi gol inchis (DATASET-COMPARISON.md,
    "de facut in continuare"): analiza completa a modelului modern trebuie
    sa poata fi redeschisa dintr-un rand din Loguri chiar si intr-o
    sesiune viitoare, cand pachetele brute nu mai exista"""
    from nids.ml.modern.inspect import modern_assessment_from_json
    from nids.ml.modern.model import FeatureContribution

    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.explain_flow",
        lambda expert, record: [FeatureContribution(feature="flow_duration", value="10", importance=0.5)],
    )

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 443, src_port=5000))

    events = analyzer.evaluate()

    assert len(events) == 1
    assert events[0].assessment_json is not None
    restored = modern_assessment_from_json(events[0].assessment_json)
    assert restored.record.dst_ip == "10.0.0.2"
    assert restored.expert_prediction == 1
    assert restored.expert_top_features[0].feature == "flow_duration"


def test_local_only_event_severity_reflects_anomaly_score(monkeypatch):
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [0] * len(records),  # expert: normal
    )
    monkeypatch.setattr("nids.ml.modern.live_hybrid.explain_flow", lambda expert, record: [])

    local_manager = ModernLocalModelManager(min_training_samples=100)
    local_manager._model = object()  # simuleaza modelul activ (nu mai invata)
    monkeypatch.setattr(local_manager, "process", lambda record: 1)  # local: anomalie
    monkeypatch.setattr(local_manager, "anomaly_score", lambda record: 0.3)  # scor "sever"
    monkeypatch.setattr(local_manager, "explain", lambda record: [])
    monkeypatch.setattr(local_manager, "explain_categorical", lambda record: [])

    analyzer = ModernLiveHybridAnalyzer(expert=object(), local_manager=local_manager)
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    events = analyzer.evaluate()

    assert len(events) == 1
    assert events[0].severity == Severity.HIGH


def test_strict_reporting_suppresses_single_model_flags(monkeypatch):
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [1] * len(records),
    )

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(),
        local_manager=ModernLocalModelManager(min_training_samples=100),
        strict_reporting=True,
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    assert analyzer.evaluate() == []


def test_agreement_counts_tracks_every_verdict_even_when_no_event_emitted(monkeypatch):
    from nids.core.ml_combination import Agreement

    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [0] * len(records),
    )

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    events = analyzer.evaluate()

    assert events == []
    assert analyzer.agreement_counts[Agreement.LOCAL_LEARNING] == 1


def test_packet_buffer_is_capped_to_avoid_unbounded_reprocessing(monkeypatch):
    """vezi test_live_hybrid.py - acelasi bug real, acelasi fix (BUGS.md)"""
    monkeypatch.setattr("nids.ml.modern.live_hybrid.MAX_BUFFERED_PACKETS", 3)

    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    for i in range(10):
        analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80, src_port=5000 + i))

    assert len(analyzer._packets) == 3


def test_reset_clears_state(monkeypatch):
    monkeypatch.setattr(
        "nids.ml.modern.live_hybrid.predict_flows",
        lambda expert, records: [0] * len(records),
    )
    analyzer = ModernLiveHybridAnalyzer(
        expert=object(), local_manager=ModernLocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))
    analyzer.evaluate()

    analyzer.reset()

    assert len(analyzer._packets) == 0
    assert analyzer._evaluated_flows == set()
