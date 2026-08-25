from nids.capture.packet_meta import PacketMeta
from nids.core.inspect import assessment_from_json
from nids.core.live_hybrid import LiveHybridAnalyzer
from nids.ml.local.learning import LocalModelManager


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
    analyzer = LiveHybridAnalyzer(
        expert=None, local_manager=LocalModelManager(min_training_samples=5)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    assert analyzer.evaluate() == []


def test_no_events_without_any_packets():
    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=5)
    )

    assert analyzer.evaluate() == []


def test_skips_already_evaluated_connections(monkeypatch):
    calls = []

    def fake_predict(expert, records):
        calls.append(len(records))
        return [1] * len(records)

    monkeypatch.setattr("nids.core.live_hybrid.predict_connections", fake_predict)
    monkeypatch.setattr("nids.core.live_hybrid.explain_connection", lambda expert, record: [])

    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    analyzer.evaluate()
    analyzer.evaluate()

    assert calls == [1]


def test_same_destination_ip_different_port_is_evaluated_separately(monkeypatch):
    """regresie: varianta initiala deduplica doar pe (src_ip, dst_ip) -
    o a doua conexiune catre acelasi IP, pe alt port, era ignorata
    complet. acum trebuie evaluata ca o conexiune noua"""
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.core.live_hybrid.explain_connection", lambda expert, record: [])

    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )

    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80, src_port=5000))
    first = analyzer.evaluate()

    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 443, src_port=5001))
    second = analyzer.evaluate()

    assert len(first) == 1
    assert len(second) == 1


def test_emits_event_when_expert_flags_and_local_still_learning(monkeypatch):
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.core.live_hybrid.explain_connection", lambda expert, record: [])

    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    events = analyzer.evaluate()

    assert len(events) == 1
    assert events[0].event_type == "atac cunoscut (model local inca invata)"


def test_no_event_when_expert_says_normal_and_local_still_learning(monkeypatch):
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [0] * len(records),
    )

    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    assert analyzer.evaluate() == []


def test_new_connection_after_previous_tick_is_evaluated(monkeypatch):
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.core.live_hybrid.explain_connection", lambda expert, record: [])

    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))
    first = analyzer.evaluate()

    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.3", 22))
    second = analyzer.evaluate()

    assert len(first) == 1
    assert len(second) == 1


def test_event_description_is_enriched_with_explanation(monkeypatch):
    from nids.ml.expert.model import FeatureContribution

    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr(
        "nids.core.live_hybrid.explain_connection",
        lambda expert, record: [FeatureContribution(feature="flag", value="S0", importance=0.5)],
    )

    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    events = analyzer.evaluate()

    assert len(events) == 1
    assert "flag=S0" in events[0].description
    assert "model expert vede:" in events[0].description


def test_event_carries_connection_identity_for_later_reanalysis(monkeypatch):
    """necesar ca sa poata fi deschisa analiza ML completa direct dintr-un
    rand din Loguri, nu doar din Trafic - vezi DashboardPanel._on_log_analyze_requested"""
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.core.live_hybrid.explain_connection", lambda expert, record: [])

    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 443, src_port=5000))

    events = analyzer.evaluate()

    assert len(events) == 1
    assert events[0].dest_ip == "10.0.0.2"
    assert events[0].src_port == 5000
    assert events[0].dest_port == 443
    assert events[0].protocol == "tcp"


def test_event_carries_full_assessment_snapshot_reconstructible_from_json(monkeypatch):
    """necesar ca analiza completa (tabele, nu doar textul din
    descriere) sa poata fi redeschisa dintr-un rand din Loguri chiar si
    intr-o sesiune viitoare, cand pachetele brute nu mai exista"""
    from nids.ml.expert.model import FeatureContribution

    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr(
        "nids.core.live_hybrid.explain_connection",
        lambda expert, record: [FeatureContribution(feature="flag", value="S0", importance=0.5)],
    )

    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 443, src_port=5000))

    events = analyzer.evaluate()

    assert len(events) == 1
    assert events[0].assessment_json is not None
    restored = assessment_from_json(events[0].assessment_json)
    assert restored.record.dst_ip == "10.0.0.2"
    assert restored.expert_prediction == 1
    assert restored.expert_top_features[0].feature == "flag"
    assert restored.local_is_learning is True


def test_strict_reporting_suppresses_single_model_flags(monkeypatch):
    """expert semnaleaza, dar modelul local inca invata (LOCAL_LEARNING) -
    in mod strict, nu e destul de sigur ca sa genereze un eveniment"""
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [1] * len(records),
    )
    monkeypatch.setattr("nids.core.live_hybrid.explain_connection", lambda expert, record: [])

    analyzer = LiveHybridAnalyzer(
        expert=object(),
        local_manager=LocalModelManager(min_training_samples=100),
        strict_reporting=True,
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))

    assert analyzer.evaluate() == []


def test_reset_clears_state(monkeypatch):
    monkeypatch.setattr(
        "nids.core.live_hybrid.predict_connections",
        lambda expert, records: [0] * len(records),
    )
    analyzer = LiveHybridAnalyzer(
        expert=object(), local_manager=LocalModelManager(min_training_samples=100)
    )
    analyzer.add_packet(_packet("10.0.0.1", "10.0.0.2", 80))
    analyzer.evaluate()

    analyzer.reset()

    assert analyzer._packets == []
    assert analyzer._evaluated_connections == set()
