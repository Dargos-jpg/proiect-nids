from nids.honeypot.listener import HoneypotHit
from nids.honeypot.training_data import HONEYPOT_HOST_IP, HoneypotTrainingStore, hit_to_packets


def test_hit_to_packets_has_syn_synack_and_fin():
    hit = HoneypotHit(
        src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview="", duration=0.1
    )

    packets = hit_to_packets(hit, timestamp=100.0)

    flags = [p.tcp_flags for p in packets]
    assert flags[0] == "S"
    assert flags[1] == "SA"
    assert flags[-1] == "FA"
    assert all(p.protocol == "tcp" for p in packets)


def test_hit_to_packets_includes_data_packet_only_when_bytes_received():
    with_data = hit_to_packets(
        HoneypotHit(src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview="hello", bytes_received=5)
    )
    without_data = hit_to_packets(
        HoneypotHit(src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview="")
    )

    assert len(with_data) == 4
    assert len(without_data) == 3
    assert any(p.tcp_flags == "A" for p in with_data)
    assert not any(p.tcp_flags == "A" for p in without_data)


def test_hit_to_packets_targets_shared_honeypot_host():
    hit = HoneypotHit(src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview="")

    packets = hit_to_packets(hit)

    assert packets[0].dst_ip == HONEYPOT_HOST_IP
    assert packets[1].src_ip == HONEYPOT_HOST_IP


def test_training_store_accumulates_and_persists_across_instances(tmp_path):
    path = tmp_path / "sessions.joblib"
    store = HoneypotTrainingStore(path)
    hit = HoneypotHit(src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview="")

    store.add_hit(hit)
    store.add_hit(hit)

    assert store.sample_count() == 2
    assert len(store.packets()) == 6  # 3 pachete per hit, fara date primite

    reloaded = HoneypotTrainingStore(path)
    assert reloaded.sample_count() == 2


def test_training_store_starts_empty_when_no_file_exists(tmp_path):
    store = HoneypotTrainingStore(tmp_path / "does_not_exist.joblib")

    assert store.sample_count() == 0
    assert store.packets() == []


def test_training_store_clear_empties_and_persists(tmp_path):
    path = tmp_path / "sessions.joblib"
    store = HoneypotTrainingStore(path)
    store.add_hit(HoneypotHit(src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview=""))

    store.clear()

    assert store.sample_count() == 0
    assert HoneypotTrainingStore(path).sample_count() == 0
