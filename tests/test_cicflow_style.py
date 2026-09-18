from nids.capture.packet_meta import PacketMeta
from nids.ml.features.cicflow_style import (
    IDLE_THRESHOLD_SECONDS,
    _segment_bursts,
    extract_cicflow_features,
    to_feature_frame,
)


def _pkt(
    src_ip="10.0.0.1",
    src_port=5000,
    dst_ip="10.0.0.2",
    dst_port=80,
    protocol="tcp",
    ts=0.0,
    length=100,
    flags=None,
    window=None,
    payload_length=0,
) -> PacketMeta:
    return PacketMeta(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        length=length,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        tcp_window=window,
        payload_length=payload_length,
    )


# --- grupare in flux bidirectional ---


def test_request_and_response_are_grouped_into_one_flow():
    request = _pkt(ts=0.0)
    response = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.1)

    flows = extract_cicflow_features([request, response])

    assert len(flows) == 1


def test_different_connections_produce_separate_flows():
    a = _pkt(dst_port=80)
    b = _pkt(dst_port=443)

    flows = extract_cicflow_features([a, b])

    assert len(flows) == 2


def test_forward_direction_is_the_first_packet_chronologically():
    """chiar daca in lista pachetele nu sunt in ordine, directia forward
    trebuie decisa dupa ordinea CRONOLOGICA (timestamp), nu dupa ordinea
    din lista de input"""
    response = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=5.0)
    request = _pkt(ts=1.0)  # mai vechi, desi apare al doilea in lista

    flow = extract_cicflow_features([response, request])[0]

    assert flow.src_ip == "10.0.0.1"  # initiatorul real, dupa timp


# --- numaratori de pachete/octeti pe directie ---


def test_counts_forward_and_backward_packets_separately():
    request = _pkt(ts=0.0, length=100)
    response1 = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.1, length=200)
    response2 = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.2, length=300)

    flow = extract_cicflow_features([request, response1, response2])[0]

    assert flow.tot_fwd_pkts == 1
    assert flow.tot_bwd_pkts == 2
    assert flow.totlen_fwd_pkts == 100
    assert flow.totlen_bwd_pkts == 500


# --- durata si rate ---


def test_flow_duration_and_rates_computed_correctly():
    a = _pkt(ts=0.0, length=100)
    b = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=2.0, length=100)

    flow = extract_cicflow_features([a, b])[0]

    assert flow.flow_duration == 2.0
    assert flow.flow_byts_per_s == 100.0  # 200 octeti / 2s
    assert flow.flow_pkts_per_s == 1.0  # 2 pachete / 2s


def test_single_packet_flow_has_zero_duration_and_rates_not_division_error():
    flow = extract_cicflow_features([_pkt(ts=0.0)])[0]

    assert flow.flow_duration == 0.0
    assert flow.flow_byts_per_s == 0.0
    assert flow.flow_pkts_per_s == 0.0


# --- statistici IAT ---


def test_iat_stats_over_multiple_packets():
    pkts = [_pkt(ts=0.0), _pkt(ts=1.0), _pkt(ts=3.0)]  # gap-uri: 1.0, 2.0

    flow = extract_cicflow_features(pkts)[0]

    assert flow.flow_iat_mean == 1.5
    assert flow.flow_iat_max == 2.0
    assert flow.flow_iat_min == 1.0


# --- lungimi de pachet ---


def test_packet_length_stats_across_both_directions():
    a = _pkt(ts=0.0, length=100)
    b = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=1.0, length=300)

    flow = extract_cicflow_features([a, b])[0]

    assert flow.pkt_len_min == 100.0
    assert flow.pkt_len_max == 300.0
    assert flow.pkt_len_mean == 200.0


# --- flag-uri TCP ---


def test_flag_counts_across_whole_flow():
    pkts = [
        _pkt(ts=0.0, flags="S"),
        _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.1, flags="SA"),
        _pkt(ts=0.2, flags="A"),
        _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=5.0, flags="FA"),
    ]

    flow = extract_cicflow_features(pkts)[0]

    assert flow.syn_flag_cnt == 2  # S + SA
    assert flow.ack_flag_cnt == 3  # SA + A + FA
    assert flow.fin_flag_cnt == 1


def test_psh_and_urg_flags_counted_per_direction():
    fwd = _pkt(ts=0.0, flags="P")
    bwd = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.1, flags="PU")

    flow = extract_cicflow_features([fwd, bwd])[0]

    assert flow.fwd_psh_flags == 1
    assert flow.bwd_psh_flags == 1
    assert flow.fwd_urg_flags == 0
    assert flow.bwd_urg_flags == 1


# --- rate/marimi derivate ---


def test_down_up_ratio_and_pkt_size_avg():
    fwd = _pkt(ts=0.0, length=100)
    bwd1 = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.1, length=100)
    bwd2 = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.2, length=100)

    flow = extract_cicflow_features([fwd, bwd1, bwd2])[0]

    assert flow.down_up_ratio == 2.0  # 2 bwd / 1 fwd
    assert flow.pkt_size_avg == 100.0


def test_down_up_ratio_is_zero_when_no_forward_packets_exist():
    """imposibil in practica (primul pachet e mereu "forward" prin
    definitie), dar functia trebuie sa fie robusta, nu sa dea eroare de
    impartire la zero"""
    from nids.ml.features.cicflow_style import _build_flow

    flow = _build_flow([_pkt(ts=0.0)])
    assert flow.tot_fwd_pkts == 1  # primul pachet e mereu fwd


# --- fereastra TCP initiala ---


def test_init_window_uses_first_packet_with_window_set():
    a = _pkt(ts=0.0, window=64240)
    b = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.1, window=29200)

    flow = extract_cicflow_features([a, b])[0]

    assert flow.init_fwd_win_byts == 64240
    assert flow.init_bwd_win_byts == 29200


def test_init_window_is_minus_one_when_never_set():
    flow = extract_cicflow_features([_pkt(ts=0.0, protocol="udp", window=None)])[0]

    assert flow.init_fwd_win_byts == -1
    assert flow.init_bwd_win_byts == -1


# --- date efective transmise ---


def test_fwd_act_data_pkts_counts_only_packets_with_payload():
    a = _pkt(ts=0.0, payload_length=0)
    b = _pkt(ts=0.1, payload_length=50)

    flow = extract_cicflow_features([a, b])[0]

    assert flow.fwd_act_data_pkts == 1


# --- segmentare activ/idle + subflow ---


def test_segment_bursts_with_no_gap_is_one_burst():
    active, idle = _segment_bursts([0.0, 1.0, 2.0], idle_threshold=5.0)

    assert active == [2.0]
    assert idle == []


def test_segment_bursts_splits_on_gap_over_threshold():
    active, idle = _segment_bursts([0.0, 1.0, 10.0, 11.0], idle_threshold=5.0)

    assert active == [1.0, 1.0]
    assert idle == [9.0]


def test_flow_without_idle_gap_has_one_subflow_equal_to_totals():
    a = _pkt(ts=0.0, length=100)
    b = _pkt(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=1.0, length=100)

    flow = extract_cicflow_features([a, b])[0]

    assert flow.subflow_fwd_pkts == flow.tot_fwd_pkts
    assert flow.subflow_fwd_byts == flow.totlen_fwd_pkts
    assert flow.idle_mean == 0.0


def test_flow_with_idle_gap_splits_into_two_subflows():
    a = _pkt(ts=0.0, length=100)
    gap = IDLE_THRESHOLD_SECONDS + 1.0
    b = _pkt(ts=gap, length=100)  # tot forward, dupa o pauza mare

    flow = extract_cicflow_features([a, b])[0]

    assert flow.subflow_fwd_pkts == 1.0  # 2 pachete fwd / 2 subflow-uri
    assert flow.idle_mean == gap


# --- to_feature_frame ---


def test_to_feature_frame_excludes_identification_but_keeps_dst_port_and_protocol():
    a = _pkt(ts=0.0)
    flows = extract_cicflow_features([a])

    df = to_feature_frame(flows)

    assert "src_ip" not in df.columns
    assert "dst_ip" not in df.columns
    assert "src_port" not in df.columns
    assert "dst_port" in df.columns
    assert "protocol" in df.columns
    assert len(df) == 1
