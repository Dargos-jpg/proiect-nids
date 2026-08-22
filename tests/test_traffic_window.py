from nids.ml.features.connection import ConnectionFeatures
from nids.ml.features.traffic_window import TrafficWindowTracker


def _conn(
    start_time: float,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 5000,
    dst_port: int = 80,
    service: str = "http",
    flag: str = "SF",
) -> ConnectionFeatures:
    return ConnectionFeatures(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="tcp",
        service=service,
        flag=flag,
        start_time=start_time,
        duration=0.0,
        src_bytes=0,
        dst_bytes=0,
        land=False,
        wrong_fragment=0,
        urgent=0,
    )


def test_single_connection_is_its_own_full_window():
    tracker = TrafficWindowTracker()

    features = tracker.process(_conn(0.0))

    assert features.count == 1
    assert features.srv_count == 1
    assert features.same_srv_rate == 1.0
    assert features.diff_srv_rate == 0.0
    assert features.dst_host_count == 1
    assert features.dst_host_srv_count == 1
    assert features.dst_host_same_srv_rate == 1.0


def test_connections_within_time_window_accumulate_count():
    tracker = TrafficWindowTracker(time_window=2.0)

    tracker.process(_conn(0.0, dst_ip="10.0.0.5"))
    tracker.process(_conn(0.5, dst_ip="10.0.0.5"))
    features = tracker.process(_conn(1.0, dst_ip="10.0.0.5"))

    assert features.count == 3


def test_connections_outside_time_window_are_evicted():
    tracker = TrafficWindowTracker(time_window=2.0)

    tracker.process(_conn(0.0))
    features = tracker.process(_conn(5.0))

    assert features.count == 1


def test_different_service_lowers_same_srv_rate():
    tracker = TrafficWindowTracker(time_window=2.0)

    tracker.process(_conn(0.0, dst_ip="10.0.0.5", dst_port=80, service="http"))
    features = tracker.process(_conn(0.1, dst_ip="10.0.0.5", dst_port=22, service="ssh"))

    assert features.count == 2
    assert features.srv_count == 1
    assert features.same_srv_rate == 0.5


def test_serror_rate_reflects_failed_connections():
    tracker = TrafficWindowTracker(time_window=2.0)

    tracker.process(_conn(0.0, dst_ip="10.0.0.5", flag="S0"))
    tracker.process(_conn(0.1, dst_ip="10.0.0.5", flag="S0"))
    features = tracker.process(_conn(0.2, dst_ip="10.0.0.5", flag="SF"))

    assert features.count == 3
    assert round(features.serror_rate, 2) == round(2 / 3, 2)


def test_dst_host_window_isolated_per_host():
    tracker = TrafficWindowTracker(time_window=2.0)

    tracker.process(_conn(0.0, dst_ip="10.0.0.5"))
    tracker.process(_conn(0.1, dst_ip="10.0.0.5"))
    features_host_a = tracker.process(_conn(0.2, dst_ip="10.0.0.5"))
    features_host_b = tracker.process(_conn(0.3, dst_ip="10.0.0.9"))

    assert features_host_a.dst_host_count == 3
    assert features_host_b.dst_host_count == 1


def test_dst_host_same_src_port_rate():
    tracker = TrafficWindowTracker(time_window=2.0)

    tracker.process(_conn(0.0, dst_ip="10.0.0.5", src_port=1111))
    features = tracker.process(_conn(0.1, dst_ip="10.0.0.5", src_port=1111))

    assert features.dst_host_same_src_port_rate == 1.0


def test_dst_host_window_capped_at_100():
    tracker = TrafficWindowTracker(time_window=1000.0, host_window_size=100)

    features = None
    for i in range(150):
        features = tracker.process(_conn(float(i), dst_ip="10.0.0.5"))

    assert features.dst_host_count == 100
