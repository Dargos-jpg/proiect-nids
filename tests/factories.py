from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures


def make_record(**overrides) -> NslKddStyleFeatures:
    base = dict(
        duration=0.1,
        protocol_type="tcp",
        service="http",
        flag="SF",
        src_bytes=200,
        dst_bytes=1000,
        land=False,
        wrong_fragment=0,
        urgent=0,
        count=1,
        srv_count=1,
        serror_rate=0.0,
        srv_serror_rate=0.0,
        rerror_rate=0.0,
        srv_rerror_rate=0.0,
        same_srv_rate=1.0,
        diff_srv_rate=0.0,
        srv_diff_host_rate=0.0,
        dst_host_count=1,
        dst_host_srv_count=1,
        dst_host_same_srv_rate=1.0,
        dst_host_diff_srv_rate=0.0,
        dst_host_same_src_port_rate=0.0,
        dst_host_srv_diff_host_rate=0.0,
        dst_host_serror_rate=0.0,
        dst_host_srv_serror_rate=0.0,
        dst_host_rerror_rate=0.0,
        dst_host_srv_rerror_rate=0.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
    )
    base.update(overrides)
    return NslKddStyleFeatures(**base)
