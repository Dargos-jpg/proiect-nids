from nids.ml.features.service_names import service_name


def test_known_tcp_ports():
    assert service_name("tcp", 80) == "http"
    assert service_name("tcp", 22) == "ssh"
    assert service_name("tcp", 443) == "http_443"


def test_known_udp_ports():
    assert service_name("udp", 53) == "domain_u"


def test_ephemeral_port_is_private():
    assert service_name("tcp", 60000) == "private"


def test_unknown_low_port_is_other():
    assert service_name("tcp", 9999) == "other"


def test_no_port_is_other():
    assert service_name("icmp", None) == "other"
