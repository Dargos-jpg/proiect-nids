from nids.core.simulation import local_ip, run_port_scan_simulation


def test_local_ip_returns_valid_looking_address():
    ip = local_ip()
    parts = ip.split(".")
    assert len(parts) == 4
    assert all(p.isdigit() for p in parts)


def test_run_port_scan_simulation_against_loopback_completes():
    target = run_port_scan_simulation(target_ip="127.0.0.1", ports=[65432, 65433, 65434])

    assert target == "127.0.0.1"
