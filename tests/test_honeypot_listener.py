import socket
import threading
import time

from nids.core.event import Severity
from nids.honeypot.listener import (
    _BANNERS,
    HoneypotHit,
    event_from_honeypot_hit,
    run_honeypot,
)


def _free_port() -> int:
    """descopera un port liber si permis de OS, in loc sa presupuna un
    numar fix - unele porturi inalte sunt rezervate/interzise la nivel de
    sistem (Hyper-V/WSL pe Windows), variaza intre masini. bind la portul
    0 lasa OS-ul sa aleaga unul valid"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


def _wait_until(condition, timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        time.sleep(0.02)
    assert condition(), "conditia nu a fost indeplinita in timp util"


def _start_honeypot(
    ports: list[int], hits: list, errors: list
) -> tuple[threading.Thread, threading.Event]:
    stop_event = threading.Event()
    thread = threading.Thread(
        target=run_honeypot,
        args=(ports, hits.append, lambda port, msg: errors.append((port, msg)), stop_event),
        daemon=True,
    )
    thread.start()
    return thread, stop_event


def test_connection_triggers_hit_with_correct_fields():
    port = _free_port()
    hits: list[HoneypotHit] = []
    errors: list = []
    thread, stop_event = _start_honeypot([port], hits, errors)

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
            conn.sendall(b"hello")
        _wait_until(lambda: len(hits) == 1)
    finally:
        stop_event.set()
        thread.join(timeout=2)

    assert hits[0].dst_port == port
    assert hits[0].src_ip == "127.0.0.1"
    assert hits[0].received_preview == "hello"
    assert errors == []


def test_connection_without_sending_data_still_triggers_hit():
    port = _free_port()
    hits: list[HoneypotHit] = []
    errors: list = []
    thread, stop_event = _start_honeypot([port], hits, errors)

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
        _wait_until(lambda: len(hits) == 1)
    finally:
        stop_event.set()
        thread.join(timeout=2)

    assert hits[0].received_preview == ""


def test_listens_on_multiple_ports_simultaneously():
    port_a, port_b = _free_port(), _free_port()
    hits: list[HoneypotHit] = []
    errors: list = []
    thread, stop_event = _start_honeypot([port_a, port_b], hits, errors)

    try:
        with socket.create_connection(("127.0.0.1", port_a), timeout=2):
            pass
        with socket.create_connection(("127.0.0.1", port_b), timeout=2):
            pass
        _wait_until(lambda: len(hits) == 2)
    finally:
        stop_event.set()
        thread.join(timeout=2)

    assert {h.dst_port for h in hits} == {port_a, port_b}


def test_stop_event_ends_the_loop():
    port = _free_port()
    hits: list[HoneypotHit] = []
    errors: list = []
    thread, stop_event = _start_honeypot([port], hits, errors)
    time.sleep(0.2)  # lasa bind-ul sa se termine

    stop_event.set()
    thread.join(timeout=2)

    assert not thread.is_alive()


def test_bind_error_reported_for_port_already_in_use():
    port = _free_port()
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("0.0.0.0", port))
    blocker.listen(1)

    errors: list = []
    stop_event = threading.Event()
    stop_event.set()  # oprit din start - nu vrem sa intre in bucla de accept

    try:
        run_honeypot(
            [port], lambda hit: None, lambda p, msg: errors.append((p, msg)), stop_event
        )
    finally:
        blocker.close()

    assert len(errors) == 1
    assert errors[0][0] == port


def test_banners_defined_for_common_impersonated_services():
    assert 22 in _BANNERS
    assert 23 in _BANNERS


def test_event_from_hit_has_high_severity_and_correct_identity():
    hit = HoneypotHit(src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview="")

    event = event_from_honeypot_hit(hit)

    assert event.severity == Severity.HIGH
    assert event.source_ip == "1.2.3.4"
    assert event.src_port == 5000
    assert event.dest_port == 2222
    assert "2222" in event.description


def test_event_from_hit_includes_preview_when_present():
    hit = HoneypotHit(
        src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview="GET / HTTP/1.1"
    )

    event = event_from_honeypot_hit(hit)

    assert "GET / HTTP/1.1" in event.description


def test_event_from_hit_omits_preview_section_when_empty():
    hit = HoneypotHit(src_ip="1.2.3.4", src_port=5000, dst_port=2222, received_preview="")

    event = event_from_honeypot_hit(hit)

    assert "a trimis" not in event.description
