import time
from datetime import timedelta

import pytest

from nids.response.manager import BlockManager, BlockRuleError


def _fake_manager(duration: timedelta = timedelta(minutes=10)) -> tuple[BlockManager, list, list]:
    added: list[str] = []
    removed: list[str] = []
    manager = BlockManager(
        add_rule=added.append, remove_rule=removed.append, default_duration=duration
    )
    return manager, added, removed


def test_block_calls_add_rule_and_tracks_entry():
    manager, added, removed = _fake_manager()

    entry = manager.block("10.0.0.5", reason="port scan")

    assert added == ["10.0.0.5"]
    assert removed == []
    assert entry.ip == "10.0.0.5"
    assert entry.reason == "port scan"
    assert manager.is_blocked("10.0.0.5")
    assert entry in manager.active_blocks()


def test_blocking_same_ip_twice_is_idempotent():
    manager, added, _ = _fake_manager()

    first = manager.block("10.0.0.5", reason="port scan")
    second = manager.block("10.0.0.5", reason="alt motiv")

    assert added == ["10.0.0.5"]  # add_rule apelat o singura data
    assert first is second


def test_unblock_calls_remove_rule_and_clears_entry():
    manager, added, removed = _fake_manager()
    manager.block("10.0.0.5", reason="port scan")

    manager.unblock("10.0.0.5")

    assert removed == ["10.0.0.5"]
    assert not manager.is_blocked("10.0.0.5")
    assert manager.active_blocks() == []


def test_unblock_unknown_ip_is_noop():
    manager, _, removed = _fake_manager()

    manager.unblock("10.0.0.9")

    assert removed == []


def test_block_auto_expires_after_duration():
    manager, _, removed = _fake_manager(duration=timedelta(milliseconds=100))

    manager.block("10.0.0.5", reason="port scan")
    assert manager.is_blocked("10.0.0.5")

    deadline = time.time() + 2
    while manager.is_blocked("10.0.0.5") and time.time() < deadline:
        time.sleep(0.02)

    assert not manager.is_blocked("10.0.0.5")
    assert removed == ["10.0.0.5"]


def test_shutdown_removes_all_active_blocks():
    manager, _, removed = _fake_manager(duration=timedelta(minutes=10))
    manager.block("10.0.0.5", reason="port scan")
    manager.block("10.0.0.6", reason="brute force")

    manager.shutdown()

    assert sorted(removed) == ["10.0.0.5", "10.0.0.6"]
    assert manager.active_blocks() == []


def test_history_includes_active_block_with_no_end_reason():
    manager, _, _ = _fake_manager()

    manager.block("10.0.0.5", reason="port scan")

    entry = manager.history()[0]
    assert entry.ip == "10.0.0.5"
    assert entry.unblocked_at is None
    assert entry.ended_by is None


def test_history_records_manual_unblock():
    manager, _, _ = _fake_manager()
    manager.block("10.0.0.5", reason="port scan")

    manager.unblock("10.0.0.5")

    entry = manager.history()[0]
    assert entry.unblocked_at is not None
    assert entry.ended_by == "manual"


def test_history_records_expiry():
    manager, _, _ = _fake_manager(duration=timedelta(milliseconds=100))
    manager.block("10.0.0.5", reason="port scan")

    deadline = time.time() + 2
    while manager.is_blocked("10.0.0.5") and time.time() < deadline:
        time.sleep(0.02)

    entry = manager.history()[0]
    assert entry.ended_by == "expirat"


def test_history_records_shutdown_reason():
    manager, _, _ = _fake_manager()
    manager.block("10.0.0.5", reason="port scan")

    manager.shutdown()

    entry = manager.history()[0]
    assert entry.ended_by == "oprire aplicatie"


def test_history_keeps_separate_entries_for_reblocked_ip():
    manager, _, _ = _fake_manager()
    manager.block("10.0.0.5", reason="prima oara")
    manager.unblock("10.0.0.5")

    manager.block("10.0.0.5", reason="a doua oara")

    assert len(manager.history()) == 2
    assert manager.history()[0].ended_by == "manual"
    assert manager.history()[1].unblocked_at is None


def test_block_raises_block_rule_error_when_add_rule_fails():
    def failing_add_rule(ip: str) -> None:
        raise RuntimeError("netsh a refuzat")

    manager = BlockManager(add_rule=failing_add_rule, remove_rule=lambda ip: None)

    with pytest.raises(BlockRuleError):
        manager.block("10.0.0.5", reason="test")


def test_failed_block_leaves_no_trace_in_state():
    """regresie: un add_rule esuat nu trebuie sa lase IP-ul marcat ca
    blocat, nici in active_blocks(), nici in history()"""

    def failing_add_rule(ip: str) -> None:
        raise RuntimeError("netsh a refuzat")

    manager = BlockManager(add_rule=failing_add_rule, remove_rule=lambda ip: None)

    with pytest.raises(BlockRuleError):
        manager.block("10.0.0.5", reason="test")

    assert not manager.is_blocked("10.0.0.5")
    assert manager.active_blocks() == []
    assert manager.history() == []


def test_unblock_does_not_raise_when_remove_rule_fails():
    """regresie: un remove_rule esuat (ex: acelasi motiv - drepturi
    insuficiente) nu trebuie sa lase IP-ul blocat "pentru totdeauna" fara
    nicio cale de a-l scoate din UI"""

    def failing_remove_rule(ip: str) -> None:
        raise RuntimeError("netsh a refuzat")

    manager = BlockManager(add_rule=lambda ip: None, remove_rule=failing_remove_rule)
    manager.block("10.0.0.5", reason="test")

    manager.unblock("10.0.0.5")  # nu trebuie sa arunce

    assert not manager.is_blocked("10.0.0.5")
    assert manager.history()[0].ended_by == "manual"


def test_shutdown_does_not_raise_when_remove_rule_fails():
    def failing_remove_rule(ip: str) -> None:
        raise RuntimeError("netsh a refuzat")

    manager = BlockManager(add_rule=lambda ip: None, remove_rule=failing_remove_rule)
    manager.block("10.0.0.5", reason="test")
    manager.block("10.0.0.6", reason="test")

    manager.shutdown()  # nu trebuie sa arunce, si trebuie sa curete AMBELE

    assert manager.active_blocks() == []


def test_history_is_capped_at_max_history():
    manager, _, _ = _fake_manager()
    manager._max_history = 3

    for i in range(5):
        manager.block(f"10.0.0.{i}", reason="test")
        manager.unblock(f"10.0.0.{i}")

    assert len(manager.history()) == 3
    assert [e.ip for e in manager.history()] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
