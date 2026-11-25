"""Tests for credbroker.board.Board: pending queue, resolution, history, toggle."""
import threading

import pytest

from credbroker import board as board_module
from credbroker.board import Board


def _open(b, **overrides):
    kwargs = dict(peer="1.2.3.4", agent="alpha", kind="exec", detail={}, timeout=5)
    kwargs.update(overrides)
    return b.open(**kwargs)


def test_wait_returns_allow_and_via_gui_when_resolved_from_another_thread():
    b = Board()
    item_id, _event = _open(b)
    results = []

    def waiter():
        results.append(b.wait(item_id, 5))

    t = threading.Thread(target=waiter)
    t.start()
    # Give the waiter a moment to block on the event before resolving.
    import time

    time.sleep(0.05)
    resolved = b.resolve([item_id], "allow")
    t.join(5)

    assert resolved == [item_id]
    assert results == [(True, "gui")]
    assert item_id not in [p["id"] for p in b.snapshot()["pending"]]


def test_wait_times_out_with_no_resolver():
    b = Board()
    item_id, _event = _open(b)
    assert b.wait(item_id, 0.05) == (False, "timeout")


def test_resolve_with_custom_via_is_reflected_in_wait():
    b = Board()
    item_id, _event = _open(b)

    def resolver():
        import time

        time.sleep(0.05)
        b.resolve([item_id], "deny", via="prompt")

    threading.Thread(target=resolver).start()
    assert b.wait(item_id, 5) == (False, "prompt")


def test_resolving_twice_second_call_is_noop():
    b = Board()
    item_id, _event = _open(b)
    first = b.resolve([item_id], "allow")
    second = b.resolve([item_id], "deny")

    assert first == [item_id]
    assert second == []
    assert b.wait(item_id, 5) == (True, "gui")


def test_three_opens_pending_order_ascending_by_id():
    b = Board()
    ids = [_open(b)[0] for _ in range(3)]
    pending_ids = [p["id"] for p in b.snapshot()["pending"]]
    assert pending_ids == ids


def test_add_history_beyond_capacity_keeps_newest_first():
    b = Board(history_size=2)
    b.add_history({"n": 1})
    b.add_history({"n": 2})
    b.add_history({"n": 3})
    assert [h["n"] for h in b.snapshot()["history"]] == [3, 2]


def test_resolve_rejects_invalid_decision():
    b = Board()
    item_id, _event = _open(b)
    with pytest.raises(ValueError):
        b.resolve([item_id], "maybe")


def test_desktop_wanted_fresh_board_is_true():
    b = Board()
    assert b.desktop_wanted() is True


def test_desktop_wanted_false_after_gui_poll():
    b = Board()
    b.touch_gui()
    assert b.desktop_wanted() is False


def test_desktop_wanted_true_when_notify_while_open_set():
    b = Board()
    b.touch_gui()
    b.set_notify_while_open(True)
    assert b.desktop_wanted() is True


def test_desktop_wanted_true_once_gui_open_window_elapses(monkeypatch):
    monkeypatch.setattr(board_module, "GUI_OPEN_WINDOW", 0)
    b = Board()
    b.touch_gui()
    assert b.desktop_wanted() is True
