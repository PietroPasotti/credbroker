"""In-memory FIFO board of pending `ask` requests, plus decided history and
the desktop-notification toggle.

Standalone module: no `credbroker.server` import, so it stays easy to test
and reuse (the broker's GUI server also talks to it without needing the
rest of server.py's HTTP plumbing).
"""
import collections
import itertools
import threading
import time

GUI_OPEN_WINDOW = 5.0  # seconds since last GUI poll that count as "GUI open"


class Board:
    def __init__(self, history_size: int = 500):
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._pending: dict[int, dict] = {}
        self._waiters: dict[int, tuple[threading.Event, list]] = {}
        self._history = collections.deque(maxlen=history_size)
        self._last_gui_poll = 0.0
        self.notify_while_open = False

    def open(self, *, peer: str, agent: str, kind: str, detail: dict, timeout: float) -> tuple[int, threading.Event]:
        with self._lock:
            item_id = next(self._ids)
            now = time.time()
            self._pending[item_id] = {
                "id": item_id,
                "created": now,
                "expires": now + timeout,
                "peer": peer,
                "agent": agent,
                "kind": kind,
                "detail": detail,
            }
            event = threading.Event()
            self._waiters[item_id] = (event, [])
            return item_id, event

    def wait(self, item_id: int, timeout: float) -> tuple[bool, str]:
        with self._lock:
            event, _ = self._waiters[item_id]
        event.wait(timeout)
        with self._lock:
            self._pending.pop(item_id, None)
            holder = self._waiters.pop(item_id)[1]
        if not holder:
            return False, "timeout"
        decision, via = holder[0]
        return decision == "allow", via

    def resolve(self, ids: list[int], decision: str, via: str = "gui") -> list[int]:
        if decision not in ("allow", "deny"):
            raise ValueError(f"bad decision: {decision!r}")
        resolved = []
        with self._lock:
            for item_id in ids:
                if item_id not in self._pending:
                    continue
                event, holder = self._waiters[item_id]
                if holder:
                    continue
                holder.append((decision, via))
                event.set()
                del self._pending[item_id]
                resolved.append(item_id)
        return resolved

    def remaining(self, item_id: int) -> float | None:
        with self._lock:
            item = self._pending.get(item_id)
            return None if item is None else item["expires"] - time.time()

    def add_history(self, entry: dict) -> None:
        with self._lock:
            self._history.appendleft(dict(entry))

    def touch_gui(self) -> None:
        self._last_gui_poll = time.monotonic()

    def gui_open(self) -> bool:
        return time.monotonic() - self._last_gui_poll < GUI_OPEN_WINDOW

    def set_notify_while_open(self, value: bool) -> None:
        with self._lock:
            self.notify_while_open = value

    def desktop_wanted(self) -> bool:
        return not self.gui_open() or self.notify_while_open

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "pending": list(self._pending.values()),
                "history": list(self._history),
                "notify_while_open": self.notify_while_open,
                "gui_open": self.gui_open(),
            }
