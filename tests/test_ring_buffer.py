"""Unit tests for the circular ring buffer."""

import time
import pytest
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)
from proctrace.core.ring_buffer import RingBuffer


def make_event(seq: int, is_err: bool = False) -> SyscallEvent:
    return SyscallEvent(
        timestamp=1000.0 + seq,
        pid=100 + (seq % 5),
        process_name="test_proc",
        category=EventCategory.FILESYSTEM if seq % 2 == 0 else EventCategory.NETWORK,
        operation=EventOperation.OPEN,
        target_path=f"file_{seq}.txt",
        result=EventResult.FAILED_NOT_FOUND if is_err else EventResult.SUCCESS,
        duration_us=float(seq * 10),
    )


def test_ring_buffer_basic_append_and_stats():
    rb = RingBuffer(capacity=10)
    assert rb.capacity == 10
    assert rb.count == 0
    assert rb.total_ingested == 0

    for i in range(5):
        rb.append(make_event(i, is_err=(i == 3)))

    assert rb.count == 5
    assert rb.total_ingested == 5
    assert rb.total_dropped == 0
    assert rb.total_errors == 1

    stats = rb.get_stats()
    assert stats["active_count"] == 5
    assert stats["total_errors"] == 1
    assert stats["utilization_pct"] == 50.0


def test_ring_buffer_wrapping_overflow():
    rb = RingBuffer(capacity=5)

    # Ingest 12 items into buffer of capacity 5
    for i in range(12):
        rb.append(make_event(i))

    assert rb.count == 5
    assert rb.total_ingested == 12
    assert rb.total_dropped == 7

    all_items = rb.get_all()
    assert len(all_items) == 5
    # The oldest kept item should be item 7 (0-indexed sequence 7)
    assert all_items[0].target_path == "file_7.txt"
    assert all_items[-1].target_path == "file_11.txt"


def test_ring_buffer_slices_and_since():
    rb = RingBuffer(capacity=20)
    for i in range(10):
        rb.append(make_event(i))

    sliced = rb.get_slice(offset=2, limit=4)
    assert len(sliced) == 4
    assert sliced[0].target_path == "file_2.txt"

    since_items = rb.get_since(1005.0)
    assert len(since_items) == 5
    assert since_items[0].target_path == "file_5.txt"


def test_ring_buffer_filtering():
    rb = RingBuffer(capacity=50)
    for i in range(20):
        rb.append(make_event(i, is_err=(i % 4 == 0)))

    errs = rb.filter_events(errors_only=True)
    assert len(errs) == 5
    for e in errs:
        assert e.is_error is True

    fs_events = rb.filter_events(category=EventCategory.FILESYSTEM)
    assert len(fs_events) == 10

    slow_events = rb.filter_events(min_duration_us=100.0)
    assert all(e.duration_us >= 100.0 for e in slow_events)


def test_ring_buffer_subscription():
    rb = RingBuffer(capacity=10)
    received = []

    def subscriber(ev: SyscallEvent):
        received.append(ev.id)

    rb.subscribe(subscriber)
    ev = make_event(1)
    rb.append(ev)

    assert len(received) == 1
    assert received[0] == ev.id

    rb.unsubscribe(subscriber)
    rb.append(make_event(2))
    assert len(received) == 1


def test_ring_buffer_clear():
    rb = RingBuffer(capacity=10)
    for i in range(5):
        rb.append(make_event(i))
    assert rb.count == 5

    rb.clear()
    assert rb.count == 0
    assert rb.total_ingested == 0
    assert rb.total_errors == 0
    assert len(rb.get_all()) == 0
