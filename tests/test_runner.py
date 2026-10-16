"""Integration tests for the SubprocessRunner."""

import sys
from proctrace.collectors.runner import SubprocessRunner
from proctrace.core.models import EventOperation
from proctrace.core.ring_buffer import RingBuffer


def test_subprocess_runner_execution():
    rb = RingBuffer(capacity=100)

    # Launch python command that prints something and exits cleanly
    cmd = [sys.executable, "-c", "print('hello from child process')"]
    runner = SubprocessRunner(
        command=cmd,
        ring_buffer=rb,
        capture_output=True,
    )

    exit_code = runner.run()
    assert exit_code == 0
    assert "hello from child process" in runner.stdout_data

    # Verify that SPAWN and EXIT events were recorded
    events = rb.get_all()
    assert len(events) >= 2
    spawn_ev = next(e for e in events if e.operation == EventOperation.SPAWN)
    exit_ev = next(e for e in events if e.operation == EventOperation.EXIT)

    assert spawn_ev.pid == runner.process.pid
    assert exit_ev.return_code == 0


def test_subprocess_runner_failure():
    rb = RingBuffer(capacity=100)

    cmd = [sys.executable, "-c", "import sys; sys.exit(42)"]
    runner = SubprocessRunner(
        command=cmd,
        ring_buffer=rb,
        capture_output=True,
    )

    exit_code = runner.run()
    assert exit_code == 42

    exit_ev = next(e for e in rb.get_all() if e.operation == EventOperation.EXIT)
    assert exit_ev.return_code == 42
    assert exit_ev.is_error is True
