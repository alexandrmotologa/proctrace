"""OS event collectors for Windows, Linux, and macOS."""

from proctrace.collectors.base import BaseCollector
from proctrace.collectors.linux import LinuxCollector
from proctrace.collectors.macos import MacOSCollector
from proctrace.collectors.runner import SubprocessRunner, get_default_collector
from proctrace.collectors.windows import WindowsCollector

__all__ = [
    "BaseCollector",
    "WindowsCollector",
    "LinuxCollector",
    "MacOSCollector",
    "SubprocessRunner",
    "get_default_collector",
]
