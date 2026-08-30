"""
TRACE — Stage Timing
======================
Small, dependency-free utility to time each stage of a scan
(DNS, TCP, HTTP, TLS, ...) without touching the logic of those stages.

Usage:
    timer = StageTimer()

    with timer.measure("DNS"):
        ip = check_dns(target)

    with timer.measure("TCP"):
        open_ports = check_ports(ip)

    print(timer.render())
"""

import time
from contextlib import contextmanager


class StageTimer:
    def __init__(self):
        self._durations_ms = {}
        self._order = []

    @contextmanager
    def measure(self, stage_name: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if stage_name not in self._durations_ms:
                self._order.append(stage_name)
            self._durations_ms[stage_name] = elapsed_ms

    def get(self, stage_name: str):
        return self._durations_ms.get(stage_name)

    def total_ms(self):
        return sum(self._durations_ms.values())

    def as_dict(self):
        return dict(self._durations_ms)

    def render(self, title: str = "TRACE TIMING") -> str:
        if not self._order:
            return f"{title}\n(no stages recorded)"

        lines = [title]
        label_width = max(len(name) for name in self._order) + 2

        for name in self._order:
            ms = self._durations_ms[name]
            lines.append(f"{name.ljust(label_width)}{ms:6.1f} ms")

        lines.append("-" * (label_width + 10))
        lines.append(f"{'TOTAL'.ljust(label_width)}{self.total_ms():6.1f} ms")

        return "\n".join(lines)
