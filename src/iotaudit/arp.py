"""ARP mode (advanced, own network only). Not implemented in 0.0.x on purpose:
hotspot mode is safer and more reliable. Planned for v0.2 behind an extra consent step."""

from __future__ import annotations


def start(*_args, **_kwargs):
    raise NotImplementedError(
        "ARP mode is not available yet. Use `iotaudit capture --mode hotspot` or import a pcap."
    )
