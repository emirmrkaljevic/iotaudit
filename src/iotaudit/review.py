"""Derive the honest 'was the media actually observed?' verdict from a report dict.

This mirrors the logic used while building findings, but works on the serialized JSON report
(a device dict from analyze.to_dict). Keeping it here lets the MCP server, tests and external
callers re-check a saved report without re-running a capture.
"""

from __future__ import annotations

from .enrich import is_special_use

MEDIA_THRESHOLD = 500_000  # bytes; below this we don't claim a real video/audio stream


def _tc(d: dict) -> dict:
    return d.get("traffic_class") or {}


def review_report(dev: dict) -> dict:
    """Return a verdict dict for one device report.

    Keys: stun (bool), observed_media (bool), real_lan_bytes (int),
    special_use_peers (list[str]), ipv6_bytes (int), media_not_observed (bool).
    media_not_observed is True when a P2P session was set up (STUN) but no sustained media
    stream was captured on the LAN, over IPv6, or to the cloud — i.e. the honest
    "video may have gone directly to your phone; not observed" case.
    """
    dests = dev.get("destinations") or []
    peers = dev.get("lan_peers") or []
    stun = any(
        3478 in (d.get("ports") or []) or "STUN/TURN" in (d.get("protocols") or [])
        for d in dests
    )
    observed_media = any(
        _tc(d).get("label") in ("video", "audio", "audio+video")
        and _tc(d).get("confidence") in ("medium", "high")
        for d in (dests + peers)
    )
    real_lan_bytes = sum(
        (p.get("bytes_out") or 0) + (p.get("bytes_in") or 0)
        for p in peers
        if not (p.get("special_use") or is_special_use(p.get("ip", "")))
    )
    special = [
        p.get("ip") for p in peers
        if p.get("special_use") or is_special_use(p.get("ip", ""))
    ]
    ipv6 = dev.get("ipv6") or {}
    ipv6_bytes = ipv6.get("bytes", 0) or 0
    not_observed = (
        stun
        and not observed_media
        and real_lan_bytes < MEDIA_THRESHOLD
        and ipv6_bytes < MEDIA_THRESHOLD
    )
    return {
        "stun": stun,
        "observed_media": observed_media,
        "real_lan_bytes": real_lan_bytes,
        "special_use_peers": special,
        "ipv6_bytes": ipv6_bytes,
        "media_not_observed": not_observed,
    }
