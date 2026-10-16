"""Time-series buckets, burst detection, entropy-based encryption guess, traffic-class inference."""

from __future__ import annotations

import math
from collections import defaultdict

BUCKET_S = 10

# Bitrate (bit/s) heuristics for classification — indicators only.
VIDEO_BPS = 200_000
AUDIO_BPS = 16_000
TELEMETRY_BPS = 2_000


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def encryption_verdict(samples: list[bytes], assumed_tls: bool = False) -> dict:
    """Return {kind, confidence, readable_fraction, detail}.
    kind: tls | plaintext | custom-encryption | unknown
    """
    if assumed_tls:
        return {"kind": "tls", "confidence": "certain", "readable_fraction": 0.0,
                "detail": "TLS record observed (ClientHello / port)."}
    if not samples:
        return {"kind": "unknown", "confidence": "low", "readable_fraction": 0.0,
                "detail": "No payload samples."}
    blob = b"".join(samples)[:65536]
    if not blob:
        return {"kind": "unknown", "confidence": "low", "readable_fraction": 0.0,
                "detail": "Empty payloads."}
    ent = shannon_entropy(blob)
    # Printable / whitespace ratio
    printable = sum(1 for b in blob if 32 <= b < 127 or b in (9, 10, 13))
    readable = printable / len(blob)
    # HTTP-like
    head = blob[:32].lstrip()
    if head.startswith((b"GET ", b"POST ", b"HTTP/", b"PUT ", b"HEAD ")):
        return {"kind": "plaintext", "confidence": "certain", "readable_fraction": readable,
                "detail": f"Readable HTTP-like plaintext (entropy {ent:.2f})."}
    if readable > 0.7 and ent < 5.0:
        return {"kind": "plaintext", "confidence": "high", "readable_fraction": readable,
                "detail": f"Mostly readable bytes ({readable:.0%}), entropy {ent:.2f}."}
    if ent >= 7.2:
        return {"kind": "custom-encryption", "confidence": "medium", "readable_fraction": readable,
                "detail": f"High entropy ({ent:.2f}) without TLS handshake — "
                          "non-standard encryption (custom protocol), unverified."}
    if ent >= 6.0:
        return {"kind": "custom-encryption", "confidence": "low", "readable_fraction": readable,
                "detail": f"Moderate-high entropy ({ent:.2f}) without TLS — "
                          "possibly custom encryption, unverified."}
    return {"kind": "plaintext", "confidence": "medium", "readable_fraction": readable,
            "detail": f"Low entropy ({ent:.2f}), likely plaintext."}


def bucket_key(ts: float) -> int:
    return int(ts // BUCKET_S) * BUCKET_S


def detect_bursts(series: dict[int, int], idle_threshold_bps: float = TELEMETRY_BPS) -> list[dict]:
    """Label contiguous 10s buckets as idle or active (burst). series: epoch->bytes."""
    if not series:
        return []
    keys = sorted(series)
    periods = []
    cur = None
    for k in keys:
        bps = series[k] * 8 / BUCKET_S
        kind = "active" if bps >= idle_threshold_bps else "idle"
        if cur and cur["kind"] == kind and k <= cur["end"] + BUCKET_S:
            cur["end"] = k + BUCKET_S
            cur["bytes"] += series[k]
        else:
            if cur:
                periods.append(cur)
            cur = {"kind": kind, "start": k, "end": k + BUCKET_S, "bytes": series[k]}
    if cur:
        periods.append(cur)
    return periods


def classify_traffic(bytes_total: int, duration_s: float, ports: set[int],
                     avg_pkt: float | None = None, protocols: set[str] | None = None) -> dict:
    """Infer video/audio/telemetry with confidence. Indicators only."""
    protocols = protocols or set()
    bps = (bytes_total * 8 / duration_s) if duration_s > 0 else 0
    evidence = {"bps": round(bps), "bytes": bytes_total, "duration_s": round(duration_s, 1),
                "ports": sorted(ports), "protocols": sorted(protocols)}
    # Protocol signatures first
    if 3478 in ports or "STUN" in protocols:
        return {"label": "audio+video", "confidence": "medium",
                "detail": "STUN/TURN present — typical of P2P video/audio setup.",
                "evidence": evidence}
    if 554 in ports or 8554 in ports or "RTSP" in protocols:
        return {"label": "video", "confidence": "high",
                "detail": "RTSP port observed.", "evidence": evidence}
    if bps >= VIDEO_BPS and (avg_pkt or 0) >= 800:
        return {"label": "video", "confidence": "medium",
                "detail": f"Sustained ~{bps/1000:.0f} kbit/s with large packets — looks like video.",
                "evidence": evidence}
    if AUDIO_BPS <= bps < VIDEO_BPS and (avg_pkt or 999) < 400:
        return {"label": "audio", "confidence": "low",
                "detail": f"~{bps/1000:.1f} kbit/s small packets — looks like audio.",
                "evidence": evidence}
    if bps < TELEMETRY_BPS or bytes_total < 5000:
        return {"label": "telemetry", "confidence": "medium",
                "detail": f"Low volume (~{bps:.0f} bit/s) — looks like telemetry/control.",
                "evidence": evidence}
    return {"label": "unknown", "confidence": "low",
            "detail": f"~{bps/1000:.1f} kbit/s — not enough signal to classify.",
            "evidence": evidence}


def merge_series(flows_series: list[dict[int, int]]) -> dict[int, int]:
    out: dict[int, int] = defaultdict(int)
    for s in flows_series:
        for k, v in s.items():
            out[k] += v
    return dict(out)
