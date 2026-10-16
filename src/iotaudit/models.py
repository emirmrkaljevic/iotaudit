"""Shared data structures."""

from __future__ import annotations

from dataclasses import dataclass, field

CONFIDENCE_LEVELS = ("low", "medium", "high", "certain")
CATEGORIES = (
    "encryption", "destination", "tracker", "port", "credential", "cve", "upnp", "dns",
    "lan-scan", "firmware", "traffic-class", "new-device", "coverage",
)
TRAFFIC_CLASSES = ("video", "audio", "audio+video", "telemetry", "firmware-download", "unknown")


@dataclass
class Flow:
    src: str
    dst: str
    dport: int
    proto: str  # "tcp" / "udp"
    bytes: int = 0
    packets: int = 0
    tls: bool = False
    tls_version: str | None = None
    sni: str | None = None
    plaintext_http: bool = False
    http_host: str | None = None


@dataclass
class Finding:
    """One observation about a device. Inferred findings carry confidence below 'certain'."""

    category: str
    severity: str  # high / medium / low / info
    title: str
    detail: str
    confidence: str = "certain"
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"category": self.category, "severity": self.severity, "title": self.title,
                "detail": self.detail, "confidence": self.confidence, "evidence": self.evidence}


@dataclass
class TrafficClass:
    """Inferred content type of traffic to one destination."""

    label: str = "unknown"
    confidence: str = "low"
    while_app_idle: bool | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class Destination:
    ip: str
    domains: set[str] = field(default_factory=set)
    country: str | None = None
    org: str | None = None
    ports: set[int] = field(default_factory=set)
    bytes_out: int = 0
    encrypted: bool = True
    tracker: bool = False
    expected: bool | None = None
    protocols: set[str] = field(default_factory=set)
    traffic_class: TrafficClass | None = None
    first_seen: float | None = None
    last_seen: float | None = None


@dataclass
class Device:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    profile: str | None = None
    destinations: dict[str, Destination] = field(default_factory=dict)
    dns_queries: set[str] = field(default_factory=set)
    open_ports: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    grade: str | None = None
    score: int | None = None
