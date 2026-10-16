"""Shared data structures."""

from __future__ import annotations

from dataclasses import dataclass, field

CONFIDENCE_LEVELS = ("low", "medium", "high", "certain")
CATEGORIES = (
    "encryption", "destination", "tracker", "port", "credential", "cve", "upnp", "dns",
    "lan-scan", "firmware", "traffic-class", "new-device", "coverage", "location",
)
TRAFFIC_CLASSES = ("video", "audio", "audio+video", "telemetry", "firmware-download", "unknown")


@dataclass
class Flow:
    src: str
    dst: str
    dport: int
    proto: str
    bytes: int = 0
    bytes_in: int = 0
    packets: int = 0
    packets_in: int = 0
    tls: bool = False
    tls_version: str | None = None
    sni: str | None = None
    plaintext_http: bool = False
    http_host: str | None = None
    lan: bool = False  # destination is private LAN
    series: dict = field(default_factory=dict)  # epoch_bucket -> bytes
    payload_samples: list = field(default_factory=list)  # up to a few chunks for entropy


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    confidence: str = "certain"
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"category": self.category, "severity": self.severity, "title": self.title,
                "detail": self.detail, "confidence": self.confidence, "evidence": self.evidence}


@dataclass
class TrafficClass:
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
    bytes_in: int = 0
    packets: int = 0
    packets_in: int = 0
    encrypted: bool = True
    encryption_kind: str | None = None  # tls / plaintext / custom-encryption / unknown
    encryption_detail: str | None = None
    readable_fraction: float | None = None
    tracker: bool = False
    expected: bool | None = None
    protocols: set[str] = field(default_factory=set)
    traffic_class: TrafficClass | None = None
    series: dict = field(default_factory=dict)
    bursts: list = field(default_factory=list)
    lan: bool = False
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
    lan_peers: dict[str, Destination] = field(default_factory=dict)
    dns_queries: set[str] = field(default_factory=set)
    open_ports: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    grade: str | None = None
    score: int | None = None
    summary: str | None = None
    series_total: dict = field(default_factory=dict)
    bursts: list = field(default_factory=list)
    idle_upload: str | None = None  # "none detected" / "detected"
    broadcasts: list = field(default_factory=list)
