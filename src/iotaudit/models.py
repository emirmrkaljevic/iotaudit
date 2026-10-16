"""Shared data structures."""

from __future__ import annotations

from dataclasses import dataclass, field


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
class Destination:
    ip: str
    domains: set[str] = field(default_factory=set)
    country: str | None = None
    org: str | None = None
    ports: set[int] = field(default_factory=set)
    bytes_out: int = 0
    encrypted: bool = True
    tracker: bool = False
    expected: bool | None = None  # matches device profile?


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
