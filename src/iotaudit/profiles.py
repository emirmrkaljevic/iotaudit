"""Device profile library. A profile is YAML describing what a device is expected to do.

Format (see src/iotaudit/profiles/*.yaml):

    id: tuya-generic
    name: Tuya-based smart device (pet feeders, plugs, cameras)
    match:
      mac_vendors: ["Tuya", "Espressif"]
      domains: ["tuyaeu.com", "tuyaus.com"]
    expected_domains: ["tuyaeu.com", "tuya.com", "pool.ntp.org"]
    expected_ports: [443, 8883, 123]
    notes: "Talks MQTT over TLS (8883) to Tuya cloud."
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml

from .enrich import suffix_match


def load_profiles(extra_dir: str | None = None) -> list[dict]:
    profiles = []
    pkg = resources.files("iotaudit") / "profiles"
    for entry in pkg.iterdir():
        if entry.name.endswith((".yaml", ".yml")):
            profiles.append(yaml.safe_load(entry.read_text(encoding="utf-8")))
    if extra_dir:
        for p in sorted(Path(extra_dir).glob("*.y*ml")):
            profiles.append(yaml.safe_load(p.read_text(encoding="utf-8")))
    return profiles


def match_profile(device, profiles: list[dict]) -> dict | None:
    names = set(device.dns_queries)
    for d in device.destinations.values():
        names |= d.domains
    best, best_score = None, 0
    for prof in profiles:
        m = prof.get("match", {})
        score = 0
        if device.vendor and any(v.lower() in device.vendor.lower() for v in m.get("mac_vendors", [])):
            score += 1
        table = set(m.get("domains", []))
        if any(suffix_match(n, table) for n in names):
            score += 2
        if score > best_score:
            best, best_score = prof, score
    return best


def is_expected(domains, profile: dict | None) -> bool | None:
    if not profile or not domains:
        return None
    table = set(profile.get("expected_domains", []))
    return any(suffix_match(d, table) for d in domains)
