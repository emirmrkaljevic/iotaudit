"""Draft device profiles from a saved audit, with made-up sample data only."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from iotaudit.cli import main
from iotaudit.models import Destination, Device
from iotaudit.profile_export import export_profile, profile_from_device
from iotaudit.profiles import match_profile
from iotaudit.redact import redact_audit

DASHES = ("\u2014", "\u2013")

AUDIT = {
    "meta": {
        "source": "auto:wlan0",
        "ssid": "HomeNet-Secret",
        "path": "/home/person/captures/kitchen.pcap",
    },
    "devices": [
        {
            "ip": "192.168.1.23",
            "mac": "AA:BB:CC:11:22:33",
            "hostname": "kitchen-plug",
            "vendor": "Example Vendor",
            "model": "Plug 2000",
            "verdict": "kitchen-plug at 192.168.1.23 talks to 8.8.8.8",
            "device_type": {"type": "plug", "label": "plug", "confidence": "medium"},
            "dns_queries": ["a2.tuyaeu.com", "kitchen-plug.local", "pool.ntp.org"],
            "destinations": [
                {
                    "ip": "8.8.8.8",
                    "domains": ["a2.tuyaeu.com"],
                    "country": "Germany",
                    "ports": [8883, 443],
                    "lan": False,
                },
                {
                    "ip": "192.168.1.40",
                    "domains": ["nas.home"],
                    "ports": [445],
                    "lan": True,
                },
            ],
            "destination_countries": [{"country": "Germany", "bytes_out": 1000}],
        },
        {
            "ip": "192.168.1.40",
            "mac": "aa-bb-cc-44-55-66",
            "hostname": "family-nas",
            "vendor": "Example Vendor",
            "dns_queries": [],
            "destinations": [],
        },
    ],
}


SECRETS = (
    "192.168.1.23",
    "192.168.1.40",
    "AA:BB:CC:11:22:33",
    "aa-bb-cc-44-55-66",
    "kitchen-plug",
    "family-nas",
    "wlan0",
    "HomeNet-Secret",
    "/home/person/captures/kitchen.pcap",
    "lan-1",
    "lan-2",
    "host-1",
    "host-2",
    "02:00:00:00",
    "nas.home",
)


def _yaml(text: str) -> dict:
    # skip comment header
    return yaml.safe_load(text)


def test_export_keeps_vendor_model_domains_and_drops_local_details():
    text = export_profile(AUDIT, "1")
    for secret in SECRETS:
        assert secret not in text, secret
    prof = _yaml(text)
    assert prof["match"]["mac_vendors"] == ["Example Vendor"]
    assert prof["model"] == "Plug 2000"
    assert "tuyaeu.com" in prof["match"]["domains"]
    assert "ntp.org" in prof["expected_domains"]
    assert "a2.tuyaeu.com" not in text  # collapsed to the registrable domain
    assert 8883 in prof["expected_ports"] and 443 in prof["expected_ports"]
    assert 445 not in prof["expected_ports"]  # LAN port dropped
    assert prof["destination_countries"] == ["Germany"]
    assert "hostnames" not in prof.get("match", {})


def test_export_uses_redact_audit(monkeypatch):
    called = {"n": 0}
    real = redact_audit

    def wrapped(data):
        called["n"] += 1
        return real(data)

    monkeypatch.setattr("iotaudit.profile_export.redact_audit", wrapped)
    export_profile(AUDIT, "192.168.1.23")
    assert called["n"] == 1


def test_select_by_vendor_is_ambiguous_when_two_match():
    try:
        export_profile(AUDIT, "Example Vendor")
    except ValueError as exc:
        assert "2 devices matched" in str(exc)
    else:
        raise AssertionError("expected ambiguity error")


def test_select_by_index_and_missing_selector():
    text = export_profile(AUDIT, "1")
    assert "tuyaeu.com" in text
    try:
        export_profile(AUDIT, "9")
    except ValueError as exc:
        assert "no device at index 9" in str(exc)
    else:
        raise AssertionError("expected missing index error")


def test_second_device_with_no_public_domains_is_rejected():
    try:
        export_profile(AUDIT, "2")
    except ValueError as exc:
        assert "no public destinations" in str(exc)
    else:
        raise AssertionError("expected empty-profile error")


def test_placeholders_from_redaction_are_not_copied():
    redacted = redact_audit(AUDIT)
    device = redacted["devices"][0]
    assert device["ip"] == "lan-1" and device["hostname"] == "host-1"
    prof = profile_from_device(device)
    dumped = yaml.safe_dump(prof)
    for secret in ("lan-1", "host-1", "02:00:00:00", "kitchen-plug"):
        assert secret not in dumped


def test_exported_yaml_loads_as_a_bundled_profile():
    prof = _yaml(export_profile(AUDIT, "1"))
    dev = Device(ip="192.0.2.50", vendor="Example Vendor")
    dest = Destination(ip="203.0.113.10", ports={443}, encrypted=True, bytes_out=100)
    dest.domains.add("m2.tuyaeu.com")
    dev.destinations["203.0.113.10"] = dest
    dev.dns_queries.add("m2.tuyaeu.com")
    matched = match_profile(dev, [prof])
    assert matched and matched["id"] == prof["id"]


def test_cli_writes_anonymized_yaml(tmp_path, capsys, monkeypatch):
    src = tmp_path / "audit.json"
    src.write_text(json.dumps(AUDIT), encoding="utf-8")
    dest = tmp_path / "draft.yaml"
    assert main(["profile", "export", str(src), "1", "--out", str(dest)]) == 0
    out = capsys.readouterr()
    assert "Draft profile written" in out.out
    text = dest.read_text(encoding="utf-8")
    for secret in SECRETS:
        assert secret not in text
    assert "tuyaeu.com" in text
    # stdout path
    assert main(["profile", "export", str(src), "1"]) == 0
    printed = capsys.readouterr().out
    assert "tuyaeu.com" in printed
    assert yaml.safe_load(printed)["model"] == "Plug 2000"
    assert main(["profile", "export", str(tmp_path / "missing.json"), "1"]) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    assert main(["profile", "export", str(bad), "1"]) == 1


def test_docs_and_issue_template_have_no_typographic_dashes():
    root = Path(__file__).resolve().parents[1]
    files = [
        root / "CONTRIBUTING.md",
        root / "docs" / "device-profiles.md",
        root / ".github" / "ISSUE_TEMPLATE" / "device-profile.yml",
        root / "src" / "iotaudit" / "profile_export.py",
    ]
    for path in files:
        text = path.read_text(encoding="utf-8")
        for dash in DASHES:
            assert dash not in text, path
