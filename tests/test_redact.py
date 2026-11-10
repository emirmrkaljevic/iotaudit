"""Redaction of saved audits, with made-up sample data only."""

from __future__ import annotations

import json
from pathlib import Path

from iotaudit.cli import main
from iotaudit.redact import redact_audit

SAMPLE = {
    "meta": {"source": "auto:wlan0", "duration": 600},
    "devices": [
        {
            "ip": "192.168.1.23",
            "mac": "AA:BB:CC:11:22:33",
            "hostname": "kitchen-plug",
            "vendor": "Example Vendor",
            "verdict": "kitchen-plug at 192.168.1.23 talks to 52.1.2.3",
            "destinations": [{"ip": "52.1.2.3", "domains": ["a2.tuyaeu.com"]},
                             {"ip": "192.168.1.40", "domains": []},
                             {"ip": "fe80::1c2:3ff:fe44:5566", "domains": []}],
            "lan_peers": {"192.168.1.40": {"ports": [6668]}},
        },
        {"ip": "192.168.1.40", "mac": "aa-bb-cc-44-55-66", "vendor": "Example Vendor"},
    ],
}


def test_redact_replaces_local_details_and_keeps_cloud():
    out = redact_audit(SAMPLE)
    text = json.dumps(out)
    for secret in ("192.168.1.23", "192.168.1.40", "AA:BB:CC:11:22:33", "aa-bb-cc-44-55-66",
                   "kitchen-plug", "wlan0", "fe80::1c2:3ff:fe44:5566"):
        assert secret not in text
    assert "52.1.2.3" in text and "a2.tuyaeu.com" in text
    first, second = out["devices"]
    assert first["ip"] == "lan-1" and first["hostname"] == "host-1"
    assert first["verdict"] == "host-1 at lan-1 talks to 52.1.2.3"
    assert second["ip"] == first["destinations"][1]["ip"]
    assert "lan-2" in first["lan_peers"]
    assert first["mac"].startswith("02:00:00:00:")
    assert out["meta"] == {"duration": 600, "redacted": True}


def test_redact_accepts_plain_device_list():
    out = redact_audit(SAMPLE["devices"])
    assert isinstance(out, list) and out[0]["ip"] == "lan-1"


def test_redact_cli(tmp_path, capsys):
    src = tmp_path / "audit.json"
    src.write_text(json.dumps(SAMPLE))
    assert main(["redact", str(src)]) == 0
    dest = tmp_path / "audit.redacted.json"
    assert "192.168.1.23" not in dest.read_text()
    assert "audit.redacted.json" in capsys.readouterr().out
    assert main(["redact", str(src), "--out", str(src)]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("nope")
    assert main(["redact", str(bad)]) == 1


def test_report_redact_writes_html(tmp_path, capsys):
    fix = Path(__file__).parent / "fixtures" / "feeder_capture.json"
    src = tmp_path / "audit.json"
    src.write_text(fix.read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["report", "--redact", str(src)]) == 0
    dest = tmp_path / "audit.redacted.html"
    out = capsys.readouterr().out
    assert "Redacted HTML report" in out
    html = dest.read_text(encoding="utf-8")
    assert "192.168." not in html
    assert "lan-" in html
    assert "iotaudit" in html.lower()


def test_report_redact_rejects_html_input(tmp_path, capsys):
    html = tmp_path / "report.html"
    html.write_text("<html><body>ok</body></html>", encoding="utf-8")
    assert main(["report", "--redact", str(html)]) == 1
    assert "JSON audit" in capsys.readouterr().err


NESTED = {
    "meta": {
        "source": "auto:wlan0",
        "iface": "wlan0",
        "ssid": "ExampleNet",
        "path": "/tmp/example-capture.pcap",
        "pcap": "/tmp/example-capture.pcap",
        "duration": 60,
    },
    "devices": [
        {
            "ip": "192.0.2.10",
            "mac": "02:00:00:00:00:0a",
            "hostname": "example-plug",
            "vendor": "Example Vendor",
            "findings": ["Uses 8.8.8.8 instead of your router DNS"],
            "iface": "wlan0",
            "ssid": "ExampleNet",
            "pcap": "/tmp/example-capture.pcap",
            "meta": {
                "source": "hotspot:wlan0",
                "interface": "wlan0",
                "ssid": "ExampleNet",
                "path": "/tmp/example-capture.pcap",
                "duration": 30,
            },
            "known_issue_hints": [
                {"source": "port-scan", "title": "Example issue", "cve": "CVE-2020-0000"},
                {"source": "upnp", "title": "Example UPnP issue"},
            ],
            "destinations": [
                {"ip": "8.8.8.8", "domains": ["device.example"], "path": "/v1/status"},
                {"ip": "192.0.2.20", "domains": []},
            ],
        }
    ],
}

# Values that must not appear in a redacted copy of NESTED.
_NESTED_SECRETS = (
    "192.0.2.10",
    "192.0.2.20",
    "02:00:00:00:00:0a",
    "example-plug",
    "wlan0",
    "ExampleNet",
    "/tmp/example-capture.pcap",
    "auto:wlan0",
    "hotspot:wlan0",
)


def test_redact_drops_nested_capture_metadata():
    original = json.loads(json.dumps(NESTED))
    out = redact_audit(NESTED)
    assert NESTED == original  # input is not modified
    text = json.dumps(out)
    for secret in _NESTED_SECRETS:
        assert secret not in text
    assert "8.8.8.8" in text and "device.example" in text
    assert "Uses 8.8.8.8 instead of your router DNS" in text
    assert out["meta"]["duration"] == 60 and out["meta"]["redacted"] is True
    assert "source" not in out["meta"] and "ssid" not in out["meta"]
    device = out["devices"][0]
    assert device["ip"] == "lan-1" and device["hostname"] == "host-1"
    assert "iface" not in device and "ssid" not in device and "pcap" not in device
    assert device["meta"]["duration"] == 30
    assert "source" not in device["meta"] and "path" not in device["meta"]
    assert "interface" not in device["meta"] and "ssid" not in device["meta"]
    hints = device["known_issue_hints"]
    assert hints[0]["source"] == "port-scan" and hints[1]["source"] == "upnp"
    dest = device["destinations"][0]
    assert dest["path"] == "/v1/status"
    assert dest["ip"] == "8.8.8.8"


def test_redact_nested_meta_on_plain_device_list():
    devices = json.loads(json.dumps(NESTED["devices"]))
    out = redact_audit(devices)
    assert isinstance(out, list)
    text = json.dumps(out)
    for secret in ("wlan0", "ExampleNet", "/tmp/example-capture.pcap", "hotspot:wlan0", "192.0.2.10"):
        assert secret not in text
    assert out[0]["known_issue_hints"][0]["source"] == "port-scan"
    assert out[0]["destinations"][0]["path"] == "/v1/status"
    assert "source" not in out[0]["meta"]


def test_report_redact_hides_nested_capture_metadata(tmp_path, capsys):
    src = tmp_path / "audit.json"
    src.write_text(json.dumps(NESTED), encoding="utf-8")
    assert main(["report", "--redact", str(src)]) == 0
    html = (tmp_path / "audit.redacted.html").read_text(encoding="utf-8")
    for secret in _NESTED_SECRETS:
        assert secret not in html
    assert "8.8.8.8" in html and "device.example" in html
    assert "source:" not in html
    assert "ExampleNet" not in html
