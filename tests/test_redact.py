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
