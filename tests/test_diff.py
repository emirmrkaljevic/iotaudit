"""Change detection between two saved audits. Fixtures use documentation addresses only."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import pytest

from iotaudit.diff import audit_from_json, diff_audits, diff_results, format_diff

FIXTURES = Path(__file__).parent / "fixtures"
OLD = FIXTURES / "diff_old.json"
NEW = FIXTURES / "diff_new.json"
_DASHES = ("\u2014", "\u2013")


def _device(**overrides) -> dict:
    base = {
        "ip": "192.168.1.10",
        "mac": "02:00:00:00:00:01",
        "vendor": "Example Vendor",
        "grade": "B",
        "verdict": "B: encrypted cloud traffic (US).",
        "destinations": [],
        "destination_countries": [],
        "dns_queries": [],
        "open_ports": [],
        "findings": [],
    }
    base.update(overrides)
    return base


def _dest(ip, domains, *, country="US", ports=(443,), encrypted=True, kind="tls"):
    return {
        "ip": ip,
        "domains": list(domains),
        "country": country,
        "ports": list(ports),
        "encrypted": encrypted,
        "encryption_kind": kind,
    }


def _upnp(external=554, internal=554, protocol="TCP", description="rtsp", remote=""):
    return {
        "category": "upnp",
        "severity": "high",
        "title": f"Port {external}/{protocol} forwarded to this device via UPnP",
        "detail": f"The router forwards public port {external} to 192.168.1.10:{internal}.",
        "confidence": "certain",
        "evidence": {
            "external_port": external,
            "protocol": protocol,
            "internal_port": internal,
            "description": description,
            "remote_host": remote,
        },
    }


def _run(old, new) -> dict:
    return diff_audits(audit_from_json(old), audit_from_json(new), "old.json", "new.json")


def _one(result: dict) -> dict:
    assert len(result["devices"]) == 1
    return result["devices"][0]


def test_fixture_matches_by_mac_then_ip_and_flags_what_appeared():
    result = diff_results(str(OLD), str(NEW))
    assert result["security_relevant"] is True
    assert result["exit_code"] == 1
    summary = result["summary"]
    assert summary == {
        "devices_old": 3,
        "devices_new": 3,
        "matched": 2,
        "unchanged": 1,
        "changed": 1,
        "new_devices": 1,
        "gone_devices": 1,
    }
    changed, unchanged, new, gone = result["devices"]
    assert changed["status"] == "changed" and changed["matched_by"] == "mac"
    assert changed["old_ip"] == "192.168.1.10" and changed["new_ip"] == "192.168.1.11"
    assert changed["mac"] == "02:00:00:00:00:01"
    assert changed["grade"]["old"] == "B" and changed["grade"]["new"] == "D"
    assert changed["grade"]["worsened"] is True
    assert changed["verdict"]["changed"] is True
    assert changed["new_domains"] == ["logs.example"]
    assert changed["gone_domains"] == ["files.example"]
    assert changed["new_ips"] == ["198.51.100.50"]
    assert changed["gone_ips"] == ["203.0.113.20"]
    assert changed["new_countries"] == ["DE"]
    assert changed["gone_countries"] == []
    assert changed["new_ports"] == [{"port": 23, "proto": "tcp", "service": "telnet", "risk": "high"}]
    assert changed["closed_ports"] == []
    assert changed["new_unencrypted"] == [{
        "ip": "198.51.100.50",
        "domains": ["logs.example"],
        "ports": [80],
        "encryption_kind": "plaintext",
    }]
    assert changed["new_upnp"] == [{
        "protocol": "TCP",
        "external_port": 554,
        "internal_port": 554,
        "remote_host": None,
        "description": "rtsp",
    }]
    assert changed["security_relevant"] is True
    assert "grade_worse" in changed["reasons"]
    assert "new_upnp" in changed["reasons"]

    assert unchanged["status"] == "unchanged" and unchanged["matched_by"] == "ip"
    assert unchanged["ip"] == "192.168.1.30" and unchanged["security_relevant"] is False

    assert new["status"] == "new" and new["ip"] == "192.168.1.40"
    assert new["reasons"][0] == "new_device"
    assert new["new_domains"] == ["setup.example"]
    assert new["new_ips"] == ["192.0.2.10"]
    assert new["security_relevant"] is True

    assert gone["status"] == "gone" and gone["ip"] == "192.168.1.20"
    assert gone["grade"]["old"] == "A" and gone["security_relevant"] is False
    assert gone["reasons"] == []

    text = format_diff(result)
    assert "Address changed from 192.168.1.10 to 192.168.1.11." in text
    assert "Grade changed from B to D (worse)." in text
    assert "New destination domain: logs.example." in text
    assert "Destination domain gone: files.example." in text
    assert "New country: DE." in text
    assert "New open port: 23/tcp (telnet, high)." in text
    assert "Newly unencrypted traffic: 198.51.100.50 (logs.example; port 80)." in text
    assert "New UPnP forward: TCP public port 554 to device port 554, description rtsp." in text
    assert "192.168.1.40 (02:00:00:00:00:04, Example Vendor) is new." in text
    assert "192.168.1.20 (02:00:00:00:00:02, Example Vendor) is gone. Last grade A." in text
    assert "Matched 2 devices. 1 unchanged, 1 changed, 1 new, 1 gone." in text
    assert "Security-relevant changes appeared on 2 devices." in text
    for dash in _DASHES:
        assert dash not in text


def test_identical_audits_are_quiet():
    result = diff_results(str(OLD), str(OLD))
    assert result["security_relevant"] is False
    assert result["exit_code"] == 0
    assert result["summary"]["unchanged"] == 3
    assert result["reasons"] == []
    assert "No security-relevant changes appeared." in format_diff(result)


def test_mac_match_ignores_separator_and_follows_a_new_address():
    old = [_device(mac="02-00-00-00-00-01", ip="192.168.1.10")]
    new = [_device(mac="02:00:00:00:00:01", ip="192.168.1.11")]
    device = _one(_run(old, new))
    assert device["matched_by"] == "mac"
    assert device["mac"] == "02:00:00:00:00:01"
    assert device["security_relevant"] is False
    assert "Address changed from 192.168.1.10 to 192.168.1.11." in format_diff(_run(old, new))


def test_different_mac_at_the_same_ip_is_a_new_device():
    old = [_device(mac="02:00:00:00:00:01", ip="192.168.1.10")]
    new = [_device(mac="02:00:00:00:00:09", ip="192.168.1.10", grade="C")]
    result = _run(old, new)
    assert [device["status"] for device in result["devices"]] == ["new", "gone"]
    assert result["security_relevant"] is True
    assert result["reasons"] == ["new_device"]


def test_missing_mac_falls_back_to_ip():
    old = [_device(mac="02:00:00:00:00:01")]
    new = [_device(mac=None, grade="A", verdict="A: encrypted cloud traffic (US).")]
    device = _one(_run(old, new))
    assert device["matched_by"] == "ip"
    assert device["grade"]["improved"] is True
    assert device["security_relevant"] is False
    text = format_diff(_run(old, new))
    assert "matched by IP." in text
    assert "Grade changed from B to A (better)." in text


def test_only_departures_do_not_exit_1():
    old = [_device(
        destinations=[_dest("203.0.113.10", ["api.example"]), _dest("203.0.113.20", ["files.example"])],
        dns_queries=["api.example", "files.example"],
        open_ports=[{"port": 23, "proto": "tcp", "service": "telnet", "risk": "high"}],
        findings=[_upnp()],
        destination_countries=[{"country": "US"}],
    )]
    new = [_device(
        destinations=[_dest("203.0.113.10", ["api.example"])],
        dns_queries=["api.example"],
        open_ports=[],
        findings=[],
        destination_countries=[{"country": "US"}],
    )]
    result = _run(old, new)
    device = _one(result)
    assert device["gone_domains"] == ["files.example"]
    assert device["gone_ips"] == ["203.0.113.20"]
    assert device["closed_ports"][0]["port"] == 23
    assert device["closed_upnp"][0]["external_port"] == 554
    assert device["new_domains"] == [] and device["new_ips"] == []
    assert result["security_relevant"] is False
    text = format_diff(result)
    assert "UPnP forward closed:" in text
    assert "No security-relevant changes appeared." in text


def test_verdict_change_alone_is_reported_and_not_security_relevant():
    old = [_device(verdict="B: encrypted cloud traffic (US).")]
    new = [_device(verdict="B: encrypted cloud traffic (US). One destination.")]
    result = _run(old, new)
    assert result["security_relevant"] is False
    assert _one(result)["verdict"]["changed"] is True
    text = format_diff(result)
    assert "Verdict changed." in text
    assert "Earlier: B: encrypted cloud traffic (US)." in text
    assert "Now: B: encrypted cloud traffic (US). One destination." in text


def test_whitespace_does_not_count_as_a_verdict_change():
    old = [_device(verdict="  B: encrypted cloud traffic (US).  ")]
    new = [_device(verdict="B: encrypted cloud traffic (US).")]
    assert _one(_run(old, new))["status"] == "unchanged"


def test_plaintext_flip_is_newly_unencrypted_and_an_existing_one_is_not():
    plain = _dest("203.0.113.10", ["api.example"], ports=(80,), encrypted=False, kind="plaintext")
    tls = _dest("203.0.113.10", ["api.example"])
    flipped = _one(_run([_device(destinations=[tls])], [_device(destinations=[plain])]))
    assert flipped["new_ips"] == []
    assert flipped["new_unencrypted"][0]["ip"] == "203.0.113.10"
    assert "new_unencrypted" in flipped["reasons"]

    legacy = {"ip": "203.0.113.10", "domains": ["api.example"], "encrypted": False, "ports": [80]}
    same = _one(_run(
        [_device(destinations=[legacy])],
        [_device(destinations=[dict(legacy)])],
    ))
    assert same["new_unencrypted"] == []
    assert same["security_relevant"] is False


def test_new_domain_and_dns_name_and_country_without_a_summary_key():
    old = _device(destinations=[_dest("203.0.113.10", ["api.example"])], dns_queries=["api.example"])
    old.pop("destination_countries")
    new = _device(
        destinations=[
            _dest("203.0.113.10", ["api.example"]),
            _dest("198.51.100.8", ["logs.example"], country="de"),
        ],
        dns_queries=["api.example", "logs.example", "extra.example"],
    )
    new.pop("destination_countries")
    device = _one(_run([old], [new]))
    assert device["new_domains"] == ["extra.example", "logs.example"]
    assert device["new_ips"] == ["198.51.100.8"]
    assert device["new_countries"] == ["DE"]
    assert device["security_relevant"] is True


def test_ipv6_case_and_lan_peers_and_remote_ports_are_not_false_alarms():
    old = _device(destinations=[_dest("2001:DB8::10", ["api.example"], ports=(443,))])
    new = _device(
        destinations=[_dest("2001:db8::10", ["api.example"], ports=(8443,))],
        lan_peers=[{"ip": "192.168.1.55", "domains": ["phone.example"], "ports": [52265]}],
    )
    device = _one(_run([old], [new]))
    assert device["status"] == "unchanged"
    assert device["new_ips"] == [] and device["new_domains"] == []


def test_open_port_proto_case_and_bare_int_match():
    old = [_device(open_ports=[{"port": 80, "proto": "TCP"}, 23])]
    new = [_device(open_ports=[{"port": 80, "proto": "tcp"}, {"port": 23, "proto": "tcp"}])]
    assert _one(_run(old, new))["status"] == "unchanged"


def test_upnp_from_title_only_and_from_top_level_mappings():
    title_only = {
        "category": "upnp",
        "title": "Port 8080/tcp forwarded to this device via UPnP",
        "detail": "The router forwards public port 8080 to 192.168.1.10:80.",
    }
    device = _one(_run([_device()], [_device(findings=[title_only])]))
    assert device["new_upnp"] == [{
        "protocol": "TCP",
        "external_port": 8080,
        "internal_port": 80,
        "remote_host": None,
        "description": None,
    }]

    mapping = {
        "external_port": 554,
        "protocol": "tcp",
        "internal_client": "192.168.1.10",
        "internal_port": "554",
        "description": "rtsp",
        "enabled": True,
        "remote_host": "",
    }
    disabled = dict(mapping, external_port=23, enabled=False)
    other = dict(mapping, internal_client="192.168.1.99", external_port=22)
    wrapped_old = {"devices": [_device()], "upnp": {"mappings": []}}
    wrapped_new = {"devices": [_device()], "upnp": {"mappings": [mapping, disabled, other]}}
    found = _one(_run(wrapped_old, wrapped_new))
    assert found["new_upnp"][0]["protocol"] == "TCP"
    assert found["new_upnp"][0]["external_port"] == 554
    assert len(found["new_upnp"]) == 1

    again = _one(_run(wrapped_new, wrapped_new))
    assert again["new_upnp"] == [] and again["status"] == "unchanged"


def test_single_device_object_and_bad_shapes():
    audit = audit_from_json(_device())
    assert len(audit.devices) == 1
    with pytest.raises(ValueError, match="devices list"):
        audit_from_json({"meta": {}})
    with pytest.raises(ValueError, match="device 1"):
        audit_from_json(["nope"])


def test_cli_diff_exit_codes_and_json(capsys, tmp_path):
    from iotaudit.cli import main

    assert main(["diff", str(OLD), str(NEW)]) == 1
    text = capsys.readouterr().out
    assert "Security-relevant changes appeared on 2 devices." in text
    for dash in _DASHES:
        assert dash not in text

    assert main(["diff", str(OLD), str(NEW), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["security_relevant"] is True and payload["exit_code"] == 1
    assert payload["summary"]["changed"] == 1

    assert main(["diff", str(OLD), str(OLD)]) == 0
    assert "No security-relevant changes appeared." in capsys.readouterr().out

    assert main(["diff", str(OLD), str(tmp_path / "missing.json")]) == 2
    assert "not a file" in capsys.readouterr().err

    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert main(["diff", str(OLD), str(bad)]) == 2
    assert "not JSON" in capsys.readouterr().err


def test_cli_exit_0_when_a_destination_only_left(capsys, tmp_path):
    from iotaudit.cli import main

    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps([_device(destinations=[_dest("203.0.113.5", ["api.example"])])]), encoding="utf-8")
    new.write_text(json.dumps([_device()]), encoding="utf-8")
    assert main(["diff", str(old), str(new)]) == 0
    text = capsys.readouterr().out
    assert "Destination IP gone: 203.0.113.5." in text
    assert "No security-relevant changes appeared." in text


def test_compare_flag_is_on_capture_and_analyze():
    from iotaudit.cli import build_parser

    parser = build_parser()
    analyze = parser.parse_args(["analyze", "capture.pcap", "--compare", "prev.json"])
    assert analyze.compare == "prev.json" and analyze.func.__name__ == "cmd_analyze"
    capture = parser.parse_args(["capture", "--compare", "prev.json"])
    assert capture.compare == "prev.json" and capture.func.__name__ == "cmd_capture"
    assert parser.parse_args(["analyze", "capture.pcap"]).compare is None
    assert parser.parse_args(["diff", "a.json", "b.json"]).json is False


def test_finish_prints_the_diff_after_the_report(tmp_path, capsys):
    from iotaudit.capture import Collector
    from iotaudit.cli import _finish

    prev = tmp_path / "prev.json"
    prev.write_text(json.dumps([_device(ip="192.168.1.20", mac="02:00:00:00:00:02")]), encoding="utf-8")
    out = tmp_path / "out.html"
    args = argparse.Namespace(
        scan=False, device=[], upnp=False, geoip=None, profiles=None,
        json=str(tmp_path / "now.json"), out=str(out), pdf=False, compare=str(prev),
    )
    assert _finish(Collector([]), args, {"source": "sample"}) == 0
    text = capsys.readouterr().out
    assert "Report written to" in text
    assert "is gone." in text
    assert text.index("Report written to") < text.index("is gone.")
    assert out.is_file() and (tmp_path / "now.json").is_file()


def test_finish_compare_exits_1_when_a_device_appears(monkeypatch, tmp_path, capsys):
    from iotaudit.capture import Collector
    from iotaudit.cli import _finish

    prev = tmp_path / "prev.json"
    prev.write_text("[]", encoding="utf-8")
    appeared = _device(ip="192.168.1.40", mac="02:00:00:00:00:04", grade="C", destinations=[])
    monkeypatch.setattr("iotaudit.cli.build_devices", lambda *args, **kwargs: [appeared])
    monkeypatch.setattr("iotaudit.cli.to_dict", lambda device: device)
    out = tmp_path / "out.html"
    args = argparse.Namespace(
        scan=False, device=[], upnp=False, geoip=None, profiles=None,
        json=str(tmp_path / "now.json"), out=str(out), pdf=False, compare=str(prev),
    )
    assert _finish(Collector([]), args, {"source": "sample"}) == 1
    text = capsys.readouterr().out
    assert text.index("Report written to") < text.index("is new.")
    assert "Security-relevant changes appeared on 1 device." in text


def test_finish_still_writes_the_report_when_compare_file_is_missing(tmp_path, capsys):
    from iotaudit.capture import Collector
    from iotaudit.cli import _finish

    out = tmp_path / "out.html"
    args = argparse.Namespace(
        scan=False, device=[], upnp=False, geoip=None, profiles=None,
        json=None, out=str(out), pdf=False, compare=str(tmp_path / "missing.json"),
    )
    assert _finish(Collector([]), args, {"source": "sample"}) == 2
    captured = capsys.readouterr()
    assert "Report written to" in captured.out
    assert "not a file" in captured.err
    assert out.is_file() and out.with_suffix(".json").is_file()


def test_readme_and_changelog_document_diff():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "iotaudit diff" in readme and "--compare" in readme and "cron" in readme.lower()
    assert "0.1.11" in readme
    quick = readme[readme.index("## Quick start"):readme.index("### macOS")]
    first_command = quick.split("```bash", 1)[1].split("```", 1)[0]
    assert first_command.strip() == "sudo iotaudit auto"
    assert "## [0.1.11]" in changelog and "iotaudit auto" in changelog
    assert "## [0.1.9]" in changelog and "iotaudit diff" in changelog
    assert "## [0.1.10]" in changelog and "known_issue_hints" in changelog
    version = (root / "src/iotaudit/__init__.py").read_text(encoding="utf-8")
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    server = (root / "server.json").read_text(encoding="utf-8")
    assert '__version__ = "0.1.11"' in version
    assert 'version = "0.1.11"' in project
    assert server.count('"version": "0.1.11"') == 2
    roadmap = (root / "ROADMAP.md").read_text(encoding="utf-8")
    auto_src = (root / "src/iotaudit/auto.py").read_text(encoding="utf-8")
    for dash in _DASHES:
        assert dash not in readme
        assert dash not in changelog
        assert dash not in roadmap
        assert dash not in auto_src
        assert dash not in (root / "src/iotaudit/diff.py").read_text(encoding="utf-8")


def test_mcp_diff_results_matches_the_library():
    from iotaudit.mcp_server import create_server

    server = create_server()
    tools = asyncio.run(server.list_tools())
    tool = next(item for item in tools if item.name == "diff_results")
    schema = getattr(tool, "input_schema", None) or tool.inputSchema
    assert "old_path" in schema["properties"] and "new_path" in schema["properties"]

    called = asyncio.run(server.call_tool("diff_results", {"old_path": str(OLD), "new_path": str(NEW)}))
    body = json.loads(called.content[0].text)
    direct = diff_results(str(OLD), str(NEW))
    assert body == direct
    assert body["security_relevant"] is True and body["exit_code"] == 1
