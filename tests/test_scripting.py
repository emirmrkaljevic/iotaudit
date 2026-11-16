"""--summary-json and --fail-under, using fixture and placeholder data only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from iotaudit.cli import build_parser, main
from iotaudit.ha import (
    fail_under_exit,
    grade_worse_than,
    scripting_exit,
    worst_grade,
)

FIX = Path(__file__).parent / "fixtures"


def test_grade_worse_than_orders_a_to_f():
    assert worst_grade([{"grade": "A"}, {"grade": "C"}, {"grade": "B"}]) == "C"
    assert worst_grade([{"grade": "F"}, {"grade": "A"}]) == "F"
    assert worst_grade([]) is None
    assert worst_grade([{"grade": "X"}]) is None
    assert grade_worse_than("C", "B") is True
    assert grade_worse_than("B", "B") is False
    assert grade_worse_than("A", "B") is False
    assert grade_worse_than("F", "E") is True
    assert grade_worse_than(None, "A") is False
    with pytest.raises(ValueError, match="unknown grade"):
        grade_worse_than("C", "G")


def test_fail_under_exit_prints_a_clear_error(capsys):
    devices = [{"grade": "D"}, {"grade": "A"}]
    assert fail_under_exit(devices, "C") == 1
    err = capsys.readouterr().err
    assert "worst grade D is worse than --fail-under C" in err
    assert fail_under_exit(devices, "D") == 0
    assert capsys.readouterr().err == ""
    assert fail_under_exit(devices, None) == 0


def test_scripting_exit_prints_json_on_stdout_and_keeps_exit_2(capsys):
    args = argparse.Namespace(summary_json=True, fail_under="A")
    devices = [{"grade": "C", "ip": "192.0.2.50", "findings": [], "looks_like": "camera"}]
    assert scripting_exit(args, devices, None, 2) == 2
    out, err = capsys.readouterr()
    data = json.loads(out)
    assert data["worst_grade"] == "C"
    assert data["devices"] == 1
    assert "192.0.2.50" in json.dumps(data)
    assert "worse than --fail-under A" in err


def test_export_fail_under_uses_the_worst_grade(capsys):
    audit = str(FIX / "diff_new.json")
    assert main(["export", audit, "--fail-under", "C"]) == 1
    out, err = capsys.readouterr()
    data = json.loads(out)
    assert data["worst_grade"] == "D"
    assert "worst grade D is worse than --fail-under C" in err
    assert main(["export", audit, "--fail-under", "D"]) == 0
    assert "worse than" not in capsys.readouterr().err


def test_parser_accepts_scripting_flags():
    parser = build_parser()
    auto = parser.parse_args(["auto", "--summary-json", "--fail-under", "B", "--i-own-this-network"])
    assert auto.summary_json is True
    assert auto.fail_under == "B"
    analyze = parser.parse_args(
        ["analyze", "capture.pcap", "--no-scan", "--summary-json", "--fail-under", "C"]
    )
    assert analyze.summary_json is True
    assert analyze.fail_under == "C"
    assert analyze.scan is False
    export = parser.parse_args(["export", "audit.json", "--fail-under", "A"])
    assert export.fail_under == "A"
    assert not hasattr(export, "summary_json")
    with pytest.raises(SystemExit):
        parser.parse_args(["analyze", "capture.pcap", "--fail-under", "G"])


def _placeholder_pcap(path: Path) -> None:
    dev = "192.0.2.50"
    ether = Ether(src="02:00:00:00:00:50", dst="02:00:00:00:00:01")
    wrpcap(
        str(path),
        [
            ether / IP(src=dev, dst="192.0.2.1") / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com")),
            ether / IP(src=dev, dst="8.8.8.8") / TCP(dport=443, flags="S"),
        ],
    )


def test_analyze_summary_json_and_fail_under(tmp_path, capsys):
    pcap = tmp_path / "capture.pcap"
    _placeholder_pcap(pcap)
    html = tmp_path / "report.html"
    assert main([
        "analyze",
        str(pcap),
        "--device",
        "192.0.2.50",
        "--no-scan",
        "--out",
        str(html),
        "--summary-json",
        "--fail-under",
        "A",
    ]) == 1
    out, err = capsys.readouterr()
    data = json.loads(out)
    assert data["devices"] == 1
    assert data["device_list"][0]["ip"] == "192.0.2.50"
    assert data["worst_grade"] in "ABCDEF"
    assert "Report written to" in err
    assert "192.0.2.50" in err
    assert "Report written to" not in out
    assert html.is_file() and html.with_suffix(".json").is_file()
    assert f"worst grade {data['worst_grade']} is worse than --fail-under A" in err

    # The same capture passes when the threshold is the worst grade itself.
    assert main([
        "analyze",
        str(pcap),
        "--device",
        "192.0.2.50",
        "--no-scan",
        "--out",
        str(tmp_path / "report2.html"),
        "--summary-json",
        "--fail-under",
        data["worst_grade"],
    ]) == 0
    out2, err2 = capsys.readouterr()
    assert json.loads(out2)["worst_grade"] == data["worst_grade"]
    assert "worse than" not in err2
    for dash in ("\u2014", "\u2013"):
        assert dash not in out and dash not in err
        assert dash not in out2 and dash not in err2
