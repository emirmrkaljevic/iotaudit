"""Home Assistant summary, with fixture data only."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from iotaudit.cli import main
from iotaudit.diff import diff_audits, load_audit
from iotaudit.ha import ha_summary

FIX = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 1, 1, 12, 0, 0)


def test_first_run_has_no_change_flag():
    new = load_audit(FIX / "diff_new.json")
    out = ha_summary(new.devices, None, now=NOW)
    assert out["generated"] == "2026-01-01T12:00:00"
    assert out["devices"] == len(new.devices)
    assert out["changed"] == 0
    for row in out["device_list"]:
        assert row["changed"] is None
        assert row["status"] == "first_run"
        assert set(row) == {"name", "ip", "grade", "findings", "changed", "status"}


def test_compare_sets_changed_and_worst_grade():
    old = load_audit(FIX / "diff_old.json")
    new = load_audit(FIX / "diff_new.json")
    diff = diff_audits(old, new)
    out = ha_summary(new.devices, diff, now=NOW)
    assert out["security_relevant"] == diff["security_relevant"]
    assert out["changed"] >= 1
    assert any(row["changed"] for row in out["device_list"])
    grades = [d.get("grade") for d in new.devices if d.get("grade")]
    assert out["worst_grade"] == max(grades, key="ABCDEF".index)
    assert out["findings"] == sum(len(d.get("findings") or []) for d in new.devices)


def test_export_cli_writes_file(tmp_path, capsys):
    dest = tmp_path / "ha" / "iotaudit.json"
    code = main(["export", str(FIX / "diff_new.json"),
                 "--compare", str(FIX / "diff_old.json"), "--out", str(dest)])
    assert code == 0
    data = json.loads(dest.read_text(encoding="utf-8"))
    assert data["device_list"]
    assert "\u2014" not in dest.read_text(encoding="utf-8")


def test_export_cli_stdout(capsys):
    assert main(["export", str(FIX / "diff_new.json")]) == 0
    assert json.loads(capsys.readouterr().out)["devices"] >= 1


def test_export_cli_bad_file(tmp_path, capsys):
    assert main(["export", str(tmp_path / "missing.json")]) == 1
