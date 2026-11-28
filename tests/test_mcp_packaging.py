"""The MCP server must start, or fail with clear install help, however it was installed."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import iotaudit
from iotaudit import mcp_server

ROOT = Path(__file__).resolve().parent.parent


def _hide_mcp(monkeypatch):
    for name in list(sys.modules):
        if name == "mcp" or name.startswith("mcp."):
            monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "mcp", None)


def test_missing_mcp_gives_install_help(monkeypatch, capsys):
    _hide_mcp(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        mcp_server.main()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert 'pip install "iotaudit[mcp]"' in err
    assert 'uvx --from "iotaudit[mcp]" iotaudit-mcp' in err
    assert "Traceback" not in err


def test_missing_mcp_via_cli_subcommand(monkeypatch, capsys):
    from iotaudit import cli

    _hide_mcp(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        cli.main(["mcp"])
    assert exc.value.code == 2
    assert "iotaudit[mcp]" in capsys.readouterr().err


def test_create_server_raises_import_error_without_mcp(monkeypatch):
    _hide_mcp(monkeypatch)
    with pytest.raises(ImportError):
        mcp_server.create_server()


def test_missing_mcp_in_a_fresh_interpreter():
    code = (
        "import sys; sys.modules['mcp'] = None\n"
        "from iotaudit.mcp_server import main\n"
        "main()\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2
    assert "iotaudit[mcp]" in proc.stderr
    assert "Traceback" not in proc.stderr


def _project():
    tomllib = pytest.importorskip("tomllib")  # Python 3.11+
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def test_registry_entry_installs_the_mcp_dependency():
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    (pkg,) = server["packages"]
    assert pkg["runtimeHint"] == "uvx"
    with_args = [a for a in pkg.get("runtimeArguments", []) if a.get("name") == "--with"]
    assert with_args and with_args[0]["value"].startswith("mcp")
    extra = _project()["optional-dependencies"]["mcp"]
    assert with_args[0]["value"] in extra


def test_versions_and_homepage_are_consistent():
    project = _project()
    version = project["version"]
    assert iotaudit.__version__ == version
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert server["version"] == version
    assert server["packages"][0]["version"] == version
    gemini = json.loads((ROOT / "gemini-extension.json").read_text(encoding="utf-8"))
    assert gemini["version"] == version
    urls = project["urls"]
    assert server["websiteUrl"] == urls["Homepage"]
    assert urls["Repository"] == server["repository"]["url"]
