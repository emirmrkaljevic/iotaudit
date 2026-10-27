"""iotaudit auto, with mocks and documentation addresses only."""

from __future__ import annotations

import argparse
import io
from datetime import datetime

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from iotaudit.auto import (
    capture_passive,
    format_missing_tools,
    host_bpf,
    install_command,
    latest_audit,
    pcap_packet_count,
    run_auto,
    summary_line,
)
from iotaudit.cli import build_parser

_DASHES = ("\u2014", "\u2013")
CAMERA = "192.168.1.50"
QUIET = "192.168.1.51"
ROUTER = "192.168.1.1"
THIS_HOST = "192.168.1.20"
DEST = "192.0.2.10"


def _no_dash(text: str) -> None:
    for dash in _DASHES:
        assert dash not in text


def _args(tmp_path, **overrides):
    ns = argparse.Namespace(
        i_own_this_network=True,
        iface="auto",
        duration=60,
        out_dir=str(tmp_path),
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def _devices():
    return [
        {"ip": ROUTER, "mac": "02:00:00:00:00:01", "role": "router", "looks_like": "Router / gateway"},
        {"ip": THIS_HOST, "mac": "02:00:00:00:00:14", "role": "this-host", "looks_like": "This Mac / PC"},
        {"ip": CAMERA, "mac": "02:00:00:00:00:32", "role": None, "looks_like": "Example camera (port 554)"},
        {"ip": QUIET, "mac": "02:00:00:00:00:33", "role": None, "looks_like": "Example plug"},
    ]


def _packet():
    return (
        Ether(src="02:00:00:00:00:32", dst="02:00:00:00:00:01")
        / IP(src=CAMERA, dst=DEST)
        / TCP(sport=41000, dport=443, flags="S")
    )


class _Proc:
    def __init__(self, code=None, stderr=b""):
        self._code = code
        self.stderr = io.BytesIO(stderr)
        self.returncode = code
        self.terminated = False

    def poll(self):
        return self._code

    def terminate(self):
        self.terminated = True
        self._code = 0
        self.returncode = 0

    def kill(self):
        self._code = -9
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
            self._code = 0
        return self.returncode


def test_install_command_is_exact_for_the_os():
    assert install_command(["nmap"], system="Darwin") == "brew install nmap"
    assert install_command(["nmap", "tcpdump"], system="Darwin") == "brew install nmap tcpdump"

    def apt(name):
        return "/usr/bin/apt" if name in ("apt", "dnf") else None

    assert install_command(["tcpdump"], system="Linux", which=apt) == "sudo apt install tcpdump"
    assert install_command(["nmap"], system="Linux", which=lambda name: "/usr/bin/dnf" if name == "dnf" else None) == (
        "sudo dnf install nmap"
    )
    pacman = install_command(
        ["nmap", "tcpdump"], system="Linux", which=lambda name: "/usr/bin/pacman" if name == "pacman" else None
    )
    assert pacman == "sudo pacman -S --needed nmap tcpdump"
    zypper = install_command(["nmap"], system="Linux", which=lambda name: "/bin/zypper" if name == "zypper" else None)
    assert zypper == "sudo zypper install nmap"
    fallback = install_command(["nmap", "tcpdump"], system="Linux", which=lambda _name: None)
    assert fallback == "sudo apt install nmap tcpdump"


def test_missing_tool_message_names_the_install_command():
    both = format_missing_tools(["nmap", "tcpdump"], system="Darwin", which=lambda _name: None)
    one = format_missing_tools(
        ["nmap"], system="Linux", which=lambda name: "/usr/bin/apt-get" if name == "apt-get" else None
    )
    assert "brew install nmap tcpdump" in both
    assert 'sudo env PATH="$PATH" iotaudit auto' in both
    assert "sudo apt install nmap" in one
    assert "brew" not in one
    _no_dash(both)
    _no_dash(one)


def test_host_filter_and_previous_audit(tmp_path):
    assert host_bpf([CAMERA, QUIET]) == f"host {CAMERA} or host {QUIET}"
    assert host_bpf(["not-an-ip"]) is None
    assert host_bpf([f"192.168.1.{i}" for i in range(1, 66)]) is None
    (tmp_path / "090000.json").write_text("[]", encoding="utf-8")
    (tmp_path / "120000.json").write_text("[]", encoding="utf-8")
    (tmp_path / "120000-2.json").write_text("[]", encoding="utf-8")
    assert latest_audit(tmp_path).name == "120000-2.json"
    assert latest_audit(tmp_path / "empty") is None


def test_pcap_packet_count_on_synthetic_capture(tmp_path):
    path = tmp_path / "t.pcap"
    wrpcap(str(path), [_packet(), _packet()])
    assert pcap_packet_count(path) == 2
    assert pcap_packet_count(tmp_path / "missing.pcap") == 0
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    assert pcap_packet_count(empty) == 0
    unknown = tmp_path / "other.pcap"
    unknown.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
    assert pcap_packet_count(unknown) is None


def test_passive_capture_prints_a_progress_line(tmp_path):
    dest = tmp_path / "cap.pcap"
    clock = {"now": 0.0}

    def popen(cmd, stdout=None, stderr=None):
        assert cmd[:3] == ["tcpdump", "-i", "eth0"]
        assert f"host {CAMERA}" in cmd[-1]
        wrpcap(str(dest), [_packet()])
        return _Proc()

    def sleep(seconds):
        clock["now"] += seconds

    lines = []
    elapsed = capture_passive(
        "eth0",
        30,
        dest,
        bpf=host_bpf([CAMERA]),
        progress_every=10,
        popen=popen,
        sleep=sleep,
        clock=lambda: clock["now"],
        echo=lines.append,
    )
    assert elapsed == 30
    assert lines[0] == "Passive capture on eth0: 10s of 30s, 1 packet"
    assert lines[-1] == "Passive capture on eth0 finished: 30s, 1 packet."
    assert any("20s of 30s" in line for line in lines)
    for line in lines:
        _no_dash(line)


def test_tcpdump_permission_error_is_friendly(tmp_path):
    proc = _Proc(code=1, stderr=b"tcpdump: eth0: You don't have permission to capture")
    with pytest.raises(RuntimeError) as exc:
        capture_passive("eth0", 5, tmp_path / "cap.pcap", popen=lambda *args, **kwargs: proc)
    message = str(exc.value)
    assert "sudo iotaudit auto" in message
    assert "permission denied" in message
    _no_dash(message)


def test_known_device_is_reported_without_traffic():
    from iotaudit.analyze import build_devices, to_dict
    from iotaudit.capture import Collector
    from iotaudit.report import render_html

    scans = {
        QUIET: [{
            "port": 23,
            "proto": "tcp",
            "service": "telnet",
            "risk": "high",
            "why": "Telnet exposes an unencrypted login shell.",
        }]
    }
    known = [{"ip": QUIET, "mac": "02:00:00:00:00:33", "looks_like": "Example plug"}]
    device = to_dict(build_devices(Collector([QUIET]), scans=scans, known_devices=known)[0])
    assert device["ip"] == QUIET
    assert device["looks_like"] == "Example plug"
    assert device["open_ports"][0]["port"] == 23
    assert "Telnet" in device["verdict"]
    assert device["grade"] != "A"
    line = summary_line(device)
    assert QUIET in line and "Example plug" in line and "Telnet" in line
    html = render_html([device], {"source": "auto:eth0", "duration": 60})
    assert "Identified as Example plug." in html
    _no_dash(line)
    _no_dash(html)


def test_parser_auto_has_ownership_flag_and_not_yes():
    parser = build_parser()
    help_text = parser.format_help()
    assert help_text.index("auto") < help_text.index("capture")
    args = parser.parse_args(["auto", "--i-own-this-network", "--duration", "30", "--out-dir", "out"])
    assert args.duration == 30 and args.func.__name__ == "cmd_auto"
    assert not hasattr(args, "yes")
    with pytest.raises(SystemExit):
        parser.parse_args(["auto", "--yes"])
    cred = parser.parse_args(["credcheck", "192.168.1.50", "--yes"])
    assert cred.yes is True


def test_auto_stops_for_consent_tools_root_and_empty_lan(tmp_path, capsys, monkeypatch):
    import iotaudit.credcheck as credcheck

    def refuse(*_args, **_kwargs):
        raise AssertionError("credcheck stays opt-in")

    monkeypatch.setattr(credcheck, "check_device", refuse)
    refused = run_auto(
        _args(tmp_path, i_own_this_network=False),
        consent=lambda _yes=False: False,
        system="Linux",
    )
    assert refused == 2
    assert "Consent not given" in capsys.readouterr().err

    missing = run_auto(_args(tmp_path), system="Darwin", which=lambda _name: None, euid=lambda: 0)
    err = capsys.readouterr().err
    assert missing == 1
    assert "brew install nmap tcpdump" in err
    _no_dash(err)

    def explode(**_kwargs):
        raise AssertionError("should not discover")

    rooted = run_auto(
        _args(tmp_path),
        system="Linux",
        which=lambda name: f"/usr/bin/{name}",
        euid=lambda: 1000,
        discover=explode,
    )
    assert rooted == 1
    assert "sudo iotaudit auto" in capsys.readouterr().err

    assert run_auto(_args(tmp_path), system="Windows") == 1
    assert "macOS and Linux" in capsys.readouterr().err

    assert run_auto(
        _args(tmp_path, duration=0),
        system="Linux",
        which=lambda name: f"/usr/bin/{name}",
        euid=lambda: 0,
    ) == 2

    empty = run_auto(
        _args(tmp_path),
        system="Linux",
        which=lambda name: f"/usr/bin/{name}",
        euid=lambda: 0,
        resolve=lambda _name: "eth0",
        discover=lambda iface: [{"ip": THIS_HOST, "mac": "02:00:00:00:00:14", "role": "this-host"}],
        capture=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no capture")),
    )
    assert empty == 1
    assert "No other devices found on eth0" in capsys.readouterr().err


def _run(tmp_path, *, previous=False):
    import sys

    scanned = []
    seen = {}

    def discover(iface):
        seen["iface"] = iface
        return _devices()

    def scan(ip):
        scanned.append(ip)
        if ip == QUIET:
            return [{
                "port": 23,
                "proto": "tcp",
                "service": "telnet",
                "risk": "high",
                "why": "Telnet exposes an unencrypted login shell.",
            }]
        return []

    def capture(iface, seconds, dest, bpf=None):
        seen["bpf"] = bpf
        seen["seconds"] = seconds
        wrpcap(str(dest), [_packet()])
        print(f"Passive capture on {iface}: 10s of {seconds}s, 1 packet", file=sys.stderr)
        return seconds

    if previous:
        folder = tmp_path / "2026-10-27"
        folder.mkdir()
        (folder / "080000.json").write_text(
            '[{"ip": "192.168.1.50", "mac": "02:00:00:00:00:32", "grade": "A", '
            '"verdict": "A: little observed.", "destinations": [], "dns_queries": [], '
            '"open_ports": [], "findings": []}]',
            encoding="utf-8",
        )

    def upnp():
        return {"routers": [{"name": "gateway"}], "mappings": [], "errors": []}

    rc = run_auto(
        _args(tmp_path),
        system="Linux",
        which=lambda name: f"/usr/bin/{name}",
        euid=lambda: 0,
        resolve=lambda _name: "eth0",
        discover=discover,
        scan=scan,
        upnp_audit=upnp,
        capture=capture,
        now=datetime(2026, 10, 27, 12, 0, 0),
    )
    return rc, scanned, seen


def test_auto_writes_a_dated_report_and_compares(tmp_path, capsys):
    rc, scanned, seen = _run(tmp_path, previous=True)
    out, err = capsys.readouterr()
    assert rc == 1
    assert seen["iface"] == "eth0"
    assert THIS_HOST not in scanned
    assert scanned == [ROUTER, CAMERA, QUIET]
    assert f"host {CAMERA}" in seen["bpf"]
    assert THIS_HOST not in seen["bpf"]
    assert "Passive capture on eth0: 10s of 60s, 1 packet" in err
    html = tmp_path / "2026-10-27" / "120000.html"
    js = html.with_suffix(".json")
    assert html.is_file() and js.is_file()
    text = js.read_text(encoding="utf-8")
    assert CAMERA in text and QUIET in text and DEST in text
    assert THIS_HOST not in text
    assert "Example camera (port 554)" in text
    assert "Identified as Example plug." in html.read_text(encoding="utf-8")
    assert f"Report written to {html.resolve()}" in out
    assert QUIET in out and "Telnet" in out
    assert "is new." in out
    assert "Security-relevant changes appeared" in out
    assert out.index(QUIET) < out.index("Report written to")
    _no_dash(out)
    _no_dash(html.read_text(encoding="utf-8"))
    pdf = html.with_suffix(".pdf")
    if pdf.is_file():
        assert f"PDF written to {pdf.resolve()}" in out
    else:
        assert 'pip install "iotaudit[pdf]"' in err


def test_auto_without_a_previous_run_exits_zero(tmp_path, capsys):
    rc, _scanned, _seen = _run(tmp_path, previous=False)
    out, err = capsys.readouterr()
    assert rc == 0
    assert "No earlier audit in this folder" in err
    assert "Report written to" in out
    assert "Security-relevant" not in out


def test_bad_previous_audit_still_writes_the_report(tmp_path, capsys):
    folder = tmp_path / "2026-10-27"
    folder.mkdir()
    (folder / "080000.json").write_text("{", encoding="utf-8")
    rc, _scanned, _seen = _run(tmp_path, previous=False)
    out, err = capsys.readouterr()
    assert rc == 2
    assert (folder / "120000.html").is_file()
    assert "Report written to" in out
    assert "--compare" in err
