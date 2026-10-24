"""PDF export: print CSS, optional extra, CLI, and MCP."""

from __future__ import annotations

import argparse
import asyncio
import builtins
import json

import pytest

from iotaudit.pdf import PDF_INSTALL_HINT, PdfExtraMissing, write_pdf
from iotaudit.report import render_html

_DASHES = ("\u2014", "\u2013", "&mdash;", "&ndash;")


def _dest(i: int) -> dict:
    return {
        "domains": [f"host-{i}.example"],
        "ip": f"192.0.2.{(i % 200) + 1}",
        "country": "US",
        "org": "Example Org",
        "ports": [443],
        "protocols": ["tcp"],
        "bytes_out": 1000 + i,
        "bytes_in": 40,
        "encryption_kind": "tls",
        "encrypted": True,
        "tracker": False,
        "readable_fraction": None,
        "traffic_class": None,
    }


def _device(ip: str, grade: str, rows: int) -> dict:
    return {
        "ip": ip,
        "mac": "02:00:00:00:00:01",
        "vendor": "Example Vendor",
        "profile": "example",
        "grade": grade,
        "score": 70,
        "verdict": f"{grade}: encrypted cloud traffic (US).",
        "summary": "Observed traffic only. One destination country.",
        "findings": [{
            "severity": "info",
            "title": "Example finding",
            "detail": "Placeholder finding for the report layout.",
            "confidence": "certain",
        }],
        "destinations": [_dest(i) for i in range(1, rows + 1)],
        "lan_peers": [],
        "open_ports": [{
            "port": 80, "proto": "tcp", "service": "http", "product": "example", "risk": "low",
        }],
        "destination_countries": [{
            "country": "US", "destinations": rows, "bytes_out": 1000, "bytes_in": 40,
            "orgs": ["Example Org"],
        }],
        "traffic_patterns": [{"confidence": "low", "summary": "looks like telemetry"}],
        "series_total": {"100": 10, "110": 40},
        "bursts": [{"kind": "upload", "bytes": 40}],
    }


def _block_xhtml2pdf(monkeypatch) -> None:
    real = builtins.__import__

    def blocked(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "xhtml2pdf" or (isinstance(name, str) and name.startswith("xhtml2pdf.")):
            raise ImportError("blocked for test")
        return real(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked)


def test_print_css_keeps_grade_verdict_together_and_rows_intact():
    devices = [_device("192.168.1.50", "C", 2), _device("192.168.1.51", "B", 1)]
    html = render_html(devices, {"source": "sample", "duration": 60})
    for dash in _DASHES:
        assert dash not in html
    assert "@media print" in html
    assert "page-break-before: always" in html
    assert "page-break-inside: avoid" in html
    assert 'repeat="1"' in html
    marker = 'class="card device device-next"'
    assert html.count(marker) == 1
    assert html.index("192.168.1.50") < html.index(marker) < html.index("192.168.1.51")
    head = html.split('class="device-head"', 1)[1]
    assert head.index("grade") < head.index("Verdict") < head.index("Summary")
    assert ".chart { display: none; }" in html
    assert 'class="chart"' in html


def test_missing_extra_raises_a_one_line_hint(monkeypatch, tmp_path):
    _block_xhtml2pdf(monkeypatch)
    with pytest.raises(PdfExtraMissing) as raised:
        write_pdf("<html><body><p>192.168.1.50</p></body></html>", tmp_path / "out.pdf")
    message = str(raised.value)
    assert message == PDF_INSTALL_HINT
    assert "\n" not in message
    for dash in _DASHES:
        assert dash not in message
    assert not (tmp_path / "out.pdf").exists()


def test_pdf_flags_on_analyze_capture_and_report():
    from iotaudit.cli import build_parser

    parser = build_parser()
    analyze = parser.parse_args(["analyze", "capture.pcap", "--pdf", "--out", "report.html"])
    assert analyze.pdf is True and analyze.func.__name__ == "cmd_analyze"
    assert parser.parse_args(["analyze", "capture.pcap"]).pdf is False
    capture = parser.parse_args(["capture", "--pdf", "--i-own-this-network"])
    assert capture.pdf is True and capture.func.__name__ == "cmd_capture"
    report = parser.parse_args(["report", "--pdf", "results.json", "--out", "copy.pdf"])
    assert report.pdf is True and report.input == "results.json" and report.out == "copy.pdf"
    assert parser.parse_args(["report", "results.json"]).pdf is False


def test_finish_still_writes_html_when_pdf_extra_is_missing(monkeypatch, tmp_path, capsys):
    _block_xhtml2pdf(monkeypatch)
    from iotaudit.capture import Collector
    from iotaudit.cli import _finish

    out = tmp_path / "out.html"
    args = argparse.Namespace(
        scan=False, device=[], upnp=False, geoip=None, profiles=None,
        json=None, out=str(out), pdf=True,
    )
    assert _finish(Collector([]), args, {"source": "sample"}) == 0
    err = capsys.readouterr().err
    assert PDF_INSTALL_HINT in err
    assert "Traceback" not in err
    assert out.is_file() and "iotaudit report" in out.read_text(encoding="utf-8")
    assert not out.with_suffix(".pdf").exists()


def test_report_command_missing_extra_is_one_stderr_line(monkeypatch, tmp_path, capsys):
    _block_xhtml2pdf(monkeypatch)
    from iotaudit.cli import main

    html = tmp_path / "report.html"
    html.write_text("<html><body><p>192.168.1.50</p></body></html>", encoding="utf-8")
    assert main(["report", "--pdf", str(html)]) == 1
    err = capsys.readouterr().err
    assert err.strip() == PDF_INSTALL_HINT
    assert not html.with_suffix(".pdf").exists()
    assert main(["report", str(html)]) == 2


def test_report_rejects_pdf_path_that_overwrites_the_input(tmp_path, capsys):
    from iotaudit.cli import main

    html = tmp_path / "report.html"
    html.write_text("<html><body><p>192.168.1.50</p></body></html>", encoding="utf-8")
    assert main(["report", "--pdf", str(html), "--out", str(html)]) == 2
    assert "same as the input" in capsys.readouterr().err
    assert html.read_text(encoding="utf-8").startswith("<html>")


def _host_row_ys(page) -> list[float]:
    ys: list[float] = []

    def visitor(text, cm, tm, font_dict, font_size):
        if text and text.startswith("host-"):
            ys.append(cm[5])

    page.extract_text(visitor_text=visitor)
    return ys


def test_render_pdf_paginates_per_device_without_cutting_rows(tmp_path):
    pytest.importorskip("xhtml2pdf")
    pytest.importorskip("pypdf")
    from pypdf import PdfReader

    devices = [_device("192.168.1.50", "C", 80), _device("192.168.1.51", "B", 4)]
    html = render_html(devices, {"source": "sample", "duration": 30})
    dest = tmp_path / "report.pdf"
    write_pdf(html, dest)
    assert dest.read_bytes().startswith(b"%PDF")
    reader = PdfReader(dest)
    texts = [(page.extract_text() or "") for page in reader.pages]
    assert len(texts) >= 3
    assert "192.168.1.50" in texts[0] and "Verdict" in texts[0]
    second_at = next(i for i, text in enumerate(texts) if "192.168.1.51" in text)
    assert second_at > 1
    assert "Verdict" in texts[second_at]
    assert "host-70" not in texts[second_at]
    # Continuation pages repeat the destination header and do not pile rows up.
    assert "Country" in texts[1]
    blob = "\n".join(texts)
    assert blob.count(" out / ") - blob.count("bytes out / ") == 84
    for page in reader.pages:
        ys = sorted(_host_row_ys(page))
        for earlier, later in zip(ys, ys[1:], strict=False):
            assert later - earlier >= 8


def test_report_command_converts_json_and_html(tmp_path, capsys):
    pytest.importorskip("xhtml2pdf")
    from iotaudit.cli import main

    devices = [_device("192.168.1.50", "C", 2)]
    src = tmp_path / "devices.json"
    src.write_text(json.dumps(devices), encoding="utf-8")
    assert main(["report", "--pdf", str(src)]) == 0
    pdf = src.with_suffix(".pdf")
    assert pdf.read_bytes().startswith(b"%PDF")
    assert "PDF written to" in capsys.readouterr().out

    html_path = tmp_path / "report.html"
    html_path.write_text(render_html(devices, {"source": "sample"}), encoding="utf-8")
    out = tmp_path / "nested" / "copy.pdf"
    assert main(["report", "--pdf", str(html_path), "--out", str(out)]) == 0
    assert out.read_bytes().startswith(b"%PDF")


def test_mcp_analyze_pcap_exposes_pdf_and_writes_beside_html(tmp_path):
    pytest.importorskip("xhtml2pdf")
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    from iotaudit.mcp_server import create_server

    pcap = tmp_path / "t.pcap"
    packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
              / IP(src="192.168.1.50", dst="192.0.2.10")
              / TCP(sport=40000, dport=443, flags="S"))
    wrpcap(str(pcap), [packet])
    server = create_server()
    tools = asyncio.run(server.list_tools())
    analyze = next(tool for tool in tools if tool.name == "analyze_pcap")
    schema = getattr(analyze, "input_schema", None) or analyze.inputSchema
    assert "pdf" in schema["properties"]

    html = tmp_path / "report.html"
    asyncio.run(server.call_tool("analyze_pcap", {
        "path": str(pcap),
        "device_ips": ["192.168.1.50"],
        "report_path": str(html),
        "pdf": True,
    }))
    assert html.is_file()
    assert html.with_suffix(".pdf").read_bytes().startswith(b"%PDF")

    with pytest.raises(Exception) as raised:
        asyncio.run(server.call_tool("analyze_pcap", {"path": str(pcap), "pdf": True}))
    assert "report_path" in str(raised.value.__cause__)


def test_mcp_pdf_missing_extra_is_a_clean_error(monkeypatch, tmp_path):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    from iotaudit.mcp_server import create_server

    def missing(*_args, **_kwargs):
        raise PdfExtraMissing(PDF_INSTALL_HINT)

    monkeypatch.setattr("iotaudit.pdf.write_pdf", missing)
    pcap = tmp_path / "t.pcap"
    packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
              / IP(src="192.168.1.50", dst="192.0.2.10")
              / TCP(sport=40000, dport=443, flags="S"))
    wrpcap(str(pcap), [packet])
    html = tmp_path / "report.html"
    server = create_server()
    with pytest.raises(Exception) as raised:
        asyncio.run(server.call_tool("analyze_pcap", {
            "path": str(pcap),
            "report_path": str(html),
            "pdf": True,
        }))
    assert PDF_INSTALL_HINT in str(raised.value.__cause__)
    assert html.is_file()
    assert not html.with_suffix(".pdf").exists()
