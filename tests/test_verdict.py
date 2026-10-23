"""One-line safety verdict: observed facts, then a hedged indicator.

The line sits on top of the A-F grade. Traffic patterns are never stated as
certain, and the wording does not accuse a vendor.
"""

from __future__ import annotations

from pathlib import Path

from iotaudit.grading import safety_verdict
from iotaudit.models import Destination, Device, TrafficClass
from iotaudit.report import render_html

_DASHES = ("\u2014", "\u2013", "&mdash;", "&ndash;")
_ACCUSATIONS = ("malicious", "spyware", "steal", "exfiltrat", "wrongdoing", "backdoor")


def _device(grade="D", ports=None, dests=None, peers=None, ipv6=None) -> Device:
    dev = Device(ip="192.168.0.50", grade=grade, open_ports=list(ports or []))
    for dest in dests or []:
        dev.destinations[dest.ip] = dest
    for dest in peers or []:
        dev.lan_peers[dest.ip] = dest
    if ipv6 is not None:
        dev.__dict__["ipv6"] = ipv6
    return dev


def _assert_plain_wording(text: str) -> None:
    assert text.endswith(".")
    for dash in _DASHES:
        assert dash not in text
    lowered = text.lower()
    for word in _ACCUSATIONS:
        assert word not in lowered
    assert "certain" not in lowered


def test_documented_shape_is_facts_then_a_hedged_indicator():
    dev = _device(
        grade="D",
        ports=[{"port": 23, "proto": "tcp", "service": "telnet", "risk": "high"}],
        dests=[
            Destination(ip="3.4.5.6", country="US", ports={443}, encryption_kind="tls",
                        bytes_out=50_000, bytes_in=1000),
            Destination(ip="8.8.8.8", country="US", ports={53}, encryption_kind="plaintext",
                        bytes_out=200),
            Destination(ip="15.204.72.48", country="US", ports={3478},
                        protocols={"STUN/TURN"}, encryption_kind="stun", bytes_out=4000),
        ],
    )
    text = safety_verdict(dev)
    assert text == (
        "D: Telnet open on the LAN; uses public DNS directly; "
        "encrypted cloud traffic (US); P2P video setup (stream not observed here)."
    )
    _assert_plain_wording(text)
    # Public DNS is plaintext by design and is not called out as app plaintext.
    assert "plaintext" not in text


def test_custom_encryption_stays_unverified_and_is_not_called_tls():
    dev = _device(
        grade="D",
        ports=[{"port": 23, "proto": "tcp", "service": "telnet", "risk": "high"}],
        dests=[
            Destination(ip="3.4.5.6", country="US", ports={443}, encryption_kind="tls",
                        bytes_out=20_000),
            Destination(ip="8.8.8.8", country="US", ports={53}, bytes_out=100),
            Destination(ip="15.204.79.232", country="US", ports={1443},
                        encryption_kind="custom-encryption", bytes_out=70_000),
            Destination(ip="15.204.72.48", country="US", ports={3478},
                        protocols={"STUN/TURN"}, encryption_kind="stun", bytes_out=4000),
        ],
    )
    text = safety_verdict(dev)
    assert text == (
        "D: Telnet open on the LAN; uses public DNS directly; "
        "TLS cloud traffic (US); custom encryption (unverified); "
        "P2P video setup (stream not observed here)."
    )
    _assert_plain_wording(text)
    assert "encrypted cloud traffic" not in text


def test_plaintext_to_the_internet_is_an_observed_fact():
    dev = _device(
        grade="F",
        dests=[
            Destination(ip="203.0.113.9", country="CN", ports={80}, encryption_kind="plaintext",
                        bytes_out=8000),
        ],
    )
    text = safety_verdict(dev)
    assert text == "F: plaintext traffic to the internet (CN)."
    _assert_plain_wording(text)


def test_countries_follow_byte_order_and_extra_ones_are_counted():
    dev = _device(
        grade="B",
        dests=[
            Destination(ip="203.0.113.1", country="DE", ports={443}, encryption_kind="tls", bytes_out=10),
            Destination(ip="203.0.113.2", country="US", ports={443}, encryption_kind="tls", bytes_out=90),
            Destination(ip="203.0.113.3", country="FR", ports={443}, encryption_kind="tls", bytes_out=20),
            Destination(ip="203.0.113.4", country="JP", ports={443}, encryption_kind="tls", bytes_out=5),
            Destination(ip="203.0.113.5", country="NL", ports={443}, encryption_kind="tls", bytes_out=4),
        ],
    )
    text = safety_verdict(dev)
    assert text == "B: encrypted cloud traffic (US, FR, DE, +2)."
    _assert_plain_wording(text)


def test_pattern_indicator_is_hedged_and_never_certain():
    dev = _device(
        grade="B",
        dests=[
            Destination(
                ip="9.9.9.10", country="DE", ports={443}, encryption_kind="tls", bytes_out=1000,
                traffic_class=TrafficClass("telemetry", "certain"),
            ),
        ],
    )
    text = safety_verdict(dev)
    assert text == (
        "B: encrypted cloud traffic (DE); looks like telemetry (confidence high)."
    )
    _assert_plain_wording(text)
    assert "confidence high" in text


def test_observed_stream_is_still_only_an_indicator():
    dev = _device(
        grade="C",
        dests=[
            Destination(ip="1.2.3.4", country="US", ports={443}, encryption_kind="tls",
                        bytes_out=1000),
            Destination(ip="5.6.7.8", country="US", ports={3478}, protocols={"STUN/TURN"},
                        encryption_kind="stun", bytes_out=200),
        ],
        peers=[
            Destination(ip="192.168.0.9", lan=True, bytes_out=2_000_000, bytes_in=1000,
                        traffic_class=TrafficClass("video", "high")),
        ],
    )
    text = safety_verdict(dev)
    assert "stream not observed" not in text
    assert "P2P video setup (looks like a stream, confidence high)" in text
    _assert_plain_wording(text)


def test_lan_bytes_without_a_media_class_are_not_called_a_stream():
    dev = _device(
        grade="C",
        dests=[
            Destination(ip="5.6.7.8", country="IE", ports={3478}, protocols={"STUN/TURN"},
                        encryption_kind="stun", bytes_out=200),
        ],
        peers=[Destination(ip="192.168.0.9", lan=True, bytes_out=600_000, bytes_in=10)],
    )
    text = safety_verdict(dev)
    assert text == (
        "C: cloud traffic (IE), encryption not confirmed; "
        "P2P video setup (traffic seen, stream not confirmed)."
    )
    _assert_plain_wording(text)


def test_low_confidence_video_does_not_count_as_an_observed_stream():
    dev = _device(
        grade="D",
        dests=[
            Destination(ip="5.6.7.8", country="US", ports={3478}, protocols={"STUN/TURN"},
                        encryption_kind="stun", bytes_out=200,
                        traffic_class=TrafficClass("video", "low")),
        ],
    )
    text = safety_verdict(dev)
    assert "stream not observed here" in text
    assert "looks like a stream" not in text
    _assert_plain_wording(text)


def test_ports_trackers_and_a_clean_scan_are_facts():
    dev = _device(
        grade="B",
        ports=[
            {"port": 23, "service": "telnet", "risk": "high"},
            {"port": 554, "service": "rtsp", "risk": "medium"},
            {"port": 443, "service": "https"},
        ],
        dests=[
            Destination(ip="1.2.3.4", country="DE", ports={443}, encryption_kind="tls",
                        bytes_out=4000, domains={"metrics.example"}, tracker=True),
            Destination(ip="1.2.3.5", country="DE", ports={443}, encryption_kind="tls",
                        bytes_out=100, domains={"ads.example"}, tracker=True),
        ],
    )
    text = safety_verdict(dev)
    assert text == (
        "B: Telnet and RTSP open on the LAN; encrypted cloud traffic (DE); "
        "2 analytics trackers."
    )
    _assert_plain_wording(text)

    clean = _device(
        grade="A",
        ports=[{"port": 443, "service": "https"}],
        dests=[
            Destination(ip="1.2.3.4", country="DE", ports={443}, encryption_kind="tls",
                        bytes_out=1000, tracker=True),
        ],
    )
    clean_text = safety_verdict(clean)
    assert clean_text == "A: no risky ports; encrypted cloud traffic (DE); one analytics tracker."
    _assert_plain_wording(clean_text)


def test_empty_capture_does_not_invent_a_clean_bill_of_health():
    text = safety_verdict(_device(grade="C"))
    assert text == "C: little traffic observed, so this grade is not conclusive."
    assert "no risky ports" not in text
    _assert_plain_wording(text)


def test_public_dns_country_is_a_fact_when_nothing_else_was_contacted():
    dev = _device(
        grade="B",
        dests=[Destination(ip="1.1.1.1", country="US", ports={53}, encryption_kind="plaintext",
                           bytes_out=80)],
    )
    text = safety_verdict(dev)
    assert text == "B: uses public DNS directly; servers in US."
    assert "plaintext" not in text
    _assert_plain_wording(text)


def test_json_and_html_keep_the_summary_and_put_the_verdict_first():
    from iotaudit.analyze import build_devices, to_dict
    from iotaudit.capture import Collector
    from iotaudit.models import Flow

    col = Collector(["192.168.0.50"])
    # 35.155.252.83 is a US cloud address in the bundled GeoIP database.
    tls = Flow("192.168.0.50", "35.155.252.83", 443, "tcp", bytes=20_000, packets=40, tls=True)
    dns = Flow("192.168.0.50", "8.8.8.8", 53, "udp", bytes=200, packets=4)
    stun = Flow("192.168.0.50", "15.204.72.48", 3478, "udp", bytes=4000, packets=20)
    for flow in (tls, dns, stun):
        col.flows[(flow.src, flow.dst, flow.dport, flow.proto)] = flow
    scans = {"192.168.0.50": [{
        "port": 23, "proto": "tcp", "service": "telnet", "risk": "high",
        "why": "Telnet exposes an unencrypted login shell.",
    }]}
    device = to_dict(build_devices(col, scans=scans)[0])
    assert device["summary"]
    assert len(device["summary"]) > len(device["verdict"])
    assert device["verdict"].startswith(f"{device['grade']}: ")
    assert "Telnet open on the LAN" in device["verdict"]
    assert "uses public DNS directly" in device["verdict"]
    assert "encrypted cloud traffic (US)" in device["verdict"]
    assert "P2P video setup (stream not observed here)" in device["verdict"]
    assert "Grade" in device["summary"]
    _assert_plain_wording(device["verdict"])

    html = render_html([device], {"source": "test"})
    assert f"<b>Verdict.</b> {device['verdict']}" in html
    assert html.index(device["verdict"]) < html.index("<b>Summary.</b>")
    assert "<b>Summary.</b>" in html
    for dash in _DASHES:
        assert dash not in html


def test_checked_in_sample_report_shows_a_verdict():
    html = (Path(__file__).resolve().parents[1] / "docs" / "sample-report.html").read_text(encoding="utf-8")
    assert "iotaudit 0.1.7" in html
    assert "<b>Verdict.</b>" in html
    assert "Telnet open on the LAN" in html
    assert "P2P video setup (stream not observed here)" in html
    assert html.index("<b>Verdict.</b>") < html.index("<b>Summary.</b>")
    for dash in _DASHES:
        assert dash not in html
