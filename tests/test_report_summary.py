"""Per-device country summary and traffic-pattern confidence.

Observed countries are facts (confidence certain). Video, audio, telemetry, and
unknown are indicators with low, medium, or high confidence.
"""

from __future__ import annotations

from pathlib import Path

from iotaudit.grading import destination_country_summary, traffic_pattern_summary
from iotaudit.models import Destination, TrafficClass
from iotaudit.report import render_html
from iotaudit.traffic import classify_traffic


def test_country_summary_is_an_observed_fact():
    a = Destination(ip="1.1.1.1", country="DE", org="Hetzner", bytes_out=10, bytes_in=1)
    b = Destination(ip="1.1.1.2", country="DE", org="Amazon", bytes_out=5, bytes_in=2)
    c = Destination(ip="1.1.1.3", country="US", org="Google", bytes_out=100, bytes_in=0)
    missing = Destination(ip="1.1.1.4", country=None, bytes_out=3)
    rows, unresolved = destination_country_summary([a, b, c, missing])
    assert unresolved == 1
    assert [r["country"] for r in rows] == ["US", "DE"]
    de = rows[1]
    assert de["destinations"] == 2
    assert de["bytes_out"] == 15 and de["bytes_in"] == 3
    assert de["orgs"] == ["Amazon", "Hetzner"]
    assert de["confidence"] == "certain" and de["kind"] == "observed"
    assert all(r["kind"] == "observed" and r["confidence"] == "certain" for r in rows)


def test_pattern_summary_is_an_indicator_and_skips_bogon_peers():
    strong = Destination(ip="1.2.3.4", bytes_out=100, bytes_in=4,
                         traffic_class=TrafficClass("video", "high"))
    strong.__dict__["_tc_detail"] = "Indicator: looks like video, not proof."
    weak = Destination(ip="1.2.3.5", bytes_out=50,
                       traffic_class=TrafficClass("video", "low"))
    tele = Destination(ip="8.8.8.8", bytes_out=20,
                       traffic_class=TrafficClass("telemetry", "medium"))
    claimed = Destination(ip="9.9.9.9", bytes_out=10,
                          traffic_class=TrafficClass("audio", "certain"))
    bogon = Destination(ip="192.0.0.6", bytes_out=9000, lan=True,
                        traffic_class=TrafficClass("video", "high"))
    bogon.__dict__["special_use"] = True
    rows = traffic_pattern_summary([strong, weak, tele, claimed], [bogon])
    by_label = {r["label"]: r for r in rows}
    assert set(by_label) == {"video", "telemetry", "audio"}
    video = by_label["video"]
    assert video["where"] == "internet"
    assert video["destinations"] == 2
    assert video["confidence"] == "high"
    assert video["kind"] == "indicator"
    assert "Strongest confidence: high." in video["summary"]
    assert "Indicator only, not proof" in video["summary"]
    assert video["display"] == "video"
    assert "Indicator: looks like video" in video["details"][0]
    # "certain" is not a pattern confidence. It is clamped to high.
    assert by_label["audio"]["confidence"] == "high"
    assert "certain" not in by_label["audio"]["summary"]
    assert by_label["telemetry"]["confidence"] == "medium"
    assert by_label["telemetry"]["display"] == "telemetry"
    assert all(r["confidence"] in ("low", "medium", "high") for r in rows)


def test_classify_details_say_indicator():
    video = classify_traffic(2_000_000, 10, {443}, 1000, set())
    audio = classify_traffic(50_000, 10, {443}, 200, set())
    tele = classify_traffic(1000, 60, {443}, 50, set())
    unknown = classify_traffic(100_000, 10, {443}, 800, set())
    rtsp = classify_traffic(100, 10, {554}, 50, set())
    assert video["label"] == "video" and video["confidence"] == "medium"
    assert audio["label"] == "audio" and audio["confidence"] == "low"
    assert tele["label"] == "telemetry" and tele["confidence"] == "medium"
    assert unknown["label"] == "unknown" and unknown["confidence"] == "low"
    assert rtsp["label"] == "video" and rtsp["confidence"] == "high"
    for row in (video, audio, tele, unknown, rtsp):
        assert "Indicator:" in row["detail"]
        assert row["confidence"] != "certain"
        assert "\u2014" not in row["detail"] and "\u2013" not in row["detail"]


def test_device_dict_and_html_show_countries_and_patterns():
    from iotaudit.analyze import build_devices, to_dict
    from iotaudit.capture import Collector
    from iotaudit.models import Flow

    col = Collector(["192.168.0.50"])
    video = Flow("192.168.0.50", "3.70.12.148", 443, "tcp", bytes=2_000_000, packets=2000, tls=True)
    video.series = {1_700_000_000: 2_000_000}
    col.flows[(video.src, video.dst, video.dport, video.proto)] = video
    tele = Flow("192.168.0.50", "8.8.8.8", 53, "udp", bytes=400, packets=4)
    tele.series = {1_700_000_000: 200, 1_700_000_010: 200}
    col.flows[(tele.src, tele.dst, tele.dport, tele.proto)] = tele

    d = to_dict(build_devices(col)[0])
    countries = {c["country"] for c in d["destination_countries"]}
    assert countries == {"DE", "US"}
    assert all(c["confidence"] == "certain" and c["kind"] == "observed"
               for c in d["destination_countries"])
    labels = {p["label"] for p in d["traffic_patterns"]}
    assert "video" in labels and "telemetry" in labels
    video_dest = next(x for x in d["destinations"] if x["ip"] == "3.70.12.148")
    assert video_dest["traffic_class"]["label"] == "video"
    assert video_dest["traffic_class"]["display"] == "video"
    assert "Indicator:" in video_dest["traffic_class"]["detail"]
    for p in d["traffic_patterns"]:
        assert p["confidence"] in ("low", "medium", "high")
        assert p["kind"] == "indicator"
        assert "Indicator only" in p["summary"]
    titles = [x["title"] for x in d["findings"]]
    assert any("looks like video" in t and "indicator" in t for t in titles)
    assert any("looks like telemetry" in t and "indicator" in t for t in titles)
    location = next(x for x in d["findings"] if x["category"] == "location")
    assert location["confidence"] == "certain"
    assert "Observed destination countries" in location["detail"]
    assert "Observed destination countries" in d["summary"]
    assert "not proof" in d["summary"]

    html = render_html([d], {"source": "test"})
    assert "Destination countries" in html
    assert "observed" in html
    assert "Traffic patterns" in html
    assert "confidence: medium" in html
    assert "Indicator only" in html
    assert "looks like video" in html
    assert "\u2014" not in html and "\u2013" not in html and "&mdash;" not in html


def test_no_unicode_dashes_under_src():
    root = Path(__file__).resolve().parents[1] / "src"
    bad = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".gz", ".mmdb", ".png", ".svg"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "\u2014" in text or "\u2013" in text:
            bad.append(str(path.relative_to(root)))
    assert bad == []
