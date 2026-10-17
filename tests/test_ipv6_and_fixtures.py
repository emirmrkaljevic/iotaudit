"""IPv6/NDP capture, special-use (bogon) peer classification, the honest
'media-not-observed' note, and regression checks against real-run report fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from iotaudit.analyze import build_devices, to_dict
from iotaudit.capture import Collector, build_bpf
from iotaudit.enrich import is_home_lan, is_special_use, special_use_label
from iotaudit.models import Flow
from iotaudit.review import review_report

FIX = Path(__file__).parent / "fixtures"


def _feeder_like_collector(with_lan_media: bool = False) -> Collector:
    col = Collector(["192.168.0.50"])
    col.macs["192.168.0.50"] = "d8:1f:12:00:00:01"
    col.queries["192.168.0.50"] = {"a1-us.iotbing.com"}
    col.dns["35.155.252.83"] = {"a1-us.iotbing.com"}
    specs = [
        ("35.155.252.83", 443, 17000, True, "tcp"),
        ("52.32.71.30", 8883, 23000, True, "tcp"),
        ("15.204.72.48", 3478, 4000, False, "udp"),      # STUN/TURN
        ("100.64.0.42", 63720, 3360, False, "udp"),  # CGNAT peer
        ("8.8.8.8", 53, 200, False, "udp"),
    ]
    for dst, port, nbytes, tls, proto in specs:
        f = Flow("192.168.0.50", dst, port, proto, bytes=nbytes,
                 packets=max(1, nbytes // 100), tls=tls)
        col.flows[(f.src, f.dst, f.dport, f.proto)] = f
    # The odd 192.0.0.6 "LAN peer" from the real fourth run (special-use space).
    bogon = Flow("192.168.0.50", "192.0.0.6", 63720, "udp", bytes=3360, packets=24, lan=True)
    col.lan_flows[(bogon.src, bogon.dst, bogon.dport, bogon.proto)] = bogon
    if with_lan_media:
        m = Flow("192.168.0.50", "192.168.0.9", 7000, "udp", bytes=2_000_000, packets=1500,
                 lan=True, bytes_in=1_500_000, packets_in=1200)
        col.lan_flows[(m.src, m.dst, m.dport, m.proto)] = m
    return col


def test_special_use_helpers():
    assert is_special_use("192.0.0.6")
    assert is_special_use("198.51.100.4")
    assert not is_special_use("192.168.0.9")
    assert is_home_lan("192.168.0.9")
    assert is_home_lan("fe80::1")
    assert not is_home_lan("192.0.0.6")
    assert "192.0.0.0/24" in special_use_label("192.0.0.6")


def test_bogon_peer_flagged_not_a_device():
    d = to_dict(build_devices(_feeder_like_collector())[0])
    peer = next(p for p in d["lan_peers"] if p["ip"] == "192.0.0.6")
    assert peer["special_use"] is True
    assert peer.get("looks_like")
    titles = [f["title"] for f in d["findings"]]
    assert any("special-use" in t for t in titles)


def test_media_not_observed_note():
    d = to_dict(build_devices(_feeder_like_collector(with_lan_media=False))[0])
    titles = [f["title"] for f in d["findings"]]
    assert any("not observed" in t.lower() for t in titles), titles
    v = review_report(d)
    assert v["stun"] and v["media_not_observed"]
    assert v["special_use_peers"] == ["192.0.0.6"]
    assert v["real_lan_bytes"] == 0  # the only LAN "peer" is a bogon, excluded


def test_media_observed_suppresses_note():
    d = to_dict(build_devices(_feeder_like_collector(with_lan_media=True))[0])
    v = review_report(d)
    assert v["real_lan_bytes"] >= 2_000_000
    assert not v["media_not_observed"]
    titles = [f["title"] for f in d["findings"]]
    assert not any("set up but not observed" in t.lower() for t in titles)


def test_ipv6_flow_and_ndp_counting():
    from scapy.layers.inet import UDP
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, IPv6
    from scapy.layers.l2 import Ether

    col = Collector(["192.168.0.50"])
    col.macs["192.168.0.50"] = "d8:1f:12:00:00:01"
    dmac = "d8:1f:12:00:00:01"
    pmac = "00:00:f0:00:00:02"
    # Link-local unicast UDP between feeder and phone (what we hope to see over IPv6).
    for _ in range(5):
        col.add(Ether(src=dmac, dst=pmac) / IPv6(src="fe80::da1f:12ff:fe00:1",
                dst="fe80::200:f0ff:fe00:2") / UDP(sport=7000, dport=7001) / (b"\x00" * 300))
    # NDP neighbor solicitation + advertisement (link-local control plane).
    col.add(Ether(src=dmac) / IPv6(src="fe80::da1f:12ff:fe00:1", dst="ff02::1:ff00:2")
            / ICMPv6ND_NS(tgt="fe80::200:f0ff:fe00:2"))
    col.add(Ether(src=pmac) / IPv6(src="fe80::200:f0ff:fe00:2",
            dst="fe80::da1f:12ff:fe00:1") / ICMPv6ND_NA(tgt="fe80::200:f0ff:fe00:2"))

    summ = col.ipv6_summary(dmac)
    assert summ["flows"] == 1
    assert summ["bytes"] > 0
    assert summ["link_local_bytes"] == summ["bytes"]
    assert summ["ndp"]["ns"] == 1 and summ["ndp"]["na"] == 1
    assert summ["any_ipv6_seen"]
    assert summ["attributed_by_mac"]


def test_build_bpf_covers_v4_v6_and_ndp():
    bpf = build_bpf("192.168.0.50", "d8:1f:12:00:00:01", ipv6=True)
    assert "host 192.168.0.50" in bpf
    assert "ether host d8:1f:12:00:00:01" in bpf
    assert "icmp6" in bpf
    assert build_bpf("192.168.0.50", None, ipv6=False) == "(host 192.168.0.50)"


def test_real_run_fixtures_load_and_review():
    for name in ("feeder_capture_run3.json", "feeder_capture_run4.json"):
        data = json.loads((FIX / name).read_text())
        assert isinstance(data, list) and data
        dev = data[0]
        assert dev["grade"] in "ABCDEF"
        assert dev["destinations"]
        # No destination should be claimed as high-confidence video given the tiny byte counts.
        for x in dev["destinations"]:
            tc = x.get("traffic_class") or {}
            if tc.get("label") == "video":
                assert tc.get("confidence") not in ("high", "medium")


def test_run4_fixture_is_the_not_observed_case():
    dev = json.loads((FIX / "feeder_capture_run4.json").read_text())[0]
    v = review_report(dev)
    # Fourth run: STUN present, only ~150KB cloud 'video-ish' traffic, LAN peer is the bogon.
    assert v["stun"] is True
    assert "192.0.0.6" in v["special_use_peers"]
    assert v["media_not_observed"] is True
