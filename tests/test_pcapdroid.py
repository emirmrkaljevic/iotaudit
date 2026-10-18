"""PCAPdroid (Android) pcap import: strip the bogus Ethernet header + trailer, record apps."""

from __future__ import annotations

import struct

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from iotaudit.capture import Collector, from_pcap


def _pcapdroid_frame(src, dst, appname, payload=b"hello-iot"):
    inner = IP(src=src, dst=dst) / UDP(sport=40000, dport=443) / payload
    trailer = (struct.pack(">I", 0x01072021) + struct.pack(">i", 10123)
               + appname.encode().ljust(20, b"\x00")[:20] + b"\x00\x00\x00\x00")
    raw = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / inner) + trailer
    return Ether(raw)


def test_pcapdroid_import_strips_trailer_and_records_app(tmp_path):
    pcap = tmp_path / "pcapdroid.pcap"
    pkts = [_pcapdroid_frame("100.64.5.5", "52.1.2.3", "com.tuya.smartlife") for _ in range(3)]
    wrpcap(str(pcap), pkts)

    col = Collector(["100.64.5.5"])
    from_pcap(str(pcap), col)
    # app name was recovered from the trailer
    assert "com.tuya.smartlife" in col.apps
    # flow recorded to the cloud dst; bogus Ethernet MAC was NOT learned as the device MAC
    dests = {f.dst for f in col.flows.values()}
    assert "52.1.2.3" in dests
    assert col.macs.get("100.64.5.5") is None


def test_plain_pcap_still_works(tmp_path):
    pcap = tmp_path / "plain.pcap"
    pkt = Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="192.168.1.9", dst="8.8.8.8") / UDP(dport=53) / b"q"
    wrpcap(str(pcap), [pkt])
    col = Collector(["192.168.1.9"])
    from_pcap(str(pcap), col)
    assert col.apps == {}
    assert any(f.dst == "8.8.8.8" for f in col.flows.values())
