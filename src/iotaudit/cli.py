"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyze import build_devices, to_dict
from .capture import Collector, from_pcap, live
from .consent import require_consent
from .enrich import Geo
from .report import render_html


def _finish(col, args, meta) -> int:
    scans = {}
    if getattr(args, "scan", False):
        from .scan import nmap_scan

        for ip in (args.device or []):
            print(f"Scanning {ip} with nmap...", file=sys.stderr)
            scans[ip] = nmap_scan(ip)
    devices = [to_dict(d) for d in build_devices(col, Geo(args.geoip), args.profiles, scans)]
    if args.json:
        Path(args.json).write_text(json.dumps(devices, indent=2))
    out = Path(args.out)
    out.write_text(render_html(devices, meta), encoding="utf-8")
    for d in devices:
        print(f"{d['ip']:<16} grade {d['grade']}  ({len(d['destinations'])} destinations, "
              f"{len(d['findings'])} findings)")
    print(f"Report written to {out.resolve()}")
    return 0


def cmd_capture(args) -> int:
    if not require_consent(args.i_own_this_network):
        print("Consent not given; aborting.", file=sys.stderr)
        return 2
    iface = args.iface
    if args.mode == "hotspot":
        from . import hotspot

        hotspot.start(args.iface, args.ssid, args.password)
        print(f"Hotspot '{args.ssid}' up on {args.iface}. Join your device to it now.",
              file=sys.stderr)
    spoofer = None
    fwd = None
    if args.mode == "arp":
        from . import arp

        if not args.device:
            print("ARP mode needs at least one --device (the IP to audit).", file=sys.stderr)
            return 2
        fwd = arp.IPForwarding().__enter__()
        spoofer = arp.start(args.device[0], args.gateway, None if args.iface == "auto" else args.iface)
    col = Collector(args.device)
    try:
        print(f"Capturing on {iface} for {args.duration}s (Ctrl+C to stop early)...",
              file=sys.stderr)
        live(None if iface == "auto" else iface, args.duration, col)
    except KeyboardInterrupt:
        pass
    finally:
        if args.mode == "hotspot" and not args.keep_hotspot:
            from . import hotspot

            hotspot.stop()
        if spoofer is not None:
            print("Restoring ARP tables...", file=sys.stderr)
            spoofer.stop()
        if fwd is not None:
            fwd.__exit__(None, None, None)
    return _finish(col, args, {"source": f"{args.mode}:{iface}", "duration": args.duration})


def cmd_analyze(args) -> int:
    col = from_pcap(args.pcap, Collector(args.device))
    return _finish(col, args, {"source": args.pcap})


def cmd_scan(args) -> int:
    if not require_consent(args.i_own_this_network):
        return 2
    from .scan import nmap_scan

    print(json.dumps(nmap_scan(args.ip), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iotaudit", description="Audit your own smart-home devices.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--device", action="append", help="device IP to focus on (repeatable)")
        sp.add_argument("--out", default="iotaudit-report.html")
        sp.add_argument("--json", help="also write JSON results here")
        sp.add_argument("--geoip", help="path to a GeoLite2/DB-IP country .mmdb")
        sp.add_argument("--profiles", help="extra directory of device profile YAML files")
        sp.add_argument("--scan", action="store_true", help="nmap-scan each --device after capture")

    c = sub.add_parser("capture", help="live capture (hotspot recommended)")
    c.add_argument("--mode", choices=["hotspot", "iface", "arp"], default="hotspot",
                   help="hotspot: start Wi-Fi AP; iface: sniff an existing interface")
    c.add_argument("--iface", default="auto", help="capture interface; 'auto' lets libpcap choose")
    c.add_argument("--gateway", help="ARP mode: router IP (auto-detected if omitted)")
    c.add_argument("--ssid", default="iotaudit")
    c.add_argument("--password", default="auditme123")
    c.add_argument("--duration", type=int, default=600)
    c.add_argument("--keep-hotspot", action="store_true")
    c.add_argument("--i-own-this-network", action="store_true")
    common(c)
    c.set_defaults(func=cmd_capture)

    a = sub.add_parser("analyze", help="analyse an existing pcap")
    a.add_argument("pcap")
    common(a)
    a.set_defaults(func=cmd_analyze)

    s = sub.add_parser("scan", help="nmap open-port scan of one device")
    s.add_argument("ip")
    s.add_argument("--i-own-this-network", action="store_true")
    s.set_defaults(func=cmd_scan)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuntimeError, ValueError, NotImplementedError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
