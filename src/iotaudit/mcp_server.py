"""MCP server: lets an assistant analyse captures and scan your own devices.
Run with `iotaudit-mcp` (stdio). Requires `pip install iotaudit[mcp]`."""

from __future__ import annotations

from .analyze import build_devices, to_dict
from .capture import Collector, from_pcap, live
from .diff import diff_results as compare_audits
from .enrich import Geo
from .report import render_html


def create_server():
    try:  # mcp >= 2
        from mcp.server.mcpserver import MCPServer as Server
    except ImportError:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as Server

    mcp = Server("iotaudit")

    @mcp.tool()
    def analyze_pcap(path: str, device_ips: list[str] | None = None,
                     report_path: str | None = None, pdf: bool = False) -> list[dict]:
        """Analyse a pcap of your own network.

        Per-device destinations, plaintext vs TLS, an A-F grade, a one-line safety verdict,
        and offline known_issue_hints from banners already in the capture. A hint changes
        the grade only when the version match is exact and the severity is critical.
        When report_path is set, write the HTML report there. pdf=true also writes a PDF
        next to that HTML (same name, .pdf suffix) and needs the iotaudit[pdf] extra.
        """
        if pdf and not report_path:
            raise ValueError("pdf=true needs report_path so the PDF is written next to the HTML.")
        devs = [to_dict(d) for d in build_devices(from_pcap(path, Collector(device_ips)), Geo())]
        if report_path:
            html = render_html(devs, {"source": path})
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write(html)
            if pdf:
                from pathlib import Path

                from .pdf import PdfExtraMissing, write_pdf

                pdf_path = Path(report_path).with_suffix(".pdf")
                try:
                    write_pdf(html, pdf_path)
                except PdfExtraMissing as exc:
                    raise ValueError(str(exc)) from None
        return devs

    @mcp.tool()
    def capture(iface: str, seconds: int = 120, device_ips: list[str] | None = None,
                i_own_this_network: bool = False) -> list[dict]:
        """Live-capture on an interface of a network you own (needs root). Set
        i_own_this_network=true only after the user confirms they own the network and devices."""
        if not i_own_this_network:
            raise ValueError("User must confirm they own this network and devices.")
        col = live(iface, min(seconds, 1800), Collector(device_ips))
        return [to_dict(d) for d in build_devices(col, Geo())]

    @mcp.tool()
    def scan_device(ip: str, i_own_this_network: bool = False) -> list[dict]:
        """nmap open-port scan of one private-LAN device the user owns."""
        if not i_own_this_network:
            raise ValueError("User must confirm they own this device.")
        from .scan import nmap_scan

        return nmap_scan(ip)

    @mcp.tool()
    def default_credential_check(ip: str, services: list[str] | None = None,
                                 i_own_this_device: bool = False) -> list[dict]:
        """Opt-in check whether one LAN device you own still accepts a well-known default login
        (telnet/http/ftp). Rate-limited, never brute-forces, stops at the first accepted login,
        and reports only accepted/not-accepted. Set i_own_this_device=true only after the user
        confirms they own this exact device."""
        from .credcheck import check_device

        if not i_own_this_device:
            raise ValueError("User must confirm they own this device.")
        results = check_device(ip, services or ["telnet"], confirmed=True)
        return [r.as_finding() for r in results]

    @mcp.tool()
    def diff_results(old_path: str, new_path: str) -> dict:
        """Compare two saved iotaudit JSON audits.

        Matches devices by MAC, then by IP. Reports new and gone destination
        domains and IPs, new countries, new open ports, grade and verdict
        changes, newly seen unencrypted traffic, and new UPnP forwards when
        the JSON contains them. security_relevant is true, and exit_code is 1,
        when a device, destination, country, open port, worse grade,
        unencrypted flow, or UPnP forward appeared.
        """
        return compare_audits(old_path, new_path)

    @mcp.tool()
    def upnp_port_mappings() -> dict:
        """List the port forwards the LAN router opened via UPnP IGD (read-only: never adds or
        removes a mapping). Shows which devices are reachable from the internet."""
        from .upnp import audit

        return audit()

    return mcp


def main() -> None:
    create_server().run()


if __name__ == "__main__":
    main()
