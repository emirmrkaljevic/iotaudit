"""MCP server: lets an assistant analyse captures and scan your own devices.
Run with `iotaudit-mcp` (stdio). Requires `pip install iotaudit[mcp]`."""

from __future__ import annotations

from .analyze import build_devices, to_dict
from .capture import Collector, from_pcap, live
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
                     report_path: str | None = None) -> list[dict]:
        """Analyse a pcap of your own network: per-device destinations, plaintext vs TLS, grade."""
        devs = [to_dict(d) for d in build_devices(from_pcap(path, Collector(device_ips)), Geo())]
        if report_path:
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write(render_html(devs, {"source": path}))
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
