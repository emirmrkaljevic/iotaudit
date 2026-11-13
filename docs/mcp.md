---
title: MCP server
---
# MCP server

The MCP server exposes iotaudit's audit tools over stdio, so a local MCP client can run them. It is not a network service.

```bash
pip install "iotaudit[mcp]"
iotaudit-mcp
```

I also list the server on [mcpservers.org](https://mcpservers.org/servers/emirmrkaljevic/iotaudit) and the official MCP Registry.

## Tools

- `analyze_pcap`: analyse a pcap of your own network. You get per-device destinations, plaintext vs TLS, an A-F grade, a one-line safety verdict, and offline `known_issue_hints` from banners already in the capture. A hint changes the grade only when the version match is exact and the severity is critical. When `report_path` is set, the HTML report is written there. `pdf=true` also writes a PDF next to that HTML (same name, `.pdf` suffix) and needs the `iotaudit[pdf]` extra. `pdf=true` requires `report_path`.
- `capture`: live-capture on an interface of a network you own (needs root). Set `i_own_this_network=true` only after you confirm you own the network and devices. The duration is capped at 1800 seconds.
- `scan_device`: nmap open-port scan of one private-LAN device you own. Needs `i_own_this_network=true`.
- `default_credential_check`: the same opt-in default-login check as `iotaudit credcheck`. It is rate-limited, never brute-forces, stops at the first accepted login, and reports only accepted or not accepted. Set `i_own_this_device=true` only after you confirm you own this exact device.
- `diff_results`: compares two saved JSON audits the same way `iotaudit diff` does. Devices match by MAC, then by IP. It reports new and gone destination domains and IPs, new countries, new open ports, grade and verdict changes, newly seen unencrypted traffic, and new UPnP forwards when the JSON contains them. `security_relevant` is true, and `exit_code` is 1, when a device, destination, country, open port, worse grade, unencrypted flow, or UPnP forward appeared.
- `upnp_port_mappings`: lists the port forwards the LAN router opened via UPnP IGD. Read-only: it never adds or removes a mapping.

Consent is the same as the command line: the live tools refuse to run until ownership is confirmed. Only audit networks and devices you own. All data stays local, no telemetry.
