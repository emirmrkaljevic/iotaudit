---
title: "Share your iotaudit results without leaking your network"
---
# Share your iotaudit results without leaking your network

When I ask for help with a strange device in a forum, I want to show what it does without posting my local IP addresses. Since 0.1.16, `iotaudit export` can leave them out.

```
pip install -U iotaudit
iotaudit export audit.json --format md --redact
```

Example output (sample data):

```
iotaudit summary: 3 devices, worst grade D, 1 finding

| name | ip | grade | findings | changed | status |
|---|---|---|---|---|---|
| Example Vendor |  | D | 1 |  | first_run |
| Example Vendor |  | C | 0 |  | first_run |
| Example Vendor |  | C | 0 |  | first_run |
```

- `--format md` gives a Markdown table for GitHub issues, Reddit or the Home Assistant forum.
- `--format csv` gives one row per device for a spreadsheet.
- `--compare earlier.json` fills in which devices changed since the last audit.
- `--redact` works with every format. Devices that only had an IP as their name become "device 1", "device 2", and so on.

## Sharing the full report

The full HTML report contains local addresses. Since 0.1.17 you can make a redacted copy of the audit first and build the report from that:

```
iotaudit redact audit.json
iotaudit report --pdf audit.redacted.json
```

`iotaudit redact` replaces private and link-local IPs with labels like `lan-1`, MAC addresses with `02:00:00:00:00:01` style placeholders, and local hostnames with `host-1`. The same device keeps the same label everywhere, so the report still reads correctly. Interface names and capture file paths are dropped. Public cloud destinations stay, because they are what people need to see. Give the result a quick read before you post it anyway. Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](./)
