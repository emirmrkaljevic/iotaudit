# Contributing to iotaudit

Bug reports, fixes, and especially device profiles are welcome. Only audit and submit devices you own. All processing stays local until you choose to open an issue or a pull request.

## Device profiles

A profile teaches iotaudit what a brand or model usually talks to, so destinations outside that usual cloud can be flagged. The format is a short YAML file (see `src/iotaudit/profiles/`).

1. Run an audit on your own network, for example `sudo iotaudit auto`.
2. Export a draft profile. This runs the same redaction as `iotaudit redact` first, and keeps only vendor, model, public domains, ports and destination countries:

   ```bash
   iotaudit profile export ~/iotaudit/2026-01-01/120000.json 1
   ```

   The last argument is a 1-based index, a vendor name, or the device IP. Add `--out draft.yaml` to write a file.
3. Open the YAML and check it. Add the model if you know it. Drop any domain that is not this product's usual cloud. Do not put back IP addresses, MAC addresses, hostnames, SSIDs, serials or paths.
4. Open a GitHub issue with the Device profile template and paste the YAML, or open a pull request that adds a file under `src/iotaudit/profiles/` with a test.

If you know a public vendor document for those domains, include the link. Please write in English, in first person if you are describing your own device, and keep local details out of screenshots too.

More on the bundled format: [device profiles](docs/device-profiles.md).
