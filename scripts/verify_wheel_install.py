"""CI helper: confirm the installed wheel ships data files and lookups work."""
from importlib.resources import files

from iotaudit.enrich import Geo, asn_org, is_cgnat, mac_vendor
from iotaudit.hints import load_catalog
from iotaudit.identify import identify_device
from iotaudit.traffic import encryption_verdict

assert files("iotaudit").joinpath("data/oui.txt.gz").is_file()
assert files("iotaudit").joinpath("data/known_issues.yaml").is_file()
_hints = load_catalog()
assert 10 <= len(_hints) <= 20 and all(row["cve"].startswith("CVE-") for row in _hints)
assert files("iotaudit").joinpath("data/ip2asn-lite.tsv.gz").is_file()
assert files("iotaudit").joinpath("data/dbip-country-lite.mmdb").is_file()
assert mac_vendor("70:87:9e:00:00:01")
asn, org = asn_org("3.70.12.148")
assert asn == 16509 and org and "Amazon" in org
assert Geo().country("3.70.12.148")
info = identify_device("192.168.0.2", mac="70:87:9e:00:00:01")
assert "Imipaw" not in info["looks_like"] and info["confidence"] == "low"
assert is_cgnat("100.64.1.1")
assert encryption_verdict([b"GET / HTTP/1.0\r\n\r\n"])["kind"] == "plaintext"
print("wheel install + OUI/ASN/geo/identify/traffic OK")
