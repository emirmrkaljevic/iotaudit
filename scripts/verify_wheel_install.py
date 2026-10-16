"""CI helper: confirm the installed wheel ships data files and lookups work."""
from importlib.resources import files

from iotaudit.enrich import Geo, asn_org, mac_vendor
from iotaudit.identify import identify_device

assert files("iotaudit").joinpath("data/oui.txt.gz").is_file(), "oui.txt.gz missing"
assert files("iotaudit").joinpath("data/ip2asn-lite.tsv.gz").is_file(), "ip2asn missing"
assert files("iotaudit").joinpath("data/dbip-country-lite.mmdb").is_file(), "dbip missing"
assert mac_vendor("48:87:2d:1f:32:c2")
asn, org = asn_org("3.70.12.148")
assert asn == 16509 and org and "Amazon" in org, (asn, org)
assert Geo().country("3.70.12.148"), "country lookup failed"
info = identify_device("192.168.0.2", mac="48:87:2d:1f:32:c2")
assert "Imipaw" in info["looks_like"] or "Tuya" in info["looks_like"], info
print("wheel install + OUI/ASN/geo/identify OK")
