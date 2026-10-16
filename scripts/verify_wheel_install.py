"""CI helper: confirm the installed wheel ships the OUI table and vendor lookup works."""
from importlib.resources import files

from iotaudit.enrich import mac_vendor

assert files("iotaudit").joinpath("data/oui.txt.gz").is_file(), "oui.txt.gz missing from package"
assert mac_vendor("70:87:9e:00:00:01"), "OUI lookup failed for known prefix"
assert mac_vendor("00:03:93:00:00:01") == "Apple"
print("wheel install + OUI OK")
