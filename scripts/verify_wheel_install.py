"""CI helper: confirm the installed wheel ships the OUI table and vendor lookup works."""
from importlib.resources import files

from iotaudit.enrich import mac_vendor

assert files("iotaudit").joinpath("data/oui.txt.gz").is_file(), "oui.txt.gz missing from package"
assert mac_vendor("48:87:2d:1f:32:c2"), "OUI lookup failed for known prefix"
assert mac_vendor("24:2a:ea:04:c8:59") == "Apple"
print("wheel install + OUI OK")
