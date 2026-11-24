"""from_pcap must decode Ethernet captures in a fresh interpreter, where no
Scapy layer has been imported yet (the state `iotaudit analyze` starts in)."""
import json
import subprocess
import sys


def test_from_pcap_decodes_ethernet_in_fresh_process(tmp_path):
    pcap = tmp_path / "eth.pcap"
    write = (
        "from scapy.layers.l2 import Ether\n"
        "from scapy.layers.inet import IP, UDP\n"
        "from scapy.utils import wrpcap\n"
        "wrpcap(%r, [Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')"
        "/IP(src='192.0.2.10', dst='198.51.100.7')/UDP(sport=40000, dport=123)])\n" % str(pcap)
    )
    subprocess.run([sys.executable, "-c", write], check=True)
    read = (
        "import json\n"
        "from iotaudit.capture import Collector, from_pcap\n"
        "c = from_pcap(%r, Collector(['192.0.2.10']))\n"
        "print(json.dumps(len(c.flows) + len(c.lan_flows)))\n" % str(pcap)
    )
    out = subprocess.run([sys.executable, "-c", read], check=True,
                         capture_output=True, text=True)
    assert "unknown LL type" not in out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == 1
