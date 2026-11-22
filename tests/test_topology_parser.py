import pytest

from ingest.topology_parser import parse_flows

HEADER = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Label"
# Rows adapted from real CICIDS2017 (Wednesday) output; middle feature columns omitted.
ROWS = """\
192.168.10.3-192.168.10.17-88-46124-6,192.168.10.17,46124,192.168.10.3,88,6,5/7/2017 8:42,BENIGN
192.168.10.3-192.168.10.17-389-49454-6,192.168.10.17,49454,192.168.10.3,389,6,5/7/2017 8:42,BENIGN
192.168.10.3-192.168.10.17-88-46126-6,192.168.10.17,46126,192.168.10.3,88,6,5/7/2017 8:42,BENIGN
192.168.10.3-192.168.10.17-389-49460-6,192.168.10.17,49460,192.168.10.3,389,6,5/7/2017 8:42,BENIGN
192.168.10.3-192.168.10.17-88-46131-6,192.168.10.17,46131,192.168.10.3,88,6,5/7/2017 8:42,BENIGN
192.168.10.16-91.189.88.161-37380-80-6,192.168.10.16,37380,91.189.88.161,80,6,5/7/2017 8:42,BENIGN
192.168.10.3-192.168.10.15-49666-49413-6,192.168.10.15,49413,192.168.10.3,49666,6,5/7/2017 8:42,BENIGN
"""


@pytest.fixture
def csv_path(tmp_path):
    p = tmp_path / "flows.csv"
    p.write_text(HEADER + "\n" + ROWS)
    return p


def test_hosts_and_internal_flag(csv_path):
    topo = parse_flows(csv_path)
    assert set(topo.hosts) == {"192.168.10.3", "192.168.10.15", "192.168.10.16",
                               "192.168.10.17", "91.189.88.161"}
    assert topo.hosts["192.168.10.3"].internal is True
    assert topo.hosts["91.189.88.161"].internal is False


def test_services_inferred_from_destination_ports(csv_path):
    dc = parse_flows(csv_path).hosts["192.168.10.3"]
    assert dc.services[88] == "kerberos" and dc.services[389] == "ldap"
    assert dc.services[49666] == "unknown"


def test_links_are_aggregated(csv_path):
    link = parse_flows(csv_path).links[("192.168.10.17", "192.168.10.3", 88, "tcp")]
    assert link.flows == 3 and link.labels == {"BENIGN": 3}


def test_min_flows_filters_noise(csv_path):
    topo = parse_flows(csv_path, min_flows=3)
    assert list(topo.hosts["192.168.10.3"].services) == [88]
    assert len(topo.links) == 1


def test_missing_column_gives_clear_error(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("a,b,c\n1,2,3\n")
    with pytest.raises(ValueError, match="Missing columns"):
        parse_flows(p)


def test_broadcast_icmp_and_netbios(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text(HEADER + "\n"
                 "a,192.168.10.12,137,192.168.10.255,137,17,t,BENIGN\n"
                 "b,192.168.10.3,0,192.168.10.8,0,1,t,BENIGN\n"
                 "c,192.168.10.12,137,192.168.10.3,137,17,t,BENIGN\n")
    topo = parse_flows(p)
    assert "192.168.10.255" not in topo.hosts
    assert topo.hosts["192.168.10.8"].services == {}
    assert topo.hosts["192.168.10.3"].services == {137: "netbios-ns"}