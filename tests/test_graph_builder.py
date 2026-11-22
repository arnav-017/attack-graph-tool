from core.graph_builder import INTERNET, attack_sources, build_graph
from core.models import Host, Link, Topology


def make_topology():
    hosts = {
        "172.16.0.1": Host("172.16.0.1", True),
        "192.168.10.50": Host("192.168.10.50", True, {80: "http", 36522: "unknown"}),
        "192.168.10.3": Host("192.168.10.3", True, {88: "kerberos"}),
        "192.168.10.17": Host("192.168.10.17", True),
        "52.1.1.1": Host("52.1.1.1", False),
        "52.2.2.2": Host("52.2.2.2", False),
        "91.189.88.161": Host("91.189.88.161", False, {80: "http"}),
    }
    links = [
        Link("172.16.0.1", "192.168.10.50", 80, "tcp", 100, {"DoS slowloris": 100}),
        Link("172.16.0.1", "192.168.10.50", 36522, "tcp", 5, {"BENIGN": 5}),   # unknown port
        Link("192.168.10.17", "192.168.10.3", 88, "tcp", 5, {"BENIGN": 5}),
        Link("52.1.1.1", "192.168.10.50", 80, "tcp", 4, {"BENIGN": 4}),
        Link("52.2.2.2", "192.168.10.50", 80, "tcp", 3, {"BENIGN": 3}),
        Link("192.168.10.17", "91.189.88.161", 80, "tcp", 9, {"BENIGN": 9}),    # outbound
    ]
    return Topology(hosts, {(l.src, l.dst, l.dst_port, l.protocol): l for l in links})


def test_attack_sources_come_from_labels():
    assert attack_sources(make_topology()) == {"172.16.0.1"}


def test_nodes_collapse_external_and_skip_outbound():
    g = build_graph(make_topology())
    assert set(g.nodes) == {"172.16.0.1", "192.168.10.50", "192.168.10.3",
                            "192.168.10.17", INTERNET}
    assert g.nodes["172.16.0.1"]["observed_attacker"] is True
    assert g.nodes[INTERNET]["kind"] == "internet"


def test_internet_edge_sums_flows():
    g = build_graph(make_topology())
    assert g.edges[INTERNET, "192.168.10.50", "80/tcp"]["flows"] == 7


def test_attack_edge_and_unknown_ports():
    g = build_graph(make_topology())
    edge = g.edges["172.16.0.1", "192.168.10.50", "80/tcp"]
    assert edge["attack_flows"] == 100 and edge["service"] == "http"
    assert not g.has_edge("172.16.0.1", "192.168.10.50", "36522/tcp")
    assert build_graph(make_topology(), include_unknown=True).has_edge(
        "172.16.0.1", "192.168.10.50", "36522/tcp")


def test_vulns_attach_to_service_edge():
    cve = {"cve_id": "CVE-X", "cvss_score": 9.8}
    g = build_graph(make_topology(), vulns={("192.168.10.50", 80): [cve]})
    assert g.edges["172.16.0.1", "192.168.10.50", "80/tcp"]["vulns"] == [cve]
    assert g.edges["192.168.10.17", "192.168.10.3", "88/tcp"]["vulns"] == []