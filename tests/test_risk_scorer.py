import pytest

from core.graph_builder import build_graph
from core.models import Host, Link, Topology
from core.risk_scorer import edge_score, entry_points, format_path, rank_paths

ATT, WEB, DC, DB, CLIENT = "172.16.0.1", "192.168.10.50", "192.168.10.3", "192.168.10.8", "192.168.10.17"


def make_graph(vulns=None):
    hosts = {
        ATT: Host(ATT, True),
        WEB: Host(WEB, True, {80: "http", 22: "ssh"}),
        DC: Host(DC, True, {88: "kerberos", 389: "ldap", 445: "smb"}),
        DB: Host(DB, True, {3306: "mysql"}),
        CLIENT: Host(CLIENT, True),
    }
    links = [
        Link(ATT, WEB, 80, "tcp", 100, {"DoS slowloris": 100}),
        Link(WEB, DC, 445, "tcp", 10, {"BENIGN": 10}),
        Link(WEB, DB, 3306, "tcp", 5, {"BENIGN": 5}),
        Link(CLIENT, DC, 88, "tcp", 5, {"BENIGN": 5}),       # not reachable from attacker
    ]
    topo = Topology(hosts, {(l.src, l.dst, l.dst_port, l.protocol): l for l in links})
    return build_graph(topo, vulns=vulns)


def test_entry_points():
    assert entry_points(make_graph()) == {ATT}


def test_edge_score_boost_and_cap():
    assert edge_score({"service": "http", "attack_flows": 0}) == 4
    assert edge_score({"service": "http", "attack_flows": 9}) == 6          # 4 x 1.5
    assert edge_score({"service": "smb", "attack_flows": 9}) == 10          # capped
    assert edge_score({"service": "http", "vulns": [{"cvss_score": 9.8}]}) == 9.8


def test_paths_ranked_by_risk():
    paths = rank_paths(make_graph())
    assert [p.nodes[-1] for p in paths] == [DC, DB, WEB]
    assert paths[0].nodes == [ATT, WEB, DC]
    assert paths[0].risk == pytest.approx(4.8)       # 0.6 x 0.8 x 10
    assert paths[1].risk == pytest.approx(3.24)      # 0.6 x 0.6 x 9
    assert paths[2].risk == pytest.approx(3.0)       # 0.6 x 5
    assert all(p.observed_attack for p in paths)


def test_unreachable_host_is_not_a_path():
    assert all(CLIENT not in p.nodes for p in rank_paths(make_graph()))


def test_cve_raises_path_risk():
    vulns = {(DC, 445): [{"cvss_score": 9.8}]}
    top = rank_paths(make_graph(vulns))[0]
    assert top.risk == pytest.approx(0.6 * 0.98 * 10)


def test_target_override_and_hop_limit():
    only_dc = rank_paths(make_graph(), targets={DC: 10})
    assert len(only_dc) == 1
    assert rank_paths(make_graph(), targets={DC: 10}, max_hops=1) == []


def test_format_path_mentions_attack_and_hops():
    text = format_path(rank_paths(make_graph())[0])
    assert ATT in text and DC in text and "100 attack flows" in text