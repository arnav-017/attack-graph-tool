"""Build the NetworkX attack graph from hosts, links and matched CVEs."""

"""Build the attack graph (NetworkX MultiDiGraph) from a Topology.

Nodes : internal hosts, plus one collapsed "Internet" node for every public IP.
Edges : "src can reach a service on dst" = observed inbound / lateral traffic to a
        named service port. Each edge carries flow counts, dataset labels, how many
        flows were attacks, and any CVEs attached to that service.

Not edges: traffic going out to the Internet (that is a client browsing, not an attack path).

CICIDS has no software versions, so `vulns` stays empty until Nmap data is added.
Pass vulns={(host_ip, port): [cve_dict, ...]} to attach CVEs.
"""
import networkx as nx

from core.models import Topology

INTERNET = "Internet"


def attack_sources(topo: Topology) -> set:
    """IPs that sent at least one non-BENIGN flow (detected from labels, not hard-coded)."""
    return {l.src for l in topo.links.values()
            if any(lbl.upper() != "BENIGN" for lbl in l.labels)}


def build_graph(topo: Topology, vulns: dict | None = None,
                include_unknown: bool = False) -> nx.MultiDiGraph:
    vulns = vulns or {}
    attackers = attack_sources(topo)

    # 1. aggregate links into candidate edges
    edges = {}
    for link in topo.links.values():
        dst = topo.hosts[link.dst]
        if not dst.internal or link.src == link.dst:
            continue                                   # outbound or self traffic
        name = dst.services.get(link.dst_port)
        if name is None or (name == "unknown" and not include_unknown):
            continue
        src_node = link.src if topo.hosts[link.src].internal else INTERNET
        e = edges.setdefault((src_node, link.dst, link.dst_port, link.protocol),
                             {"service": name, "flows": 0, "attack_flows": 0, "labels": {}})
        e["flows"] += link.flows
        for label, count in link.labels.items():
            e["labels"][label] = e["labels"].get(label, 0) + count
            if label.upper() != "BENIGN":
                e["attack_flows"] += count

    # 2. build the graph
    g = nx.MultiDiGraph()

    def add_node(n):
        if n in g:
            return
        if n == INTERNET:
            g.add_node(n, kind="internet", services={}, observed_attacker=False)
        else:
            g.add_node(n, kind="host", services=dict(topo.hosts[n].services),
                       observed_attacker=n in attackers)

    for (src, dst, port, proto), e in edges.items():
        add_node(src)
        add_node(dst)
        g.add_edge(src, dst, key=f"{port}/{proto}", port=port, protocol=proto,
                   vulns=vulns.get((dst, port), []), **e)
    return g