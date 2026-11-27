"""Score and rank attack paths using CVSS values."""

"""Find and rank attack paths through the graph from core.graph_builder.

How a path is scored (all heuristic, tune the tables below):
  edge score   = max(service weight, best CVSS on that service), x1.5 if attack traffic
                 was actually observed on it, capped at 10
  likelihood   = product of (edge score / 10) along the path, so longer paths fade
  path risk    = likelihood x asset value of the target host (0-10)

Until real CVEs are attached (Nmap step), the service weights drive the scores.
When an edge has vulns, its CVSS score takes over automatically.
"""
from dataclasses import dataclass, field
from itertools import islice

import networkx as nx

from core.graph_builder import INTERNET

# How attractive/dangerous a service is to attack (0-10). Judgement calls, not measurements.
SERVICE_WEIGHT = {
    "telnet": 8, "smb": 8, "rdp": 8, "ftp": 7, "msrpc": 6, "netbios-ssn": 6,
    "mysql": 6, "mssql": 6, "postgresql": 6, "ldap": 6, "ldap-gc": 6,
    "ssh": 5, "kerberos": 5, "smtp": 4, "http": 4, "http-alt": 4,
    "https": 3, "dns": 3, "ntp": 2, "netbios-ns": 2, "netbios-dgm": 2,
}
DEFAULT_SERVICE_WEIGHT = 3

# How much a host is worth to an attacker (0-10), judged by what it serves.
ASSET_VALUE = {
    "kerberos": 10, "ldap": 10, "ldap-gc": 10,          # looks like a domain controller
    "mysql": 9, "mssql": 9, "postgresql": 9,             # databases
    "smb": 7, "rdp": 7,
}
DEFAULT_ASSET_VALUE = 5
ATTACK_BOOST = 1.5


@dataclass
class AttackPath:
    nodes: list
    steps: list                      # one dict per hop
    likelihood: float
    target_value: float
    risk: float
    observed_attack: bool = False


def edge_score(data: dict) -> float:
    base = SERVICE_WEIGHT.get(data.get("service"), DEFAULT_SERVICE_WEIGHT)
    cvss = max((v.get("cvss_score") or 0 for v in data.get("vulns", [])), default=0)
    score = max(base, cvss)
    if data.get("attack_flows", 0) > 0:
        score *= ATTACK_BOOST
    return min(score, 10.0)


def asset_value(services: dict) -> float:
    if not services:
        return 0.0
    return float(max(ASSET_VALUE.get(name, DEFAULT_ASSET_VALUE) for name in services.values()))


def entry_points(g: nx.MultiDiGraph) -> set:
    """The Internet node plus every host seen sending attack traffic."""
    return {n for n, d in g.nodes(data=True)
            if n == INTERNET or d.get("observed_attacker")}


def _best_step_graph(g: nx.MultiDiGraph) -> nx.DiGraph:
    """Collapse parallel edges: between two hosts, keep the easiest service to use."""
    d = nx.DiGraph()
    d.add_nodes_from(g.nodes)
    for u, v, key, data in g.edges(keys=True, data=True):
        score = edge_score(data)
        if not d.has_edge(u, v) or score > d[u][v]["score"]:
            d.add_edge(u, v, score=score, key=key, service=data.get("service"),
                       port=data.get("port"), attack_flows=data.get("attack_flows", 0),
                       vulns=data.get("vulns", []))
    return d


def rank_paths(g: nx.MultiDiGraph, targets: dict | None = None, max_hops: int = 4,
               top_n: int = 10, max_paths: int = 10000) -> list[AttackPath]:
    """Rank paths from every entry point to every target, highest risk first.

    targets: optional {host_ip: value} to override automatic asset values.
    Default targets are all non-entry hosts that expose at least one service.
    """
    entries = entry_points(g)
    if targets is None:
        targets = {n: asset_value(d["services"]) for n, d in g.nodes(data=True)
                   if n not in entries and d.get("services")}
    steps_graph = _best_step_graph(g)

    seen, results = set(), []
    for entry in entries:
        for target, value in targets.items():
            if target == entry or target not in steps_graph:
                continue
            paths = nx.all_simple_paths(steps_graph, entry, target, cutoff=max_hops)
            for nodes in islice(paths, max_paths):
                key = tuple(nodes)
                if key in seen:
                    continue
                seen.add(key)
                steps = [{"src": a, "dst": b, **steps_graph[a][b]}
                         for a, b in zip(nodes, nodes[1:])]
                likelihood = 1.0
                for s in steps:
                    likelihood *= s["score"] / 10
                results.append(AttackPath(
                    nodes=nodes, steps=steps, likelihood=likelihood, target_value=value,
                    risk=likelihood * value,
                    observed_attack=any(s["attack_flows"] > 0 for s in steps)))
    results.sort(key=lambda p: (-p.risk, len(p.nodes)))
    return results[:top_n]


def format_path(p: AttackPath) -> str:
    parts = [p.nodes[0]]
    for s in p.steps:
        tag = f"{s['service']}/{s['port']}"
        if s["attack_flows"]:
            tag += f", {s['attack_flows']} attack flows"
        if s["vulns"]:
            tag += f", {len(s['vulns'])} CVEs"
        parts.append(f"--[{tag}]--> {s['dst']}")
    return f"risk {p.risk:.2f} (likelihood {p.likelihood:.2f} x value {p.target_value:g})  " + " ".join(parts)