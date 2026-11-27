from collections import Counter
from ingest.topology_parser import parse_flows
from core.graph_builder import build_graph

topo = parse_flows(r"C:\Users\arnav\OneDrive\Desktop\attack-graph-tool\attack-graph-tool\TrafficLabelling\Wednesday-workingHours.pcap_ISCX.csv", min_flows=5, max_rows=50000)
print(len(topo.hosts), "hosts,", len(topo.links), "links")

internal = {ip: h for ip, h in topo.hosts.items() if h.internal}
print(len(internal), "internal hosts")
for ip, h in sorted(internal.items()):
    print(ip, h.services)

labels = Counter()
for link in topo.links.values():
    labels.update(link.labels)
print(labels)

g = build_graph(topo)
print(g.number_of_nodes(), "nodes,", g.number_of_edges(), "edges")
for src, dst, key, d in g.edges(keys=True, data=True):
    if d["attack_flows"]:
        print(src, "->", dst, key, d["labels"])

from core.risk_scorer import rank_paths, format_path

for p in rank_paths(g, top_n=10):
    print(format_path(p))