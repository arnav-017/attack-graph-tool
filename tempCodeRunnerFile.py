from ingest.topology_parser import parse_flows

topo = parse_flows(r"C:\Users\arnav\OneDrive\Desktop\attack-graph-tool\attack-graph-tool\TrafficLabelling\Wednesday-workingHours.pcap_ISCX.csv", min_flows=5, max_rows=50000)
print(len(topo.hosts), "hosts,", len(topo.links), "links")
for ip, h in list(topo.hosts.items())[:10]:
    print(ip, h.internal, h.services)
