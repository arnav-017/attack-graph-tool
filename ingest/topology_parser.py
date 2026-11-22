"""Turn CICIDS2017 'TrafficLabelling' flow CSVs into hosts, services and links.

Important: these CSVs record who talked to whom on which port. They do NOT record
software names or versions, so service names here are guesses from well-known ports.
Real versions arrive later via Nmap (see the roadmap).
"""
import csv
import ipaddress

from core.models import Host, Link, Topology

PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp"}

PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    88: "kerberos", 110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
    137: "netbios-ns", 138: "netbios-dgm", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 1433: "mssql", 3268: "ldap-gc", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 8080: "http-alt",
}

REQUIRED = ["Source IP", "Source Port", "Destination IP", "Destination Port",
            "Protocol", "Label"]


def _is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_broadcast(ip: str) -> bool:
    # Broadcast addresses are not real machines (heuristic: private x.x.x.255).
    return ip == "255.255.255.255" or (_is_internal(ip) and ip.endswith(".255"))


def parse_flows(path, min_flows: int = 1, max_rows: int | None = None) -> Topology:
    """Read one CICIDS flow CSV.

    min_flows: ignore src->dst:port links seen fewer times than this. Use 5 or more
               on real files to cut noise from scans and one-off connections.
    max_rows:  stop early (handy while developing on the large files).
    """
    all_hosts = set()
    links = {}

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = [h.strip() for h in next(reader)]   # real headers have leading spaces
        missing = [c for c in REQUIRED if c not in header]
        if missing:
            raise ValueError(f"Missing columns {missing}. First columns found: {header[:10]}")
        idx = {c: header.index(c) for c in REQUIRED}
        width = max(idx.values())

        for n, row in enumerate(reader):
            if max_rows is not None and n >= max_rows:
                break
            if len(row) <= width:
                continue
            try:
                dport = int(row[idx["Destination Port"]])
            except ValueError:
                continue
            src = row[idx["Source IP"]].strip()
            dst = row[idx["Destination IP"]].strip()
            if _is_broadcast(src) or _is_broadcast(dst):
                continue
            proto = PROTOCOLS.get(row[idx["Protocol"]].strip(), row[idx["Protocol"]].strip())
            label = row[idx["Label"]].strip()

            all_hosts.update((src, dst))
            key = (src, dst, dport, proto)
            link = links.get(key) or links.setdefault(key, Link(src, dst, dport, proto))
            link.flows += 1
            link.labels[label] = link.labels.get(label, 0) + 1

    topo = Topology(hosts={ip: Host(ip, _is_internal(ip)) for ip in all_hosts})
    for key, link in links.items():
        if link.flows < min_flows:
            continue
        topo.links[key] = link
        if link.dst_port != 0:                      # port 0 = ICMP, not a service
            topo.hosts[link.dst].services[link.dst_port] = PORT_NAMES.get(link.dst_port, "unknown")
    return topo