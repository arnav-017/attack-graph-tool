"""Host, Service, Vulnerability and Edge data classes."""
"""Plain data classes shared by the ingest and core layers."""
from dataclasses import dataclass, field


@dataclass
class Host:
    ip: str
    internal: bool                                  # private (RFC 1918) address?
    services: dict = field(default_factory=dict)    # port -> service name guess


@dataclass
class Link:
    """Aggregated traffic from src to dst:port."""
    src: str
    dst: str
    dst_port: int
    protocol: str
    flows: int = 0
    labels: dict = field(default_factory=dict)      # dataset label -> flow count


@dataclass
class Topology:
    hosts: dict = field(default_factory=dict)       # ip -> Host
    links: dict = field(default_factory=dict)       # (src, dst, port, proto) -> Link