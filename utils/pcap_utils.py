from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6

from collections import defaultdict


def extract_email_sessions(packets):
    """Group packets by TCP stream and protocol"""
    sessions = defaultdict(list)

    for p in packets:
        try:
            # Check required layers exist
            if not (TCP in p and (IP in p or IPv6 in p)):
                continue

            # Get network layers
            ip = p[IP] if IP in p else p[IPv6]
            tcp = p[TCP]

            # Determine protocol by port
            if tcp.sport in {25, 587, 465} or tcp.dport in {25, 587, 465}:
                protocol = 'smtp'
            elif tcp.sport in {110, 995} or tcp.dport in {110, 995}:
                protocol = 'pop'
            elif tcp.sport in {143, 993} or tcp.dport in {143, 993}:
                protocol = 'imap'
            else:
                continue

            # Create session key (client->server)
            if tcp.sport < tcp.dport:  # Client port is usually higher
                key = (ip.src, ip.dst, tcp.sport, tcp.dport, protocol)
            else:
                key = (ip.dst, ip.src, tcp.dport, tcp.sport, protocol)

            sessions[key].append(p)

        except Exception:
            continue

    return [{'protocol': k[4], 'packets': v} for k, v in sessions.items()]
