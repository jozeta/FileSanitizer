import ipaddress
import socket
import urllib.parse
from typing import Tuple, List, Optional
from app.core.logging_config import logger

# Blocked IP networks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (including 169.254.169.254 Cloud Metadata)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-Use (RFC 1918 / Docker networks)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

def is_ip_blocked(ip: ipaddress.IPv4Address or ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any private, loopback, or cloud metadata network."""
    # Convert IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) to IPv4
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return True

    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True

    return False

def validate_url_for_ssrf(url_str: str) -> Tuple[bool, Optional[str], Optional[List[str]]]:
    """
    Validate a destination URL to prevent Server-Side Request Forgery (SSRF).
    Resolves DNS and asserts that none of the resolved IPs are in forbidden ranges.
    Returns: (is_safe, error_reason, resolved_ips)
    """
    try:
        parsed = urllib.parse.urlparse(url_str)
        if parsed.scheme.lower() not in ["http", "https"]:
            return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https are allowed.", None

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname in URL.", None

        # Check for numeric or localhost hostname directly
        if hostname.lower() in ["localhost", "127.0.0.1", "::1", "metadata.google.internal"]:
            return False, f"Forbidden local destination '{hostname}'.", None

        # Resolve DNS addresses
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError:
            return False, f"Invalid port in URL '{url_str}'.", None
        try:
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            return False, f"DNS resolution failed: {e}", None

        resolved_ips = []
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                resolved_ips.append(ip_str)
                if is_ip_blocked(ip_obj):
                    return False, f"Resolved IP {ip_str} belongs to a private/internal network (SSRF violation).", resolved_ips
            except ValueError:
                return False, f"Invalid IP address {ip_str} returned by DNS.", None

        if not resolved_ips:
            return False, "No IP addresses resolved for hostname.", None

        return True, None, resolved_ips

    except Exception as e:
        return False, f"URL validation error: {e}", None
