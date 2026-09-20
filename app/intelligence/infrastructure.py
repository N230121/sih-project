import ipaddress
import socket
from urllib.parse import urlparse


def extract_hostnames(urls):
    """
    Extract hostnames from URLs.
    """

    hostnames = set()

    for url in urls:

        try:
            parsed = urlparse(url)

            hostname = parsed.hostname

            if hostname:
                hostnames.add(
                    hostname.lower()
                )

        except Exception:
            continue

    return sorted(hostnames)


def is_public_ip(ip):
    """
    Return True only for publicly routable IP addresses.
    """

    try:
        address = ipaddress.ip_address(ip)

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_reserved
            and not address.is_multicast
        )

    except ValueError:
        return False


def resolve_hostname(hostname):
    """
    Resolve a hostname into IPv4 addresses.
    """

    try:

        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_INET
        )

        ips = set()

        for result in results:

            ip = result[4][0]

            if is_public_ip(ip):
                ips.add(ip)

        return sorted(ips)

    except Exception:
        return []
def extract_public_ips(urls):
    """
    Extract public IP infrastructure from email URLs.
    """

    hostnames = extract_hostnames(
        urls
    )

    infrastructure = []

    for hostname in hostnames:

        ips = resolve_hostname(
            hostname
        )

        for ip in ips:

            infrastructure.append({
                "hostname": hostname,
                "ip": ip,
            })

    return infrastructure