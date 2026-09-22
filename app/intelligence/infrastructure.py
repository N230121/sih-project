import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from ..config import INFRA_PROVIDER_API_KEY


# ---------------------------------------------------------
# BASIC HOST / IP UTILITIES
# ---------------------------------------------------------

def extract_hostnames(urls):
    """
    Extract unique hostnames from URLs.
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
    Resolve hostname into public IPv4 addresses.
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


# ---------------------------------------------------------
# IPINFO ENRICHMENT
# ---------------------------------------------------------

def enrich_ip_with_ipinfo(ip):
    """
    Enrich one public IP using IPinfo.

    The function intentionally normalizes the provider
    response into TraceMail's own infrastructure schema.
    """

    if not INFRA_PROVIDER_API_KEY:
        return None

    url = (
        f"https://ipinfo.io/{ip}/json"
        f"?token={INFRA_PROVIDER_API_KEY}"
    )

    try:

        response = httpx.get(
            url,
            timeout=8.0,
        )

        if response.status_code != 200:
            return None

        data = response.json()

        loc = data.get("loc", "")

        latitude = None
        longitude = None

        if loc and "," in loc:

            try:
                latitude, longitude = [
                    float(value.strip())
                    for value in loc.split(",", 1)
                ]
            except (ValueError, TypeError):
                latitude = None
                longitude = None

        as_data = data.get("as") or {}
        anonymous = data.get("anonymous") or {}

        return {
            "ip": ip,

            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),

            "latitude": latitude,
            "longitude": longitude,

            "asn": as_data.get("asn") or data.get("asn"),
            "organization": (
                as_data.get("name")
                or data.get("org")
            ),

            "isp": data.get("org"),

            "vpn": anonymous.get("is_vpn"),
            "proxy": anonymous.get("is_proxy"),
            "tor": anonymous.get("is_tor"),

            "provider": "ipinfo",

            "raw_json": data,
        }

    except Exception:
        return None


# ---------------------------------------------------------
# IPAPI FALLBACK ENRICHMENT
# ---------------------------------------------------------

def enrich_ip_with_ipapi(ip):
    """
    Fallback geolocation provider.

    Used when IPinfo is unavailable or does not return
    usable infrastructure information.
    """

    url = f"https://ipapi.co/{ip}/json/"

    try:

        response = httpx.get(
            url,
            timeout=8.0,
        )

        if response.status_code != 200:
            return None

        data = response.json()

        return {
            "ip": ip,

            "country": (
                data.get("country_name")
                or data.get("country")
            ),

            "region": data.get("region"),
            "city": data.get("city"),

            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),

            "asn": data.get("asn"),

            "organization": data.get("org"),

            "isp": data.get("org"),

            # ipapi does not provide the same privacy
            # fields we want from IPinfo.
            "vpn": None,
            "proxy": None,
            "tor": None,

            "provider": "ipapi",

            "raw_json": data,
        }

    except Exception:
        return None


# ---------------------------------------------------------
# UNIFIED ENRICHMENT
# ---------------------------------------------------------

def enrich_ip(ip):
    """
    Enrich one public IP.

    Provider order:

    1. IPinfo
    2. ipapi fallback
    """

    if not is_public_ip(ip):
        return None

    result = enrich_ip_with_ipinfo(ip)

    if result:
        return result

    return enrich_ip_with_ipapi(ip)


# ---------------------------------------------------------
# URL → HOSTNAME → IP → INTELLIGENCE
# ---------------------------------------------------------

def extract_infrastructure(urls):
    """
    Convert email URLs into enriched infrastructure records.

    Example:

        URL
         ↓
        hostname
         ↓
        public IP
         ↓
        geolocation / ASN / privacy
    """

    hostnames = extract_hostnames(urls)

    infrastructure = []

    for hostname in hostnames:

        ips = resolve_hostname(
            hostname
        )

        for ip in ips:

            enrichment = enrich_ip(ip)

            if enrichment:

                infrastructure.append({
                    "hostname": hostname,
                    **enrichment,
                })

            else:

                infrastructure.append({
                    "hostname": hostname,
                    "ip": ip,

                    "country": None,
                    "region": None,
                    "city": None,

                    "latitude": None,
                    "longitude": None,

                    "asn": None,
                    "isp": None,
                    "organization": None,

                    "vpn": None,
                    "proxy": None,
                    "tor": None,

                    "provider": "dns_resolution",
                    "raw_json": None,
                })

    return infrastructure


# ---------------------------------------------------------
# BACKWARD COMPATIBILITY
# ---------------------------------------------------------

def extract_public_ips(urls):
    """
    Backward-compatible wrapper.

    Existing TraceMail code can continue calling
    extract_public_ips() while receiving enriched
    infrastructure information.
    """

    return extract_infrastructure(urls)