"""
Proxy Tier Detection v1.0
Detects proxy tier (mobile, residential, ipv6, datacenter) from IP characteristics.
Uses ASN lookup via ip-api.com (free, no auth, 45 req/min limit).
"""
import socket
import ipaddress
import logging
import asyncio
from typing import Optional, Tuple

logger = logging.getLogger("tier_detection")

# Common datacenter / cloud ASNs
DATACENTER_ASNS = {
    "AS16509", "AS14618",  # AWS
    "AS15169",             # Google Cloud
    "AS8075",              # Microsoft Azure
    "AS14061",             # DigitalOcean
    "AS16276",             # OVH
    "AS24940",             # Hetzner
    "AS63949",             # Linode/Akamai
    "AS20473",             # Choopa/Vultr
    "AS9009",              # M247
    "AS46606",             # Unified Layer
    "AS396982",            # Google
    "AS6939",              # Hurricane Electric
    "AS13335",             # Cloudflare
    "AS54113",             # Fastly
    "AS54994", "AS62240",  # Cloud providers
    "AS19551",             # InCapsula
    "AS200052",            # Maxihost
    "AS35540",             # NetCup
    "AS49981",             # WorldStream
}

# Mobile carrier ASN patterns
MOBILE_ASN_KEYWORDS = [
    "t-mobile", "verizon", "at&t", "att-mobility", "sprint",
    "vodafone", "orange", "telefonica", "china mobile", "china unicom",
    "ntt docomo", "softbank", "kddi", "telkomsel", "indosat",
    "axiata", "celcom", "digi", "u mobile", "maxis",
    "telstra", "optus", "vodafone hutchison",
]

# Residential ISP keywords
RESIDENTIAL_ASN_KEYWORDS = [
    "comcast", "spectrum", "charter", "cox", "centurylink",
    "frontier", "windstream", "cable", "telecom", "broadband",
    "fios", "uverse", "xfinity", "btnet", "deutsche telekom",
    "kpn", "ziggo", "telenor", "telia", "swisscom",
    "telkom", "biznet", "first media",
]

# Cloud provider keywords
CLOUD_KEYWORDS = [
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
    "linode", "ovh", "hetzner", "vultr", "scaleway", "alibaba",
    "tencent", "akamai", "cloudflare", "fastly", "incapsula",
    "leaseweb", "psychz", "hostwinds", "contabo", "datacamp",
]


def is_ipv6_address(host: str) -> bool:
    """Check if host is IPv6 address."""
    try:
        return ":" in host and ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def classify_asn(asn_info: dict) -> str:
    """
    Classify proxy tier from ASN info.
    Returns: 'mobile', 'residential', 'ipv6', or 'datacenter'.
    """
    if not asn_info:
        return "datacenter"

    asn = (asn_info.get("as") or "").lower()
    isp = (asn_info.get("isp") or "").lower()
    org = (asn_info.get("org") or "").lower()
    mobile = asn_info.get("mobile", False)
    hosting = asn_info.get("hosting", False)
    proxy = asn_info.get("proxy", False)

    combined = f"{asn} {isp} {org}".lower()

    # Mobile detection (strongest signal)
    if mobile:
        return "mobile"
    if any(kw in combined for kw in MOBILE_ASN_KEYWORDS):
        return "mobile"

    # Datacenter / hosting (cloud) detection
    if hosting:
        return "datacenter"
    if any(kw in combined for kw in CLOUD_KEYWORDS):
        return "datacenter"

    # Check ASN against known datacenter list
    asn_num = asn.split()[0].upper() if asn else ""
    if asn_num in DATACENTER_ASNS:
        return "datacenter"

    # Residential ISP keywords
    if any(kw in combined for kw in RESIDENTIAL_ASN_KEYWORDS):
        return "residential"

    # Default fallback
    return "datacenter"


async def lookup_asn(ip: str, timeout: int = 5) -> Optional[dict]:
    """
    Lookup ASN info from ip-api.com (free, 45 req/min).
    Returns dict with: country, isp, org, as, mobile, hosting, proxy, etc.
    """
    try:
        import aiohttp
        url = f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as,asname,mobile,proxy,hosting"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        return data
    except Exception as e:
        logger.debug(f"ASN lookup failed for {ip}: {e}")
    return None


async def detect_proxy_tier(proxy_url: str, external_ip: Optional[str] = None) -> str:
    """
    Detect proxy tier from URL + optional external IP.
    Order:
    1. IPv6 detection (from URL host)
    2. ASN lookup (if external_ip provided or resolvable)
    3. Fallback to 'datacenter'
    """
    from urllib.parse import urlparse
    parsed = urlparse(proxy_url)
    host = parsed.hostname or ""

    # IPv6 check
    if is_ipv6_address(host):
        return "ipv6"

    # If external IP available (from validation), use it for ASN lookup
    target_ip = external_ip
    if not target_ip:
        try:
            target_ip = socket.gethostbyname(host)
        except Exception:
            return "datacenter"

    # Skip private IPs
    try:
        ip_obj = ipaddress.ip_address(target_ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "datacenter"
    except ValueError:
        return "datacenter"

    asn_info = await lookup_asn(target_ip)
    if asn_info:
        return classify_asn(asn_info)
    return "datacenter"
