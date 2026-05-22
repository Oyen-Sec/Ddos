"""
NOIR PROJECT v6.0 - JA4/JA3+ Fingerprint Spoofing Engine
Replicates TLS handshake, ALPN, and cipher suites like real 2026 browsers
"""
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class TLSProfile:
    """TLS fingerprint profile matching real browsers"""
    name: str
    ja3: str
    ja4: str
    alpn: List[str]
    ciphers: List[int]
    extensions: List[int]
    curves: List[int]
    ec_point_formats: List[int]
    sig_algs: List[int]
    tls_version: int
    impersonate: str

# Chrome 136 TLS Profile
CHROME_136_TLS = TLSProfile(
    name="chrome136",
    ja3="771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-65037-27-51-13-43-5-18-17513-65281-23-10-45-35-11-16,29-23-24-25-256-257,0",
    ja4="t13d1516h2_8daaf6152771_b1ff852e8b9c",
    alpn=["h2", "http/1.1"],
    ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
    extensions=[0, 0xfe0d, 0x001b, 0x0033, 0x000d, 0x002b, 0x0012, 0x4489, 0xfe0d, 0x0017, 0x000a, 0x002d, 0x0023, 0x000b, 0x0010, 0x0005],
    curves=[0x001d, 0x0017, 0x0018, 0x0100],
    ec_point_formats=[0],
    sig_algs=[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    tls_version=0x0304,
    impersonate="chrome134",
)

# Firefox 140 TLS Profile
FIREFOX_140_TLS = TLSProfile(
    name="firefox140",
    ja3="771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24,0",
    ja4="t13d1517h2_8daaf6152771_b1ff852e8b9c",
    alpn=["h2", "http/1.1"],
    ciphers=[0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
    extensions=[0, 0x0017, 0xfe0d, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0xfe0d],
    curves=[0x1d, 0x17, 0x18],
    ec_point_formats=[0],
    sig_algs=[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
    tls_version=0x0304,
    impersonate="firefox133",
)

# Safari 18 TLS Profile
SAFARI_18_TLS = TLSProfile(
    name="safari18",
    ja3="771,4865-4866-4867-49196-49195-52393-49200-49199-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-17513-21,29-23-24-25,0",
    ja4="t13d1516h2_8daaf6152771_b1ff852e8b9c",
    alpn=["h2", "http/1.1"],
    ciphers=[0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f],
    extensions=[0, 0x0017, 0xfe0d, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002b, 0x002d, 0x001b, 0x4489, 0x0015],
    curves=[0x1d, 0x17, 0x18, 0x19],
    ec_point_formats=[0],
    sig_algs=[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
    tls_version=0x0304,
    impersonate="safari17_0",
)

# Edge 136 TLS Profile
EDGE_136_TLS = TLSProfile(
    name="edge136",
    ja3="771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-65037-27-51-13-43-5-18-17513-65281-23-10-45-35-11-16,29-23-24-25-256-257,0",
    ja4="t13d1516h2_8daaf6152771_b1ff852e8b9c",
    alpn=["h2", "http/1.1"],
    ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
    extensions=[0, 0xfe0d, 0x001b, 0x0033, 0x000d, 0x002b, 0x0012, 0x4489, 0xfe0d, 0x0017, 0x000a, 0x002d, 0x0023, 0x000b, 0x0010, 0x0005],
    curves=[0x001d, 0x0017, 0x0018, 0x0100],
    ec_point_formats=[0],
    sig_algs=[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    tls_version=0x0304,
    impersonate="chrome134",
)

# Registry of TLS profiles
TLS_PROFILES = {
    "chrome136": CHROME_136_TLS,
    "firefox140": FIREFOX_140_TLS,
    "safari18": SAFARI_18_TLS,
    "edge136": EDGE_136_TLS,
}

# curl_cffi impersonate mapping (updated for 2026)
CURL_IMPERSONATE_MAP = {
    "chrome136": "chrome136",
    "firefox140": "firefox144",
    "safari18": "safari180",
    "edge136": "chrome136",
}


def get_tls_profile(browser: str = "chrome136") -> TLSProfile:
    """Get TLS profile for specified browser"""
    return TLS_PROFILES.get(browser, CHROME_136_TLS)


def get_curl_impersonate(browser: str = "chrome136") -> str:
    """Get curl_cffi impersonate string for browser"""
    return CURL_IMPERSONATE_MAP.get(browser, "chrome134")


def get_random_browser() -> str:
    """Get random browser profile"""
    return random.choice(list(TLS_PROFILES.keys()))
