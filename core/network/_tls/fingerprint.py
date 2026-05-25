"""
TLS Fingerprint Spoofing Module
Implements JA3/JA4 randomization and cipher suite diversification
UPDATED: 2026-05-25 - Latest browser versions + HTTP/2 impersonation integration
"""
import hashlib
import random
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple

from core.network.http2_impersonator import (
    H2ConnectionManager,
    create_h2_connection,
    get_browser_settings,
    get_random_profile as get_h2_profile,
)

# ── TLS Profile Cross-Reference ─────────────────────────────────────────────
# Maps HTTP/2 profile names to their corresponding TLS cipher profiles
TLS_TO_H2_PROFILE = {
    "chrome124": "chrome126",
    "chrome126": "chrome126",
    "firefox125": "firefox130",
    "firefox130": "firefox130",
    "safari17": "safari17.4",
    "safari17.4": "safari17.4",
    "edge124": "edge126",
    "edge126": "edge126",
    "opera110": "opera110",
    "brave126": "brave126",
}

H2_TO_TLS_PROFILE = {v: k for k, v in TLS_TO_H2_PROFILE.items()}

# ── Cipher Suites ───────────────────────────────────────────────────────────
CIPHER_SUITES = {
    "chrome124": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ],
    "chrome126": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ],
    "firefox125": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ],
    "firefox130": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ],
    "safari17": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ],
    "safari17.4": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ],
    "edge124": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
    ],
    "edge126": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
    ],
    "opera110": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ],
    "brave126": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ],
}

TLS_VERSIONS = {
    "chrome124": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "chrome126": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "firefox125": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "firefox130": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "safari17": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "safari17.4": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "edge124": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "edge126": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "opera110": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "brave126": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
}

ALPN_PROTOCOLS = {
    "chrome124": ["h2", "http/1.1"],
    "chrome126": ["h2", "http/1.1"],
    "firefox125": ["h2", "http/1.1"],
    "firefox130": ["h2", "http/1.1"],
    "safari17": ["h2", "http/1.1"],
    "safari17.4": ["h2", "http/1.1"],
    "edge124": ["h2", "http/1.1"],
    "edge126": ["h2", "http/1.1"],
    "opera110": ["h2", "http/1.1"],
    "brave126": ["h2", "http/1.1"],
}

# ── JA4 Support: Extension & Curve Maps ─────────────────────────────────────
# TLS extension IDs commonly seen in browser Client Hellos
TLS_EXTENSIONS = {
    "chrome126": [0, 1, 13, 14, 15, 16, 21, 23, 27, 28, 35, 43, 45, 51, 65281],
    "firefox130": [0, 1, 13, 14, 15, 16, 21, 23, 27, 35, 43, 44, 45, 51, 65281],
    "safari17.4": [0, 1, 13, 14, 15, 16, 21, 23, 27, 35, 43, 45, 51, 65281],
    "edge126": [0, 1, 13, 14, 15, 16, 21, 23, 27, 28, 35, 43, 45, 51, 65281],
    "opera110": [0, 1, 13, 14, 15, 16, 21, 23, 27, 28, 35, 43, 45, 51, 65281],
    "brave126": [0, 1, 13, 14, 15, 16, 21, 23, 27, 28, 35, 43, 45, 51, 65281],
}

# Supported groups (curves)
SUPPORTED_GROUPS = {
    "chrome126": ["x25519", "secp256r1", "secp384r1"],
    "firefox130": ["x25519", "secp256r1", "secp384r1"],
    "safari17.4": ["x25519", "secp256r1", "secp384r1"],
    "edge126": ["x25519", "secp256r1", "secp384r1"],
    "opera110": ["x25519", "secp256r1", "secp384r1"],
    "brave126": ["x25519", "secp256r1", "secp384r1"],
}

# Signature algorithms
SIGNATURE_ALGORITHMS = {
    "chrome126": [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ],
    "firefox130": [
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "rsa_pkcs1_sha384",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ],
    "safari17.4": [
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "rsa_pkcs1_sha384",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ],
    "edge126": [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ],
    "opera110": [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ],
    "brave126": [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ],
}

# ── Default fallback for profiles without explicit extension/curve maps ─────
_DEFAULT_EXTENSIONS = [0, 1, 13, 14, 15, 16, 21, 23, 27, 35, 43, 45, 51, 65281]
_DEFAULT_GROUPS = ["x25519", "secp256r1", "secp384r1"]
_DEFAULT_SIG_ALGS = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
]

# ── Profile name translations for JA4 lookups ───────────────────────────────
_JA4_PROFILE_LOOKUP = {
    "chrome124": "chrome126",
    "chrome126": "chrome126",
    "firefox125": "firefox130",
    "firefox130": "firefox130",
    "safari17": "safari17.4",
    "safari17.4": "safari17.4",
    "edge124": "edge126",
    "edge126": "edge126",
    "opera110": "opera110",
    "brave126": "brave126",
}


def _resolve_ja4_profile(profile: str) -> str:
    return _JA4_PROFILE_LOOKUP.get(profile, profile)


class TLSFingerprintGenerator:
    """Generate randomized TLS fingerprints per connection"""

    def __init__(self):
        self.browser_profiles = list(CIPHER_SUITES.keys())

    def get_random_profile(self) -> str:
        """Select random browser profile"""
        return random.choice(self.browser_profiles)

    def get_ssl_context(self, profile: Optional[str] = None) -> Tuple[ssl.SSLContext, str]:
        """
        Create SSL context with randomized cipher suites
        Mimics real browser TLS fingerprint
        Returns: (ssl_context, profile_name) for cross-validation with headers
        """
        if profile is None:
            profile = self.get_random_profile()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if profile in TLS_VERSIONS:
            min_ver, max_ver = TLS_VERSIONS[profile]
            context.minimum_version = min_ver
            context.maximum_version = max_ver

        if profile in CIPHER_SUITES:
            ciphers = CIPHER_SUITES[profile].copy()
            if len(ciphers) >= 3:
                first_three = ciphers[:3]
                random.shuffle(first_three)
                ciphers[:3] = first_three
            try:
                context.set_ciphers(":".join(ciphers))
            except ssl.SSLError:
                pass

        if profile in ALPN_PROTOCOLS:
            context.set_alpn_protocols(ALPN_PROTOCOLS[profile])

        return context, profile

    def get_ja3_string(self, profile: Optional[str] = None) -> str:
        """
        Generate JA3 fingerprint string (for logging/debugging)
        Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        """
        if profile is None:
            profile = self.get_random_profile()

        ssl_ver = "771"
        ciphers = CIPHER_SUITES.get(profile, CIPHER_SUITES["chrome126"])
        cipher_ids = ",".join([str(hash(c) % 10000) for c in ciphers[:5]])
        extensions = "0-10-11-13-23-35-65281"
        curves = "29-23-24"
        point_formats = "0"

        return f"{ssl_ver},{cipher_ids},{extensions},{curves},{point_formats}"

    def get_combined_fingerprint(self, profile_name: str) -> Dict[str, Any]:
        """
        Return a dict with BOTH TLS and HTTP/2 settings for the given profile.
        Cross-references TLS profile ↔ HTTP/2 profile automatically.
        """
        h2_prof = TLS_TO_H2_PROFILE.get(profile_name, profile_name)
        tls_prof = H2_TO_TLS_PROFILE.get(profile_name, profile_name)

        tls_ciphers = CIPHER_SUITES.get(tls_prof, [])
        tls_vers = TLS_VERSIONS.get(tls_prof, (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3))
        tls_alpn = ALPN_PROTOCOLS.get(tls_prof, ["h2", "http/1.1"])

        h2_settings_raw = {}
        try:
            h2_settings_raw = get_browser_settings(h2_prof)
        except KeyError:
            pass

        return {
            "profile": profile_name,
            "tls_profile": tls_prof,
            "h2_profile": h2_prof,
            "tls": {
                "ciphers": tls_ciphers,
                "min_version": str(tls_vers[0]),
                "max_version": str(tls_vers[1]),
                "alpn": tls_alpn,
            },
            "h2": h2_settings_raw,
        }

    def create_tls_and_h2_session(self, sock: Any, profile_name: str) -> Tuple[ssl.SSLContext, H2ConnectionManager]:
        """
        Creates a TLS context wrapping *sock*, then initiates HTTP/2
        over the TLS-wrapped socket using the given *profile_name*.

        Returns (ssl_context, h2_manager).
        """
        context, _ = self.get_ssl_context(
            H2_TO_TLS_PROFILE.get(profile_name, profile_name)
        )
        tls_sock = context.wrap_socket(
            sock, server_hostname="",
            do_handshake_on_connect=False,
        )
        tls_sock.do_handshake()

        h2_manager = create_h2_connection(profile_name, tls_sock)
        return context, h2_manager

    def get_ja4_string(self, profile: Optional[str] = None) -> str:
        """
        Generate JA4 fingerprint string.

        JA4 format (simplified, RFC-like):
          tls_version + cipher_count + alpn + extension_count + curves + signature_algorithm

        Full JA4 uses raw-sha256 of extension/curve/sig-alg lists;
        this implementation mirrors that pattern.
        """
        if profile is None:
            profile = self.get_random_profile()

        ja4_prof = _resolve_ja4_profile(profile)

        # tls_version: "t13" for TLS 1.3 capable
        tls_ver = "t13"

        # cipher_count: hex digit of cipher count
        ciphers = CIPHER_SUITES.get(ja4_prof, CIPHER_SUITES["chrome126"])
        cipher_cnt = format(min(len(ciphers), 15), "x")

        # alpn: first ALPN protocol
        alpn = ALPN_PROTOCOLS.get(ja4_prof, ["h2", "http/1.1"])[0]

        # extension_count: hex digit of extension count
        exts = TLS_EXTENSIONS.get(ja4_prof, _DEFAULT_EXTENSIONS)
        ext_cnt = format(min(len(exts), 15), "x")

        # curves: first supported group abbreviation
        groups = SUPPORTED_GROUPS.get(ja4_prof, _DEFAULT_GROUPS)
        first_curve = groups[0] if groups else "x25519"
        curve_map = {
            "x25519": "x25519",
            "secp256r1": "s256",
            "secp384r1": "s384",
            "secp521r1": "s521",
        }
        curve_abbr = curve_map.get(first_curve, first_curve[:5])

        # signature_algorithm: first sig alg abbreviation
        sigs = SIGNATURE_ALGORITHMS.get(ja4_prof, _DEFAULT_SIG_ALGS)
        first_sig = sigs[0] if sigs else "ecdsa_secp256r1_sha256"
        sig_map = {
            "ecdsa_secp256r1_sha256": "e256",
            "ecdsa_secp384r1_sha384": "e384",
            "ecdsa_secp521r1_sha512": "e521",
            "rsa_pss_rsae_sha256": "rs256",
            "rsa_pkcs1_sha256": "rs256",
            "rsa_pkcs1_sha384": "rs384",
            "rsa_pkcs1_sha512": "rs512",
            "rsa_pkcs1_sha1": "rs1",
        }
        sig_abbr = sig_map.get(first_sig, first_sig[:4])

        raw = f"{tls_ver}{cipher_cnt}{alpn}{ext_cnt}{curve_abbr}{sig_abbr}"
        h = hashlib.sha256(raw.encode()).hexdigest()[:12]
        return f"ja4_{raw}_{h}"


_tls_generator = TLSFingerprintGenerator()


def get_random_ssl_context() -> Tuple[ssl.SSLContext, str]:
    """Get randomized SSL context for each connection with profile name"""
    return _tls_generator.get_ssl_context()


def get_ssl_context_for_profile(profile: str) -> Tuple[ssl.SSLContext, str]:
    """Get SSL context for specific browser profile"""
    return _tls_generator.get_ssl_context(profile)


# =
# HTTP/2 FRAME PADDING & SETTINGS WINDOW RANDOMIZATION
# =

class H2FrameRandomizer:
    """
    HTTP/2 Frame manipulation for anti-fingerprinting:
    - Frame padding randomization (HEADERS, DATA)
    - Settings window size variation
    - PRIORITY frame randomization per browser
    - SETTINGS frame ACK timing simulation
    - Eliminates static packet size signatures

    Optimized for Windows local environment:
    - Uses minimum MAX_FRAME_SIZE (16384) to prevent bandwidth saturation
    - Small frames flow through limited upload bandwidth without blocking
    """

    MIN_FRAME_SIZE = 16384

    def __init__(self):
        self.padding_profiles = {
            "chrome124":  {"min": 0, "max": 64,  "probability": 0.2},
            "chrome126":  {"min": 0, "max": 64,  "probability": 0.2},
            "firefox125": {"min": 0, "max": 32,  "probability": 0.3},
            "firefox130": {"min": 0, "max": 32,  "probability": 0.3},
            "safari17":   {"min": 0, "max": 32,  "probability": 0.15},
            "safari17.4": {"min": 0, "max": 32,  "probability": 0.15},
            "edge124":    {"min": 0, "max": 64,  "probability": 0.2},
            "edge126":    {"min": 0, "max": 64,  "probability": 0.2},
            "opera110":   {"min": 0, "max": 64,  "probability": 0.2},
            "brave126":   {"min": 0, "max": 32,  "probability": 0.25},
        }

        self.window_sizes = {
            "chrome124":  [65535, 131072, 262144],
            "chrome126":  [65535, 131072, 262144],
            "firefox125": [65535, 131072],
            "firefox130": [65535, 131072],
            "safari17":   [65535, 524288],
            "safari17.4": [65535, 524288],
            "edge124":    [65535, 131072, 262144],
            "edge126":    [65535, 131072, 262144],
            "opera110":   [65535, 131072, 262144],
            "brave126":   [65535, 131072, 524288],
        }

        self.max_frame_sizes = [self.MIN_FRAME_SIZE]
        self.header_table_sizes = [4096, 8192]
        self.max_concurrent_streams = [100, 250]

        # ── PRIORITY frame profiles ──────────────────────────────────────
        # Firefox sends PRIORITY frames on odd-numbered streams at startup.
        self.priority_profiles = {
            "chrome124":  [],
            "chrome126":  [],
            "firefox125": [
                {"stream_id": 3,  "depends_on": 0, "weight": 201, "exclusive": False},
                {"stream_id": 5,  "depends_on": 0, "weight": 101, "exclusive": False},
                {"stream_id": 7,  "depends_on": 0, "weight": 1,   "exclusive": False},
                {"stream_id": 9,  "depends_on": 0, "weight": 1,   "exclusive": False},
                {"stream_id": 11, "depends_on": 0, "weight": 1,   "exclusive": False},
            ],
            "firefox130": [
                {"stream_id": 3,  "depends_on": 0, "weight": 201, "exclusive": False},
                {"stream_id": 5,  "depends_on": 0, "weight": 101, "exclusive": False},
                {"stream_id": 7,  "depends_on": 0, "weight": 1,   "exclusive": False},
                {"stream_id": 9,  "depends_on": 0, "weight": 1,   "exclusive": False},
                {"stream_id": 11, "depends_on": 0, "weight": 1,   "exclusive": False},
            ],
            "safari17":   [],
            "safari17.4": [],
            "edge124":    [],
            "edge126":    [],
            "opera110":   [],
            "brave126":   [],
        }

        # ── SETTINGS ACK timing (milliseconds) ───────────────────────────
        # Some browsers delay their SETTINGS ACK; others send it immediately.
        self.settings_ack_delay = {
            "chrome124":  (0, 10),
            "chrome126":  (0, 10),
            "firefox125": (50, 150),
            "firefox130": (50, 150),
            "safari17":   (0, 30),
            "safari17.4": (0, 30),
            "edge124":    (0, 10),
            "edge126":    (0, 10),
            "opera110":   (0, 10),
            "brave126":   (0, 50),
        }

    def get_padding_size(self, profile: str = "chrome124") -> int:
        """Get random padding size for HEADERS/DATA frames"""
        prof = self.padding_profiles.get(profile, self.padding_profiles["chrome124"])
        if random.random() < prof["probability"]:
            return random.randint(prof["min"], prof["max"])
        return 0

    def get_window_size(self, profile: str = "chrome124") -> int:
        """Get realistic window size matching browser profile"""
        sizes = self.window_sizes.get(profile, self.window_sizes["chrome124"])
        return random.choice(sizes)

    def get_max_frame_size(self) -> int:
        return self.MIN_FRAME_SIZE

    def get_header_table_size(self) -> int:
        return random.choice(self.header_table_sizes)

    def get_max_concurrent_streams(self) -> int:
        return random.choice(self.max_concurrent_streams)

    def get_priority_frames(self, profile: str = "chrome124") -> List[Dict[str, Any]]:
        """
        Return the PRIORITY frames the browser would emit at connection
        startup.  Chromium-based browsers send none; Firefox sends several.
        """
        frames = self.priority_profiles.get(profile, self.priority_profiles["chrome124"])
        return [dict(f) for f in frames]

    def get_settings_ack_delay_ms(self, profile: str = "chrome124") -> int:
        """
        Return the simulated SETTINGS ACK delay in milliseconds.
        Chromium-based browsers ACK ~immediately; Firefox may delay.
        """
        delay_range = self.settings_ack_delay.get(profile, (0, 10))
        return random.randint(delay_range[0], delay_range[1])

    def maybe_delay_settings_ack(self, profile: str = "chrome124") -> None:
        """Sleep for the browser-specific SETTINGS ACK delay."""
        delay = self.get_settings_ack_delay_ms(profile)
        if delay > 0:
            time.sleep(delay / 1000.0)

    def get_settings_payload(self, profile: str = "chrome124") -> dict:
        """Get complete randomized SETTINGS payload"""
        return {
            "header_table_size": self.get_header_table_size(),
            "enable_push": 0,
            "max_concurrent_streams": self.get_max_concurrent_streams(),
            "initial_window_size": self.get_window_size(profile),
            "max_frame_size": self.MIN_FRAME_SIZE,
            "max_header_list_size": 8192,
        }


_h2_randomizer = H2FrameRandomizer()


def get_h2_padding_size(profile: str = "chrome124") -> int:
    """Get random padding size for H2 frames"""
    return _h2_randomizer.get_padding_size(profile)


def get_h2_window_size(profile: str = "chrome124") -> int:
    """Get random window size for H2 SETTINGS"""
    return _h2_randomizer.get_window_size(profile)


def get_h2_settings(profile: str = "chrome124") -> dict:
    """Get complete randomized H2 SETTINGS payload"""
    return _h2_randomizer.get_settings_payload(profile)


# =
# NEW CONVENIENCE FUNCTIONS
# =

def get_combined_fingerprint(profile_name: str) -> Dict[str, Any]:
    """Return dict with TLS + HTTP/2 fingerprint details for a profile."""
    return _tls_generator.get_combined_fingerprint(profile_name)


def create_tls_and_h2_session(sock: Any, profile_name: str) -> Tuple[ssl.SSLContext, H2ConnectionManager]:
    """Create TLS context + initiate HTTP/2 over a connected socket."""
    return _tls_generator.create_tls_and_h2_session(sock, profile_name)


def create_complete_session(sock: Any, profile_name: str) -> Tuple[ssl.SSLContext, H2ConnectionManager]:
    """
    One-call setup: TLS handshake + HTTP/2 connection initiation.
    Returns (ssl_context, h2_manager).
    """
    return _tls_generator.create_tls_and_h2_session(sock, profile_name)


def get_ja4_string(profile: Optional[str] = None) -> str:
    """Generate JA4 fingerprint string for the given (or random) profile."""
    return _tls_generator.get_ja4_string(profile)


def get_fingerprint_summary(profile_name: str) -> Dict[str, Any]:
    """
    Return a human-readable summary dict with TLS + HTTP/2 details.
    Includes JA4 fingerprint, cipher names, ALPN, H2 settings, etc.
    """
    combined = get_combined_fingerprint(profile_name)
    ja4 = get_ja4_string(profile_name)
    combined["ja4"] = ja4
    combined["tls_version_display"] = "TLSv1.3" if "TLSv1_3" in str(combined.get("tls", {}).get("max_version", "")) else "TLSv1.2"
    return combined
