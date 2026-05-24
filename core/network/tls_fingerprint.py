"""
TLS Fingerprint Spoofing Module
Implements JA3/JA4 randomization and cipher suite diversification
UPDATED: 2026-05-23 - Latest browser versions
"""
import random
import ssl
from typing import Dict, List, Optional, Tuple

# Modern browser TLS cipher suites (Chrome 124+, Firefox 125+, Safari 17.4+, Edge 124+)
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
    "safari17": [
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
}

# TLS versions
TLS_VERSIONS = {
    "chrome124": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "firefox125": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "safari17": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "edge124": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
}

# ALPN protocols
ALPN_PROTOCOLS = {
    "chrome124": ["h2", "http/1.1"],
    "firefox125": ["h2", "http/1.1"],
    "safari17": ["h2", "http/1.1"],
    "edge124": ["h2", "http/1.1"],
}


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
        
        # Set TLS version range
        if profile in TLS_VERSIONS:
            min_ver, max_ver = TLS_VERSIONS[profile]
            context.minimum_version = min_ver
            context.maximum_version = max_ver
        
        # Set cipher suites (randomize order slightly)
        if profile in CIPHER_SUITES:
            ciphers = CIPHER_SUITES[profile].copy()
            # Shuffle first 3 ciphers for entropy
            if len(ciphers) >= 3:
                first_three = ciphers[:3]
                random.shuffle(first_three)
                ciphers[:3] = first_three
            try:
                context.set_ciphers(":".join(ciphers))
            except ssl.SSLError:
                # Fallback to default if cipher string invalid
                pass
        
        # Set ALPN protocols
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
        
        # Simplified JA3 representation
        ssl_ver = "771"  # TLS 1.2
        ciphers = CIPHER_SUITES.get(profile, CIPHER_SUITES["chrome120"])
        cipher_ids = ",".join([str(hash(c) % 10000) for c in ciphers[:5]])
        extensions = "0-10-11-13-23-35-65281"  # Common extensions
        curves = "29-23-24"  # x25519, secp256r1, secp384r1
        point_formats = "0"
        
        return f"{ssl_ver},{cipher_ids},{extensions},{curves},{point_formats}"


# Global instance
_tls_generator = TLSFingerprintGenerator()


def get_random_ssl_context() -> Tuple[ssl.SSLContext, str]:
    """Get randomized SSL context for each connection with profile name"""
    return _tls_generator.get_ssl_context()


def get_ssl_context_for_profile(profile: str) -> Tuple[ssl.SSLContext, str]:
    """Get SSL context for specific browser profile"""
    return _tls_generator.get_ssl_context(profile)


# ============================================================================
# HTTP/2 FRAME PADDING & SETTINGS WINDOW RANDOMIZATION
# ============================================================================

class H2FrameRandomizer:
    """
    HTTP/2 Frame manipulation for anti-fingerprinting:
    - Frame padding randomization (HEADERS, DATA)
    - Settings window size variation
    - Eliminates static packet size signatures
    
    Optimized for Windows local environment:
    - Uses minimum MAX_FRAME_SIZE (16384) to prevent bandwidth saturation
    - Small frames flow through limited upload bandwidth without blocking
    """
    
    # HTTP/2 minimum frame size per RFC 7540 section 4.2
    MIN_FRAME_SIZE = 16384  # 16KB - smallest valid HTTP/2 frame size
    
    def __init__(self):
        # Padding ranges per browser profile (reduced for low bandwidth)
        self.padding_profiles = {
            "chrome124": {"min": 0, "max": 64, "probability": 0.2},
            "firefox125": {"min": 0, "max": 32, "probability": 0.3},
            "safari17": {"min": 0, "max": 32, "probability": 0.15},
            "edge124": {"min": 0, "max": 64, "probability": 0.2},
        }
        
        # Settings window sizes (reduced for limited bandwidth)
        self.window_sizes = {
            "chrome124": [65535, 131072, 262144],
            "firefox125": [65535, 131072],
            "safari17": [65535, 524288],
            "edge124": [65535, 131072, 262144],
        }
        
        # Use MINIMUM frame size only (16384) to prevent bandwidth blocking
        # Small frames = consistent throughput, no large packet stalls
        self.max_frame_sizes = [self.MIN_FRAME_SIZE]
        
        # Header table sizes (reduced)
        self.header_table_sizes = [4096, 8192]
        
        # Max concurrent streams (reduced for bandwidth conservation)
        self.max_concurrent_streams = [100, 250]
    
    def get_padding_size(self, profile: str = "chrome124") -> int:
        """Get random padding size for HEADERS/DATA frames"""
        prof = self.padding_profiles.get(profile, self.padding_profiles["chrome124"])
        if random.random() < prof["probability"]:
            return random.randint(prof["min"], prof["max"])
        return 0  # No padding
    
    def get_window_size(self, profile: str = "chrome124") -> int:
        """Get realistic window size matching browser profile"""
        sizes = self.window_sizes.get(profile, self.window_sizes["chrome124"])
        return random.choice(sizes)
    
    def get_max_frame_size(self) -> int:
        """
        Always returns minimum HTTP/2 frame size (16384 bytes)
        Prevents bandwidth blocking by single large frame
        """
        return self.MIN_FRAME_SIZE
    
    def get_header_table_size(self) -> int:
        """Get random header table size"""
        return random.choice(self.header_table_sizes)
    
    def get_max_concurrent_streams(self) -> int:
        """Get random max concurrent streams setting"""
        return random.choice(self.max_concurrent_streams)
    
    def get_settings_payload(self, profile: str = "chrome124") -> dict:
        """
        Get complete randomized SETTINGS payload
        Always uses minimum MAX_FRAME_SIZE for bandwidth optimization
        """
        return {
            "header_table_size": self.get_header_table_size(),
            "enable_push": 0,
            "max_concurrent_streams": self.get_max_concurrent_streams(),
            "initial_window_size": self.get_window_size(profile),
            "max_frame_size": self.MIN_FRAME_SIZE,  # Always minimum
            "max_header_list_size": 8192,  # Reduced
        }


# Global H2 frame randomizer
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
