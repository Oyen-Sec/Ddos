"""
Multi-Protocol Concurrency Layer - Browser Fingerprint Module
Generates unique, realistic browser fingerprints per instance
"""
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BrowserFingerprint:
    """Complete browser fingerprint"""
    user_agent: str
    platform: str
    language: str
    languages: List[str]
    screen_width: int
    screen_height: int
    viewport_width: int
    viewport_height: int
    device_memory: int
    hardware_concurrency: int
    timezone: str
    timezone_offset: int
    vendor: str
    product: str
    product_sub: str
    instance_id: str = field(default_factory=lambda: ''.join(
        random.choices('0123456789abcdef', k=16)
    ))


class FingerprintGenerator:
    """Generates realistic browser fingerprints"""
    
    USER_AGENTS = [
        # Chrome Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.0",
        # Firefox Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        # Edge Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.0 Edg/126.0.0.0",
    ]
    
    VIEWPORTS = [
        {"width": 1920, "height": 1080},
        {"width": 1366, "height": 768},
        {"width": 1440, "height": 900},
        {"width": 1536, "height": 864},
        {"width": 1280, "height": 720},
        {"width": 1680, "height": 1050},
    ]
    
    TIMEZONES = [
        ("America/New_York", -300),
        ("America/Chicago", -360),
        ("America/Los_Angeles", -480),
        ("Europe/London", 0),
        ("Europe/Paris", 60),
        ("Europe/Berlin", 60),
        ("Asia/Tokyo", 540),
        ("Asia/Shanghai", 480),
        ("Asia/Singapore", 480),
        ("Asia/Jakarta", 420),
        ("Australia/Sydney", 600),
    ]
    
    def generate(self) -> BrowserFingerprint:
        """Generate a complete browser fingerprint"""
        ua = random.choice(self.USER_AGENTS)
        viewport = random.choice(self.VIEWPORTS)
        tz_name, tz_offset = random.choice(self.TIMEZONES)
        
        # Determine platform from UA
        if "Windows" in ua:
            platform = "Win32"
        elif "Macintosh" in ua:
            platform = "MacIntel"
        elif "Linux" in ua:
            platform = "Linux x86_64"
        else:
            platform = "Win32"
        
        # Generate viewport slightly smaller than screen
        screen_w = viewport["width"]
        screen_h = viewport["height"]
        vp_w = screen_w - random.randint(0, 20)
        vp_h = screen_h - random.randint(80, 120)
        
        return BrowserFingerprint(
            user_agent=ua,
            platform=platform,
            language="en-US",
            languages=["en-US", "en"],
            screen_width=screen_w,
            screen_height=screen_h,
            viewport_width=vp_w,
            viewport_height=vp_h,
            device_memory=random.choice([4, 8, 16]),
            hardware_concurrency=random.choice([4, 8, 16]),
            timezone=tz_name,
            timezone_offset=tz_offset,
            vendor="Google Inc.",
            product="Gecko",
            product_sub="20030107",
        )


def generate_fingerprint() -> BrowserFingerprint:
    """Generate a new browser fingerprint"""
    return FingerprintGenerator().generate()
