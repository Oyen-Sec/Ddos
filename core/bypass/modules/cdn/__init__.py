"""Bypass modules for Cdn."""
from .cloudflare import CloudflareBypass
from .fastly import FastlyBypass
from .akamai import AkamaiBypass
from .cloudfront import CloudFrontBypass
from .sucuri import SucuriBypass
from .ddos_guard import DdosGuardBypass
from .stackpath import StackpathBypass
from .netlify import NetlifyBypass
from .vercel import VercelBypass
from .gcore import GcoreBypass
from .bunnycdn import BunnycdnBypass
from .quiccloud import QuiccloudBypass
from .cdn77 import Cdn77Bypass
from .gcorelabs import GcorelabsBypass
from .belugacdn import BelugacdnBypass
from .io_river import IoRiverBypass
from .io_iwant import IoIwantBypass
from .edgecast import EdgecastBypass
from .cdnetworks import CdnetworksBypass
from .arvancloud import ArvancloudBypass
from .imagekit import ImagekitBypass
from .speedcdn import SpeedcdnBypass
from .hostinger import HostingerBypass

__all__ = [
    "CloudflareBypass",
    "FastlyBypass",
    "AkamaiBypass",
    "CloudFrontBypass",
    "SucuriBypass",
    "DdosGuardBypass",
    "StackpathBypass",
    "NetlifyBypass",
    "VercelBypass",
    "GcoreBypass",
    "BunnycdnBypass",
    "QuiccloudBypass",
    "Cdn77Bypass",
    "GcorelabsBypass",
    "BelugacdnBypass",
    "IoRiverBypass",
    "IoIwantBypass",
    "EdgecastBypass",
    "CdnetworksBypass",
    "ArvancloudBypass",
    "ImagekitBypass",
    "SpeedcdnBypass",
    "HostingerBypass"
]
