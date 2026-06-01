"""Bypass modules for Web Servers."""
from .nginx import NginxBypass
from .apache import ApacheBypass
from .iis import IISBypass
from .litespeed import LitespeedBypass
from .caddy import CaddyBypass
from .lighttpd import LighttpdBypass
from .cloudflare_server import CloudflareServerBypass
from .openresty import OpenrestyBypass
from .nodejs import NodejsBypass
from .traefik import TraefikBypass
from .tomcat import TomcatBypass
from .gws import GwsBypass
from .amazon_linux import AmazonLinuxBypass

__all__ = [
    "NginxBypass",
    "ApacheBypass",
    "IISBypass",
    "LitespeedBypass",
    "CaddyBypass",
    "LighttpdBypass",
    "CloudflareServerBypass",
    "OpenrestyBypass",
    "NodejsBypass",
    "TraefikBypass",
    "TomcatBypass",
    "GwsBypass",
    "AmazonLinuxBypass"
]
