import httpx
import logging
import hashlib
import asyncio
from typing import List, Dict, Tuple

class OriginValidator:
    """
    The ultimate Origin IP validation module.
    Compares the HTTP response (content hash, title, and headers) of a CDN-protected
    target with a list of candidate IPs.
    """
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.logger = logging.getLogger("OriginValidator")
        self.original_hash = None
        self.original_title = None

    async def get_original_fingerprint(self):
        """Fetches the fingerprint of the site via the CDN."""
        self.logger.info(f"[*] Getting original fingerprint for {self.target_domain} via CDN...")
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                res = await client.get(f"https://{self.target_domain}")
                self.original_hash = hashlib.md5(res.content).hexdigest()
                # Simple title extraction
                import re
                title_match = re.search(r'<title>(.*?)</title>', res.text, re.I)
                self.original_title = title_match.group(1) if title_match else ""
                self.logger.info(f"[+] CDN Fingerprint: Hash={self.original_hash}, Title='{self.original_title}'")
        except Exception as e:
            self.logger.error(f"[-] Failed to get CDN fingerprint: {e}")

    async def validate_ip(self, ip: str) -> Dict:
        """Attempts to access the target domain directly via the given IP."""
        url = f"http://{ip}/"
        headers = {"Host": self.target_domain, "User-Agent": "Mozilla/5.0"}
        
        result = {"ip": ip, "is_origin": False, "match_score": 0, "reason": None}
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                # Try HTTP first
                res = await client.get(url, headers=headers, follow_redirects=False)
                
                # Check for content similarity
                current_hash = hashlib.md5(res.content).hexdigest()
                
                if current_hash == self.original_hash:
                    result["is_origin"] = True
                    result["match_score"] = 100
                    result["reason"] = "Perfect MD5 Hash Match"
                elif self.original_title and self.original_title in res.text:
                    result["is_origin"] = True
                    result["match_score"] = 80
                    result["reason"] = "Title Match"
                elif res.status_code == 200 and len(res.content) > 0:
                    # Partial match based on size similarity (rough)
                    size_diff = abs(len(res.content) - (0 if not self.original_hash else 1000)) # Placeholder
                    result["match_score"] = 50
                    result["reason"] = "Response 200 with content"
                    
        except Exception:
            pass
            
        return result

    async def validate(self, ip: str) -> bool:
        """Helper for single IP validation."""
        if not self.original_hash:
            await self.get_original_fingerprint()
        res = await self.validate_ip(ip)
        return res["is_origin"]

    async def run(self, candidate_ips: List[str]) -> List[Dict]:
        if not candidate_ips:
            return []
            
        await self.get_original_fingerprint()
        
        self.logger.info(f"[*] Validating {len(candidate_ips)} candidate IPs for Origin IP...")
        tasks = [self.validate_ip(ip) for ip in set(candidate_ips)]
        results = await asyncio.gather(*tasks)
        
        valid_origins = [r for r in results if r["is_origin"]]
        # Sort by match score
        valid_origins.sort(key=lambda x: x["match_score"], reverse=True)
        
        if valid_origins:
            self.logger.info(f"[!] BOOM! Found {len(valid_origins)} potential Origin IPs!")
            for v in valid_origins:
                self.logger.info(f"    -> {v['ip']} (Score: {v['match_score']}%, Reason: {v['reason']})")
        else:
            self.logger.info("[-] No Origin IP confirmed via direct content matching.")
            
        return valid_origins
