import logging
import json
import os
from typing import List, Dict, Any
from src.core.analysis.universal_adapter import UniversalTargetAdapter
from src.utils.cdn_filter import is_cdn_or_static

class EndpointSelector:
    """
    GAP-01: AI Endpoint Selector.
    Analyzes and ranks endpoints by resource consumption cost.
    """
    def __init__(self, domain: str, recon_data: Dict[str, Any] = None):
        self.domain = domain
        self.recon_data = recon_data or {}
        self.logger = logging.getLogger("EndpointSelector")
        self.adapter = UniversalTargetAdapter(domain, self.recon_data)
        self.ranked_endpoints: List[Dict[str, Any]] = []

    async def get_ranked_endpoints(self, raw_data: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Main entry point to get ranked endpoints. 
        """
        if not raw_data:
            self.logger.info("[*] No raw endpoint data provided. Using Universal Adapter discovery...")
            raw_data = self.adapter.discover_endpoints()
            
        return self.analyze_cost(raw_data)

    def analyze_cost(self, endpoint_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scores endpoints based on:
        - Response time (higher = heavier)
        - Dynamic parameters (more params = more DB processing)
        - Content type (HTML SSR vs Static JS)
        - Presence of forms (POST processing)
        """
        scored_list = []
        
        for ep in endpoint_data:
            url = ep.get("url", "")
            
            # Filter using CDN rules
            blocked, reason = is_cdn_or_static(url, self.domain)
            if blocked:
                self.logger.debug(f"[AI Selector] Skipping URL: {url} | Reason: {reason}")
                continue

            latency = ep.get("avg_latency", 0)
            status = ep.get("status_code", 0)
            
            # Base score from latency
            score = latency / 100.0 
            
            # Bonus for dynamic params
            if "?" in url:
                params_count = len(url.split("?")[-1].split("&"))
                score += (params_count * 2.0)
                
            # Bonus for API/AJAX patterns
            if any(p in url.lower() for p in ["/api/", "ajax", "graphql", "/v1/", "/v2/"]):
                score += 5.0
                
            # Bonus for heavy frameworks detected in recon
            tech = self.recon_data.get("technology_stack", {})
            if "asp.net" in str(tech).lower() and ".aspx" in url.lower():
                score += 3.0
                
            # Bonus for potential SSR
            if ep.get("is_dynamic"):
                score += 4.0
                
            scored_list.append({
                "url": url,
                "cost_score": round(score, 2),
                "avg_latency": latency,
                "is_dynamic": ep.get("is_dynamic", False)
            })
            
        # Sort by cost score descending
        self.ranked_endpoints = sorted(scored_list, key=lambda x: x["cost_score"], reverse=True)
        
        self.logger.info(f"[AI Selector] Ranked {len(self.ranked_endpoints)} endpoints. Top target: {self.ranked_endpoints[0]['url'] if self.ranked_endpoints else 'None'}")
        return self.ranked_endpoints

    def save_ranking(self):
        os.makedirs("output/reports", exist_ok=True)
        path = f"output/reports/ranked_endpoints_{self.domain}.json"
        try:
            with open(path, 'w') as f:
                json.dump(self.ranked_endpoints, f, indent=4)
        except Exception as e:
            self.logger.error(f"[-] Failed to save rankings: {e}")
            
    def get_top_target(self, limit: int = 1) -> List[str]:
        return [ep["url"] for ep in self.ranked_endpoints[:limit]]
