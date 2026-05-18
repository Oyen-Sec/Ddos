import json
import os
import logging
from typing import Dict, List, Any

class ReconDataConsumer:
    """
    GAP-06: Reconnaissance Data Integration.
    Consumes Phase 1/2 outputs to optimize Phase 4/5 execution.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("ReconDataConsumer")
        self.recon_data = self._load_all_recon_data()

    def _load_all_recon_data(self) -> Dict[str, Any]:
        recon_path = f"output/reports/recon_{self.domain}.json"
        deep_recon_path = f"output/reports/deep_recon_{self.domain}.json"
        
        combined_data = {}
        
        if os.path.exists(recon_path):
            try:
                with open(recon_path, 'r') as f:
                    combined_data.update(json.load(f))
            except Exception as e:
                self.logger.error(f"[-] Error loading recon data: {e}")
        
        if os.path.exists(deep_recon_path):
            try:
                with open(deep_recon_path, 'r') as f:
                    combined_data.update(json.load(f))
            except Exception as e:
                self.logger.error(f"[-] Error loading deep recon data: {e}")
                
        return combined_data

    def get_tech_stack(self) -> Dict[str, Any]:
        return self.recon_data.get("technology_stack", {})

    def get_waf_info(self) -> Dict[str, Any]:
        return self.recon_data.get("waf_analysis", {})

    def select_vectors_by_tech(self) -> List[str]:
        """Suggests vectors based on backend technology."""
        tech = self.get_tech_stack()
        backend = str(tech.get("backend", "")).lower()
        
        vectors = ["http_get_flood"] # Default
        
        if "php" in backend:
            vectors.append("dynamic_request_flood") # PHP param pollution potential
        if "asp.net" in backend:
            vectors.append("http_post_flood") # ViewState/Session exhaustion
        if "graphql" in str(tech).lower():
            vectors.append("graphql_abuse")
            
        return vectors

    def select_bypass_by_waf(self) -> str:
        """Selects bypass method based on detected WAF."""
        waf = self.get_waf_info()
        vendor = str(waf.get("vendor", "")).lower()
        
        if "cloudflare" in vendor:
            return "cloudflare"
        if "aws" in vendor:
            return "aws_waf_bypass"
        if "akamai" in vendor:
            return "akamai_bypass"
            
        return "none"

    def get_confirmed_origin(self) -> str:
        """Returns confirmed origin IP if found in Phase 2."""
        return self.recon_data.get("confirmed_origin")

    def generate_attack_plan(self) -> Dict[str, Any]:
        """Creates a comprehensive plan for the adaptive engine."""
        origin = self.get_confirmed_origin()
        waf_method = self.select_bypass_by_waf()
        
        plan = {
            "target": self.domain,
            "origin_ip": origin,
            "bypass_method": "origin" if origin else waf_method,
            "recommended_vectors": self.select_vectors_by_tech(),
            "is_cloudflare": "cloudflare" in str(self.get_waf_info().get("vendor", "")).lower(),
            "tech_stack": self.get_tech_stack()
        }
        
        self.logger.info(f"[AI Plan] Optimized for {plan['bypass_method']} bypass using {plan['recommended_vectors']}")
        return plan
