import random
import time
import logging
from typing import Dict, List

class MimicEngine:
    """
    Generates human-like browsing patterns and request behaviors.
    """
    def __init__(self):
        self.logger = logging.getLogger("MimicEngine")
        self.user_behaviors = [
            "casual_browser",  # Slow, random delays, common pages
            "power_user",      # Fast, systematic, API-heavy
            "crawler",         # High volume, link-following
            "bot_evasive"      # Erratic timing, rotating fingerprints
        ]

    def get_delay(self, behavior: str = "casual_browser") -> float:
        """
        Calculates timing delays based on simulated user behavior.
        Optimized for high throughput with human-like jitter.
        """
        if behavior == "casual_browser":
            # Optimized: Mean 0.2s, StdDev 0.1s (Realistic for high-speed browsing)
            return max(0.05, random.gauss(0.2, 0.1))
        elif behavior == "power_user":
            # Optimized: Mean 0.05s, StdDev 0.02s
            return max(0.01, random.gauss(0.05, 0.02))
        elif behavior == "bot_evasive":
            # Erratic but fast
            return random.choice([0.01, 0.05, 0.1, 0.02])
        return 0.01

    def get_adaptive_headers(self, base_headers: Dict) -> Dict:
        """
        Dynamically adjusts request headers to bypass detection.
        """
        headers = base_headers.copy()
        
        # Randomize order and slightly modify common headers
        if "User-Agent" in headers:
            # Add slight variation or comment to UA if it's too static
            if random.random() > 0.8:
                headers["User-Agent"] += f" (mimic-v{random.randint(1,9)})"
        
        # Add human-like headers if missing
        if "Accept-Language" not in headers:
            langs = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "id-ID,id;q=0.9,en-US;q=0.8"]
            headers["Accept-Language"] = random.choice(langs)
            
        # Sec-CH-UA headers for modern browsers
        if random.random() > 0.5:
            headers["sec-ch-ua"] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
            headers["sec-ch-ua-mobile"] = "?0"
            headers["sec-ch-ua-platform"] = '"Windows"'

        return headers

    def generate_polymorphic_payload(self, template: Dict) -> Dict:
        """
        Randomizes payload structure while maintaining target compatibility.
        """
        payload = template.copy()
        for key, value in payload.items():
            if isinstance(value, str):
                # Add random padding or noise that server might ignore
                if random.random() > 0.7:
                    payload[key] = value + (" " * random.randint(1, 5))
            elif isinstance(value, int):
                # Small numeric variations if applicable
                pass
        
        # Add garbage keys that might bypass some WAF rules
        if random.random() > 0.8:
            payload[f"var_{random.randint(1,100)}"] = "".join(random.choices("abcdef", k=5))
            
        return payload
