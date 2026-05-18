import requests
import logging
from bs4 import BeautifulSoup

class Fingerprinter:
    def __init__(self, target_url: str):
        if not target_url.startswith("http"):
            target_url = f"http://{target_url}"
        self.target = target_url
        self.logger = logging.getLogger("Fingerprinter")
        self.tech_stack = {
            "server": None,
            "cms": None,
            "framework": [],
            "frontend_libs": []
        }

    def identify_tech(self):
        self.logger.info(f"Fingerprinting {self.target}...")
        try:
            response = requests.get(self.target, timeout=10)
            
            # Check headers
            self.tech_stack["server"] = response.headers.get("Server")
            
            # Check HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # CMS Detection
            if soup.find("meta", {"name": "generator"}):
                self.tech_stack["cms"] = soup.find("meta", {"name": "generator"})["content"]
            
            # Basic lib detection
            scripts = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
            for src in scripts:
                if "jquery" in src.lower():
                    self.tech_stack["frontend_libs"].append("jQuery")
                if "react" in src.lower():
                    self.tech_stack["frontend_libs"].append("React")
                if "vue" in src.lower():
                    self.tech_stack["frontend_libs"].append("Vue.js")
            
            self.tech_stack["frontend_libs"] = list(set(self.tech_stack["frontend_libs"]))
            
        except Exception as e:
            self.logger.error(f"Error during fingerprinting: {e}")
            
        return self.tech_stack
