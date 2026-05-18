import requests
import logging
from typing import Dict, Any, List

class CloudLeakFinder:
    """
    Scans for leaked cloud resources (S3, Azure, GCP) that might reveal Origin IPs or sensitive data.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.name = domain.split('.')[0]
        self.logger = logging.getLogger("CloudLeakFinder")

    def run(self) -> Dict[str, Any]:
        self.logger.info(f"[*] Scanning for leaked cloud resources for {self.domain}...")
        
        results = {
            "leaked_buckets": [],
            "cloud_metadata_exposed": False,
            "sensitive_paths_found": []
        }

        # 1. AWS S3 Bucket Brute Force (Common patterns)
        bucket_patterns = [
            self.name, f"{self.name}-backup", f"{self.name}-data", f"{self.name}-static",
            f"{self.name}-dev", f"{self.name}-staging", f"{self.name}-assets"
        ]
        
        for bucket in bucket_patterns:
            url = f"https://{bucket}.s3.amazonaws.com"
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 404:
                    self.logger.info(f"    [+] Potential S3 Bucket Found: {url} (Status: {resp.status_code})")
                    results["leaked_buckets"].append({"url": url, "status": resp.status_code})
            except:
                continue

        # 2. Azure Blob Storage (Common patterns)
        azure_patterns = [self.name, self.name.replace('-', ''), f"{self.name}storage"]
        for blob in azure_patterns:
            url = f"https://{blob}.blob.core.windows.net"
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 404:
                    self.logger.info(f"    [+] Potential Azure Blob Found: {url}")
                    results["leaked_buckets"].append({"url": url, "platform": "Azure"})
            except:
                continue

        # 3. Check for exposed sensitive development paths on the domain
        sensitive_paths = [
            "/.env", "/.git/config", "/.svn/entries", "/.htaccess", 
            "/phpinfo.php", "/config.php", "/wp-config.php.bak",
            "/server-status", "/phpmyadmin/"
        ]
        
        base_url = f"https://{self.domain}"
        for path in sensitive_paths:
            url = f"{base_url}{path}"
            try:
                resp = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                if resp.status_code == 200:
                    self.logger.warning(f"    SENSITIVE PATH EXPOSED: {url}")
                    results["sensitive_paths_found"].append(url)
            except:
                continue

        return results
