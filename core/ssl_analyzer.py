import ssl
import socket
import logging
from typing import Dict, Any, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("SSLAnalyzer")

class SSLAnalyzer:
    def __init__(self, domain: str):
        self.domain = domain

    def analyze(self) -> Dict[str, Any]:
        results = {
            "certificate": {},
            "tls_version": "Unknown",
            "cipher_suite": "Unknown",
            "supported_versions": [],
            "grade": "F",
            "vulnerabilities": [],
            "hsts": {
                "enabled": False,
                "max_age": 0,
                "include_subdomains": False,
                "preload": False
            }
        }

        try:
            for version_name in ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
                if self._check_tls_version(version_name):
                    results["supported_versions"].append(version_name)

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert_bin = ssock.getpeercert(True)
                    results["tls_version"] = ssock.version()
                    results["cipher_suite"] = ssock.cipher()[0]

                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                    results["certificate"] = {
                        "subject": {str(attr.oid._name): attr.value for attr in cert.subject},
                        "issuer": {str(attr.oid._name): attr.value for attr in cert.issuer},
                        "valid_from": cert.not_valid_before_utc.isoformat(),
                        "valid_until": cert.not_valid_after_utc.isoformat(),
                        "serial_number": format(cert.serial_number, 'X'),
                        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                        "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(),
                        "signature_algorithm": cert.signature_algorithm_oid._name,
                        "key_type": cert.public_key().__class__.__name__,
                        "key_size": getattr(cert.public_key(), 'key_size', 'Unknown'),
                        "is_wildcard": "*" in str(cert.subject),
                        "san": self._get_san(cert)
                    }

                    if results["tls_version"] == "TLSv1.3":
                        results["grade"] = "A+"
                    elif results["tls_version"] == "TLSv1.2":
                        results["grade"] = "A"
                    elif "TLSv1" in results["supported_versions"] or "TLSv1.1" in results["supported_versions"]:
                        results["grade"] = "B"
                        results["vulnerabilities"].append("Legacy TLS versions supported")

        except Exception as e:
            logger.error(f"SSL Analysis failed for {self.domain}: {e}")

        self._check_hsts(results)
        results["transparency_logs"] = self._get_crt_sh()

        return results

    def _check_tls_version(self, version_name: str) -> bool:
        try:
            version_map = {
                'TLSv1': ssl.PROTOCOL_TLSv1,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
                'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
                'TLSv1.3': getattr(ssl, 'PROTOCOL_TLSv1_3', None)
            }
            proto = version_map.get(version_name)
            if proto is None:
                return False
            context = ssl.SSLContext(proto)
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    return True
        except Exception:
            return False

    def _check_hsts(self, results: Dict):
        try:
            resp = requests.get(f"https://{self.domain}", timeout=10, verify=False)
            hsts = resp.headers.get('Strict-Transport-Security')
            if hsts:
                results["hsts"]["enabled"] = True
                if 'max-age=' in hsts:
                    results["hsts"]["max_age"] = int(hsts.split('max-age=')[1].split(';')[0])
                if 'includeSubDomains' in hsts:
                    results["hsts"]["include_subdomains"] = True
                if 'preload' in hsts:
                    results["hsts"]["preload"] = True
        except Exception:
            pass

    def _get_san(self, cert) -> List[str]:
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            return []

    def _get_crt_sh(self) -> List[Dict]:
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                return resp.json()[:20]
        except Exception:
            pass
        return []

    def run(self):
        logger.info(f"[*] Starting Deep SSL/TLS Analysis for {self.domain}...")
        return self.analyze()
