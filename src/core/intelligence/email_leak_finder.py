import logging
from typing import List, Optional
import socket

class EmailLeakFinder:
    """
    Checks for potential IP leaks via email headers and MX records.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("EmailLeakFinder")

    def check_mx_records(self) -> List[str]:
        """
        Check MX records and resolve them to IPs.
        Often mail servers are on the same subnet as the origin server.
        """
        self.logger.info(f"[*] Checking MX records for {self.domain}...")
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            ips = []
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                self.logger.info(f"[+] Found MX: {mx_host}")
                try:
                    ip = socket.gethostbyname(mx_host)
                    self.logger.info(f"    -> IP: {ip}")
                    ips.append(ip)
                except:
                    pass
            return ips
        except Exception as e:
            self.logger.error(f"[-] Error checking MX records: {e}")
            return []

    def simulate_email_trigger(self):
        """
        Suggests ways to trigger an email to get headers.
        """
        self.logger.info(f"[!] Tip: To find Origin IP via Email Header:")
        self.logger.info(f"    1. Register on the target website (if available).")
        self.logger.info(f"    2. Use 'Forgot Password' feature.")
        self.logger.info(f"    3. Check the received email's full headers.")
        self.logger.info(f"    4. Look for 'Received: from' or 'X-Originating-IP' fields.")
        self.logger.info(f"    5. The IP found there is often the real Origin IP.")

    def run(self):
        ips = self.check_mx_records()
        self.simulate_email_trigger()
        return ips
