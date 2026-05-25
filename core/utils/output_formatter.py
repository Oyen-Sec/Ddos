"""
Output Formatter v8.0
Clean, professional output without emoji and excessive separators
"""
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("output_formatter")


class CleanFormatter:
    """Clean output formatter for v8.0."""
    
    @staticmethod
    def print_header(title: str, subtitle: str = ""):
        """Print clean header."""
        print()
        print("-" * 80)
        print(title.upper())
        if subtitle:
            print(subtitle)
        print("-" * 80)
    
    @staticmethod
    def print_section(title: str):
        """Print section title."""
        print()
        print(f"{title}")
        print("-" * 80)
    
    @staticmethod
    def print_item(label: str, value: str, indent: int = 0):
        """Print key-value item."""
        spaces = " " * indent
        print(f"{spaces}{label:20s} : {value}")
    
    @staticmethod
    def print_list(items: List[str], indent: int = 2):
        """Print list of items."""
        spaces = " " * indent
        for item in items:
            print(f"{spaces}- {item}")
    
    @staticmethod
    def print_verification_report(domain: str, results: List[Dict]):
        """Print origin verification report."""
        print()
        print("-" * 80)
        print(f"VERIFIED ORIGIN IP REPORT: {domain}")
        print("-" * 80)
        
        verified_count = 0
        discarded_count = 0
        
        for result in results:
            ip = result.get('ip', 'unknown')
            is_verified = result.get('is_verified', False)
            reason = result.get('reason', '')
            method = result.get('verification_method', '')
            server = result.get('server_header', 'unknown')
            ssl_cn = result.get('ssl_cn', '')
            hash_match = result.get('hash_match_count', 0)
            
            if is_verified:
                verified_count += 1
                print()
                print(f"[PASS] {ip:15s}  |  VERIFIED ORIGIN")
                print(f"       Method     : {method}")
                print(f"       Protocol   : HTTP {result.get('http_status', 0)} / HTTPS {result.get('https_status', 0)}")
                print(f"       Server     : {server}")
                if hash_match > 0:
                    print(f"       Hash Match : {hash_match}/3 content hashes matched")
                if ssl_cn:
                    print(f"       SSL CN     : {ssl_cn}")
                print(f"       Verified   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
            else:
                discarded_count += 1
                print()
                print(f"[FAIL] {ip:15s}  |  DISCARDED")
                print(f"       Reason     : {reason}")
                
                # Additional details
                if result.get('is_cdn_ip'):
                    provider = result.get('cdn_provider', 'unknown')
                    print(f"       Detail     : CDN IP range ({provider.upper()})")
                elif result.get('is_shared_hosting'):
                    ptr = result.get('ptr_record', '')
                    print(f"       Detail     : Shared hosting (PTR: {ptr})")
                elif result.get('is_redirect'):
                    print(f"       Detail     : HTTP redirect detected")
        
        print()
        print("-" * 80)
        print("SUMMARY")
        print("-" * 80)
        print(f"Total candidates : {len(results)}")
        print(f"Verified origin  : {verified_count}")
        print(f"Discarded        : {discarded_count}")
        print("-" * 80)
    
    @staticmethod
    def print_sustained_attack_config(config: Dict):
        """Print sustained attack configuration."""
        print()
        print("-" * 80)
        print("SUSTAINED ATTACK CONFIGURATION")
        print("-" * 80)
        
        if config.get('vector_rotation'):
            print(f"Vector Rotation   : Enabled ({config.get('rotation_interval', 60)}s interval)")
        
        if config.get('low_slow'):
            print(f"Low-Slow Attack   : Enabled ({config.get('connection_limit', 25)} conn/IP, {config.get('request_interval', 15)}s interval)")
        
        if config.get('connection_decoupling'):
            print(f"Connection Decoupling: Enabled ({config.get('file_size', '10MB')} resource, {config.get('amplification', '40000x')} amplification)")
        
        if config.get('head_bomb'):
            print(f"HEAD Bomb         : Enabled (cache-bypass query string)")
        
        if config.get('distributed_botnet'):
            print(f"Distributed Botnet: Enabled ({config.get('proxy_count', 1000)} proxies)")
        
        if config.get('tor_enabled'):
            instances = config.get('tor_instances', 5)
            exit_ip = config.get('tor_exit_ip', 'unknown')
            print(f"Tor Status        : Active ({instances} instances) | Exit IP: {exit_ip}")
        
        print("-" * 80)
    
    @staticmethod
    def print_attack_stats(stats: Dict):
        """Print attack statistics."""
        print()
        print("-" * 80)
        print("ATTACK STATISTICS")
        print("-" * 80)
        
        duration = stats.get('duration', 0)
        total_requests = stats.get('total_requests', 0)
        total_connections = stats.get('total_connections', 0)
        failed_requests = stats.get('failed_requests', 0)
        
        print(f"Duration          : {duration:.2f} seconds")
        print(f"Total requests    : {total_requests}")
        print(f"Total connections : {total_connections}")
        print(f"Failed requests   : {failed_requests}")
        
        if total_requests > 0:
            success_rate = (1 - failed_requests / total_requests) * 100
            print(f"Success rate      : {success_rate:.2f}%")
        
        if duration > 0:
            avg_rps = total_requests / duration
            print(f"Avg RPS           : {avg_rps:.2f}")
        
        if stats.get('vectors_executed'):
            print(f"Vectors executed  : {stats['vectors_executed']}")
        
        if stats.get('current_vector'):
            print(f"Current vector    : {stats['current_vector']}")
        
        print("-" * 80)
    
    @staticmethod
    def print_tor_status(instances: List[Dict]):
        """Print Tor instances status."""
        print()
        print("-" * 80)
        print("TOR INSTANCES STATUS")
        print("-" * 80)
        
        for inst in instances:
            instance_id = inst.get('instance_id', 0)
            socks_port = inst.get('socks_port', 0)
            is_healthy = inst.get('is_healthy', False)
            exit_ip = inst.get('exit_ip', 'unknown')
            
            status = "HEALTHY" if is_healthy else "UNHEALTHY"
            print(f"Instance {instance_id:2d} : SOCKS={socks_port} | {status:10s} | Exit IP: {exit_ip}")
        
        print("-" * 80)
    
    @staticmethod
    def print_proxy_distribution(distribution: Dict[str, int]):
        """Print proxy geo-distribution."""
        print()
        print("-" * 80)
        print("PROXY GEO-DISTRIBUTION")
        print("-" * 80)
        
        total = sum(distribution.values())
        
        for region, count in sorted(distribution.items()):
            percentage = (count / total * 100) if total > 0 else 0
            print(f"{region:6s} : {count:4d} proxies ({percentage:5.2f}%)")
        
        print(f"{'TOTAL':6s} : {total:4d} proxies")
        print("-" * 80)


# Global formatter instance
formatter = CleanFormatter()


def print_header(title: str, subtitle: str = ""):
    """Print clean header."""
    formatter.print_header(title, subtitle)


def print_section(title: str):
    """Print section title."""
    formatter.print_section(title)


def print_item(label: str, value: str, indent: int = 0):
    """Print key-value item."""
    formatter.print_item(label, value, indent)


def print_verification_report(domain: str, results: List[Dict]):
    """Print origin verification report."""
    formatter.print_verification_report(domain, results)


def print_sustained_attack_config(config: Dict):
    """Print sustained attack configuration."""
    formatter.print_sustained_attack_config(config)


def print_attack_stats(stats: Dict):
    """Print attack statistics."""
    formatter.print_attack_stats(stats)


def print_tor_status(instances: List[Dict]):
    """Print Tor instances status."""
    formatter.print_tor_status(instances)


def print_proxy_distribution(distribution: Dict[str, int]):
    """Print proxy geo-distribution."""
    formatter.print_proxy_distribution(distribution)
