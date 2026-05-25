# Multi-Protocol Concurrency Layer v6.0

Professional network stress testing framework with advanced bypass capabilities.

## Project Structure

```
Ddos/
├── bin/                       # Compiled binaries
├── config/                    # Configuration files
├── core/
│   ├── attack/               # Attack engines
│   ├── bypass/               # Advanced bypass techniques
│   │   ├── behavioral_engine.py     # AI-driven human behavior mimicry
│   │   ├── business_logic.py        # Low-slow resource exhaustion
│   │   ├── cache_origin.py          # Cache poisoning & origin discovery
│   │   ├── fingerprint_evasion.py   # TLS/Canvas/WebGL/WebRTC evasion
│   │   ├── orchestrator.py          # Attack coordination
│   │   └── waf_parsing_bypass.py    # WAF parsing discrepancy fuzzing
│   ├── handlers/             # Menu handlers
│   ├── monitor/              # Monitoring and dashboards
│   ├── network/              # Network utilities
│   │   ├── flaresolverr_client.py   # FlareSolverr Cloudflare challenge solver
│   │   ├── http2_impersonator.py    # HTTP/2 browser fingerprint spoofing
│   │   ├── proxy.py                 # Proxy pool + FlareSolverr integration
│   │   ├── tls_fingerprint.py       # TLS + JA4 + HTTP/2 combined fingerprint
│   │   └── header_mutation.py
│   ├── recon/                # Reconnaissance modules
│   │   ├── origin_hunter.py         # 18 sources + WAF bypass logic
│   │   ├── detector.py
│   │   └── endpoint.py
│   ├── seo/                  # SEO attack modules
│   ├── waf/                  # WAF detection module
│   └── utils/
├── logs/
├── proxies/
├── wordlists/
├── main.py                   # Main entry point
└── requirements.txt
```

## Installation

```bash
pip install -r requirements.txt
pip install hyperframe h2  # For HTTP/2 fingerprinting
```

## Quick Start

### Interactive Menu
```bash
python main.py --start
```

### Direct Attack
```bash
python main.py -t https://target.com -m http-flood -d 300 -r 5000
```

## Main Features

### Standard Attacks
- **[1-7]** HTTP/HTTP2/Layer4 floods
- **[A-J]** Advanced protocol attacks
- **[Q-S]** QUIC/HTTP3 attacks
- **[T-Z]** API and serverless attacks

### Advanced 2026 Features
- **[N]** Advanced 2026 - Full bypass suite
- **[L]** Business Logic - Resource exhaustion
- **[K]** SEO Attack - Negative SEO campaigns

### Tools
- **[H]** Origin Hunt - CDN bypass (18 sources)
- **[P]** Proxy Harvest - Auto proxy collection
- **[9]** Auto Mode - AI-driven adaptive attack

## Cloudflare Bypass Modules (New in v6.0)

### HTTP/2 Fingerprint Impersonation
Spoofs browser-specific HTTP/2 fingerprints including SETTINGS frame order, WINDOW_UPDATE sizes, and PRIORITY frame patterns for Chrome 126+ and Firefox 130+.

### AI-Powered Behavioral Evasion
- Markov chain timing generator for realistic request intervals
- Canvas/WebGL noise injection
- Session diversity (5 human behavior templates)
- nodriver integration for stealth browser automation

### Origin Discovery Enhancement
18 passive DNS sources including AnubisDB, RapidDNS, ThreatMiner, URLScan, Wayback CDX, CertSpotter, and VirusTotal. WAF bypass logic for health check endpoints, ACME validation, and CDN misconfiguration exploitation.

### FlareSolverr Integration
Automatic Cloudflare challenge solving via external service. SQLite-based cookie persistence and residential proxy support with BrightData, Oxylabs, and IPRoyal templates.

### WAF Parsing Discrepancy Fuzzing
20 proven bypass methods including Transfer-Encoding smuggling, Content-Type boundary ambiguity, method spoofing, path normalization confusion, and HTTP Request Smuggling detection (CL.TE, TE.CL).

## Advanced Modules

### Advanced 2026 Attack
Combines multiple bypass techniques:
- AI behavioral mimicry with Markov chain timing
- HTTP/2 browser fingerprint impersonation
- TLS/Canvas/WebGL fingerprint evasion (JA3/JA4)
- Origin discovery (18 sources)
- Cache poisoning
- WAF parsing bypass fuzzing
- Adaptive learning

### Business Logic Attack
Low-volume, high-impact targeting:
- Complex database queries
- Expensive API operations
- Payment processing
- 2FA/SMS operations

### SEO Attack
Negative SEO techniques:
- Toxic backlink generation (10k+)
- GSC spam
- Content scraping
- Competitor manipulation

## FlareSolverr Setup (Optional)

For Cloudflare challenge bypass:
```bash
docker run -d --name flaresolverr -p 8191:8191 ghcr.io/flaresolverr/flaresolverr:latest
```

## Configuration

Edit `config/default.yaml`:
```yaml
attack:
  default_duration: 300
  initial_rps: 5000
  max_rps: 50000

proxy:
  connect_timeout: 3
  min_pool: 5

flaresolverr:
  endpoint: "http://localhost:8191"
  timeout: 30

http2:
  default_profile: "chrome126"
  profiles: ["chrome126", "firefox130", "edge126", "safari17.4"]
```

## Performance

| Metric | v5.0 | v6.0 | Improvement |
|--------|------|------|-------------|
| RPS | 2.5 | 300-900 | 120x-360x |
| Concurrency | 33-500 | 200-2000 | 6x-60x |
| Workers | 16 | 500 | 31x |
| Session Pool | 20 | 500 | 25x |
| Max RPS | 10k | 50k | 5x |
| Origin Sources | 11 | 18 | 1.6x |
| WAF Bypass Methods | 0 | 20 | New |
| CF Block Rate | >70% | <30%* | 2.3x |

*Estimated with all bypass techniques enabled.

## Legal Notice

For authorized security testing only. Unauthorized use is illegal.

## Version

v6.0 (2026-05-25)
