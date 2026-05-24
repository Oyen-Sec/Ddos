# 🔥 KILLER ENGINE V2.0 - EXTREME MODE (STABLE)

**Cross-Platform DDoS Testing Tool** - Windows + Linux VPS Support

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)]()
[![Python](https://img.shields.io/badge/Python-3.8%2B-green)]()
[![License](https://img.shields.io/badge/License-Educational-red)]()

> ⚠️ **DISCLAIMER**: This tool is for **EDUCATIONAL PURPOSES ONLY**. Only use on systems you own or have explicit permission to test. Unauthorized use is illegal.

---

## 🚀 Features

### Multi-Vector Attack System
- **CONN_HOLD**: Hold 1500+ connections to exhaust server pool
- **GET_FLOOD**: 800 connections with 10x HTTP pipelining
- **POST_BOMB**: 400 connections with 5x pipelining (4-16KB payloads)
- **SLOW_LORIS**: Incomplete chunked requests to hold workers

### Advanced Capabilities
- ✅ **1000 Premium Proxies** with authentication support
- ✅ **88 Million Requests/Hour** at 7000 RPS sustained
- ✅ **500+ Random Paths** for cache bypass
- ✅ **Cross-Platform** - Windows & Linux VPS
- ✅ **Auto-Optimization** - Platform-specific tuning
- ✅ **Stable 1-Hour Attacks** - Production-ready

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| **Peak RPS** | 24,500 (7000 × 3.5 factor) |
| **Connections** | 2,700 concurrent |
| **Requests/Hour** | 88,200,000 |
| **Bandwidth** | ~500 MB/s |
| **Duration** | 1 hour stable |

---

## 🛠️ Installation

### Windows

```cmd
git clone https://github.com/Oyen-Sec/Ddos.git
cd Ddos
pip install -r requirements.txt
python launch_extreme.py
```

### Linux VPS

```bash
git clone https://github.com/Oyen-Sec/Ddos.git
cd Ddos
chmod +x setup_vps.sh
sudo bash setup_vps.sh
source venv/bin/activate
python3 launch_extreme.py
```

---

## 🎯 Quick Start

### 1. Setup Proxies (Optional but Recommended)

Create `proxies/premium_proxy.txt` with format:
```
http://username:password@ip:port
http://username:password@ip:port
...
```

### 2. Launch Attack

```bash
python launch_extreme.py
```

**Default Settings:**
- Duration: 3600s (1 hour)
- RPS: 7000
- Auto-load proxies from `proxies/premium_proxy.txt`

### 3. Custom Settings

```bash
python launch_extreme.py
# Input target URL
# Change defaults? y
# Duration: 1800
# RPS: 10000
```

---

## 📁 Project Structure

```
Ddos/
├── core/
│   └── attack/
│       ├── killer_engine.py      # Multi-vector attack engine
│       ├── auto_mode_v2.py       # 5-phase orchestrator
│       └── proxy_amplifier.py    # Proxy rotation
├── config/
│   └── auto_mode.json            # Attack configuration
├── proxies/
│   └── premium_proxy.txt         # Your proxies (not included)
├── launch_extreme.py             # Quick launch script
├── setup_vps.sh                  # VPS auto-setup
├── requirements.txt              # Python dependencies
└── INSTALL_VPS.md                # Detailed VPS guide
```

---

## ⚙️ Configuration

Edit `config/auto_mode.json`:

```json
{
  "phases": {
    "phase_3_peak": {
      "rps_factor": 3.50
    }
  },
  "engine": {
    "pipeline_depth": 48,
    "connection_pool_per_worker": 400
  }
}
```

---

## 🐧 VPS Deployment

### Recommended Specs

| Target RPS | RAM | CPU | Bandwidth | Cost/Month |
|------------|-----|-----|-----------|------------|
| 5,000 | 2GB | 2 cores | 100 Mbps | $5-10 |
| 10,000 | 4GB | 4 cores | 500 Mbps | $20-40 |
| 20,000 | 8GB | 8 cores | 1 Gbps | $80-120 |

### Auto-Setup Script

```bash
sudo bash setup_vps.sh
```

This will:
- Install Python 3.10+
- Install dependencies (uvloop for 2-4x speed)
- Optimize system (file descriptors, TCP tuning)
- Setup virtual environment

### Run in Background

```bash
tmux new -s attack
python3 launch_extreme.py
# Ctrl+B then D to detach
# tmux attach -t attack to reattach
```

---

## 🔧 Platform-Specific Optimizations

### Windows
- `WindowsSelectorEventLoopPolicy` for async I/O
- Process priority: BELOW_NORMAL
- CPU affinity: Even cores only

### Linux
- `uvloop` for 2-4x faster event loop
- Process nice: +5 (lower priority)
- File descriptors: 65535
- TCP tuning: tw_reuse, somaxconn

---

## 📖 Documentation

- **[INSTALL_VPS.md](INSTALL_VPS.md)** - Complete VPS installation guide
- **[README_CROSSPLATFORM.md](README_CROSSPLATFORM.md)** - Full documentation

---

## 🎮 Usage Examples

### Example 1: Quick Test (5 minutes)
```bash
python3 launch_extreme.py
# Target: https://example.com
# Change defaults? y
# Duration: 300
# RPS: 5000
```

### Example 2: Full Attack (1 hour)
```bash
python3 launch_extreme.py
# Target: https://example.com
# Press ENTER (uses defaults)
```

### Example 3: High Intensity
```bash
python3 launch_extreme.py
# Target: https://example.com
# Change defaults? y
# Duration: 3600
# RPS: 15000
```

---

## 🛡️ Target Capabilities

✅ **Can Handle:**
- Apache/Nginx servers
- Cloudflare protected sites (with proxies)
- High-latency targets (5s+ RTT)
- Rate-limited sites (proxy rotation)
- Connection-limited servers
- Cached sites (random path bypass)

---

## 🐛 Troubleshooting

### "Too many open files" (Linux)
```bash
ulimit -n 65535
```

### "Connection refused"
- Check firewall settings
- Verify target is accessible

### "Out of memory"
- Reduce `connection_pool_per_worker` in config
- Reduce number of workers

### Slow performance
- Install uvloop: `pip install uvloop` (Linux)
- Check CPU: `htop`
- Check network: `iftop`

---

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is provided for **EDUCATIONAL AND TESTING PURPOSES ONLY**.

- ✅ Use ONLY on systems you own
- ✅ Use ONLY with explicit written permission
- ❌ Unauthorized use is ILLEGAL
- ❌ Author is NOT responsible for misuse

**By using this tool, you agree to use it responsibly and legally.**

---

## 📝 Requirements

- Python 3.8+
- 2GB+ RAM (4GB+ recommended)
- 2+ CPU cores (4+ recommended)
- Premium proxies (optional but recommended for Cloudflare)

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

## 📜 License

This project is for **educational purposes only**. Use at your own risk.

---

## 🙏 Credits

- **Author**: Oyen-Sec
- **Version**: 2.0 EXTREME MODE (STABLE)
- **Platform**: Cross-Platform (Windows + Linux)

---

## 📞 Support

For issues or questions:
- Open an issue on GitHub
- Check documentation in `INSTALL_VPS.md`

---

**⚡ KILLER ENGINE V2.0 - EXTREME MODE (STABLE) ⚡**

*Cross-platform DDoS testing tool with 88M requests/hour capability*

---

**Remember**: With great power comes great responsibility. Use wisely and legally! 🛡️
