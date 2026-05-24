# KILLER ENGINE V2.0 - VPS Installation Guide

## 🚀 Quick Install (Linux VPS)

### 1. System Requirements
- **OS**: Ubuntu 20.04+, Debian 11+, CentOS 8+
- **RAM**: Minimum 2GB (Recommended 4GB+)
- **CPU**: 2+ cores
- **Python**: 3.8+

### 2. Install Python & Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.10+
sudo apt install python3 python3-pip python3-venv git -y

# Verify Python version
python3 --version  # Should be 3.8+
```

### 3. Clone/Upload Project

**Option A: Git Clone (if repo available)**
```bash
git clone <your-repo-url> Ddos
cd Ddos
```

**Option B: Upload via SCP**
```bash
# From your Windows machine:
scp -r C:\laragon\www\Ddos root@YOUR_VPS_IP:/root/
```

**Option C: Upload via FTP/SFTP**
Use FileZilla or WinSCP to upload the entire `Ddos` folder

### 4. Setup Virtual Environment

```bash
cd Ddos

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 5. Configure Premium Proxies

Make sure your premium proxies are in the correct format:
```bash
cat proxies/premium_proxy.txt
# Should show: http://user:pass@ip:port
```

### 6. Run Attack

**Quick Launch (Recommended)**
```bash
python3 launch_extreme.py
```

**Or via Menu**
```bash
python3 main.py --start
# Select [9] Auto Mode
```

### 7. Run in Background (tmux/screen)

**Using tmux (Recommended)**
```bash
# Install tmux
sudo apt install tmux -y

# Start tmux session
tmux new -s attack

# Run attack
python3 launch_extreme.py

# Detach: Press Ctrl+B then D
# Reattach: tmux attach -t attack
```

**Using screen**
```bash
# Install screen
sudo apt install screen -y

# Start screen session
screen -S attack

# Run attack
python3 launch_extreme.py

# Detach: Press Ctrl+A then D
# Reattach: screen -r attack
```

### 8. Monitor Performance

```bash
# CPU/RAM usage
htop

# Network usage
iftop

# Process info
ps aux | grep python
```

---

## 🪟 Windows Installation

### 1. Requirements
- Windows 10/11
- Python 3.8+
- Already installed at: `C:\laragon\www\Ddos`

### 2. Run Attack

**Quick Launch**
```cmd
cd C:\laragon\www\Ddos
python launch_extreme.py
```

**Or via Menu**
```cmd
python main.py --start
```

---

## ⚙️ Configuration

### Default Settings (launch_extreme.py)
- **Duration**: 3600s (1 hour)
- **RPS**: 7000
- **Proxies**: Auto-load from `proxies/premium_proxy.txt`

### Custom Settings
Edit `config/auto_mode.json`:
```json
{
  "phases": {
    "phase_3_peak": {
      "rps_factor": 3.50  // Multiply target RPS
    }
  },
  "engine": {
    "pipeline_depth": 48,
    "connection_pool_per_worker": 400
  }
}
```

---

## 🔥 Performance Tuning

### Linux VPS Optimization

**1. Increase file descriptors**
```bash
# Edit limits
sudo nano /etc/security/limits.conf

# Add these lines:
* soft nofile 65535
* hard nofile 65535

# Reboot or re-login
```

**2. TCP tuning**
```bash
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sudo sysctl -w net.core.somaxconn=65535
```

**3. Install uvloop (faster event loop)**
```bash
pip install uvloop
# Automatically used on Linux
```

### Windows Optimization
- Already optimized in code
- Uses `WindowsSelectorEventLoopPolicy`
- Process priority: BELOW_NORMAL

---

## 📊 Expected Performance

### With 1000 Premium Proxies
- **Connections**: 1500 held + 800 flood + 400 POST = 2700 total
- **RPS**: 7000 × 3.5 = 24,500 peak RPS
- **Duration**: 1 hour = 88 million requests
- **Bandwidth**: ~500 MB/s (depends on POST size)

### VPS Specs Recommendation
| Target RPS | RAM | CPU | Bandwidth |
|------------|-----|-----|-----------|
| 5,000 | 2GB | 2 cores | 100 Mbps |
| 10,000 | 4GB | 4 cores | 500 Mbps |
| 20,000 | 8GB | 8 cores | 1 Gbps |

---

## 🐛 Troubleshooting

### "Too many open files"
```bash
ulimit -n 65535
```

### "Connection refused"
- Check firewall: `sudo ufw status`
- Check if target is blocking your IP

### "Out of memory"
- Reduce `connection_pool_per_worker` in config
- Reduce `workers_per_vector`

### Slow performance on VPS
- Install uvloop: `pip install uvloop`
- Check CPU: `htop`
- Check network: `iftop`

---

## 📝 Notes

- **Legal**: Use only on targets you own or have permission to test
- **Proxies**: Premium proxies recommended for Cloudflare targets
- **Duration**: Start with 5 minutes for testing, then scale to 1 hour
- **Monitoring**: Use tmux/screen to keep attack running after disconnect

---

## 🆘 Support

If you encounter issues:
1. Check logs in terminal
2. Verify proxy format: `http://user:pass@ip:port`
3. Test with shorter duration first (300s)
4. Reduce RPS if system is overloaded

**Platform Detection**: Script automatically detects Windows/Linux and applies appropriate optimizations.
