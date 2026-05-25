#!/bin/bash
# Tor Auto-Installer v8.0
# Cross-platform: Windows (Git Bash/WSL), Linux, macOS

set -e

echo "--------------------------------------------------------------------------------"
echo "Tor Auto-Installer v8.0"
echo "--------------------------------------------------------------------------------"

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM=linux;;
    Darwin*)    PLATFORM=macos;;
    CYGWIN*)    PLATFORM=windows;;
    MINGW*)     PLATFORM=windows;;
    MSYS*)      PLATFORM=windows;;
    *)          PLATFORM="unknown";;
esac

echo "Detected platform: ${PLATFORM}"

# Check if Tor is already installed
if command -v tor &> /dev/null; then
    echo "Tor is already installed: $(tor --version | head -n1)"
    exit 0
fi

# Install based on platform
case "${PLATFORM}" in
    linux)
        echo "Installing Tor on Linux..."
        
        # Detect package manager
        if command -v apt &> /dev/null; then
            echo "Using apt package manager..."
            sudo apt update
            sudo apt install -y tor tor-geoipdb
            sudo systemctl enable tor
            sudo systemctl start tor
            echo "Tor installed and started via systemd"
            
        elif command -v yum &> /dev/null; then
            echo "Using yum package manager..."
            sudo yum install -y tor
            sudo systemctl enable tor
            sudo systemctl start tor
            echo "Tor installed and started via systemd"
            
        elif command -v dnf &> /dev/null; then
            echo "Using dnf package manager..."
            sudo dnf install -y tor
            sudo systemctl enable tor
            sudo systemctl start tor
            echo "Tor installed and started via systemd"
            
        else
            echo "ERROR: No supported package manager found (apt/yum/dnf)"
            exit 1
        fi
        ;;
        
    macos)
        echo "Installing Tor on macOS..."
        
        # Check if Homebrew is installed
        if ! command -v brew &> /dev/null; then
            echo "ERROR: Homebrew not found. Please install Homebrew first:"
            echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            exit 1
        fi
        
        brew install tor
        brew services start tor
        echo "Tor installed and started via Homebrew services"
        ;;
        
    windows)
        echo "Installing Tor on Windows..."
        echo "Please run the PowerShell installer instead:"
        echo "  powershell -ExecutionPolicy Bypass -File bin/tor_setup.ps1"
        exit 1
        ;;
        
    *)
        echo "ERROR: Unsupported platform: ${PLATFORM}"
        exit 1
        ;;
esac

# Verify installation
if command -v tor &> /dev/null; then
    echo "--------------------------------------------------------------------------------"
    echo "Tor installation successful!"
    echo "Version: $(tor --version | head -n1)"
    echo "--------------------------------------------------------------------------------"
else
    echo "ERROR: Tor installation failed"
    exit 1
fi
