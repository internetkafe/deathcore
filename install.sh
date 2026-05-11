#!/usr/bin/env bash
set -e

# 1. Install unzip if missing
if ! command -v unzip &>/dev/null; then
  echo "Installing unzip..."
  sudo apt-get update -qq
  sudo apt-get install -y unzip
fi

# 2. Install Go 1.22.3 if missing or wrong version
if ! command -v go &>/dev/null || [[ "$(go version)" != *"go1.22.3"* ]]; then
  echo "Installing Go 1.22.3..."
  wget -qO go1.22.3.linux-amd64.tar.gz https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
  rm go1.22.3.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  if ! grep -qxF 'export PATH=$PATH:/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  fi
fi

# 3. Install xray-core (latest)
if ! command -v xray &>/dev/null; then
  echo "Installing xray-core..."
  XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest \
             | grep -Po '"tag_name": "\K.*?(?=")')
  wget -qO xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip"
  unzip -qo xray.zip -d xray_tmp
  sudo mv xray_tmp/xray /usr/local/bin/xray
  sudo chmod +x /usr/local/bin/xray
  rm -rf xray.zip xray_tmp
fi

echo "✔ Dependencies installed."
echo "Now build the project:"
echo "  cd deathcore"
echo "  go mod tidy"
echo "  go build -o deathcore ."
