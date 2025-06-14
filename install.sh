#!/bin/bash

echo "[*] Updating system packages..."
sudo apt update

echo "[*] Installing Python 3 and pip..."
sudo apt install -y python3 python3-pip

echo "[*] Installing required Python packages..."
pip3 install -r requirements.txt

echo "[✓] Audit_Forge is ready. Run it with: python3 audit_forge.py"
