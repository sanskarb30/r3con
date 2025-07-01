#!/bin/bash

echo -e "\e[1;34m[+] Starting Security Breach Setup...\e[0m"

sudo apt update && sudo apt install -y python3 python3-pip python3-venv dos2unix

dos2unix secbreach.py

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install requests

echo -e "\e[1;32m[+] Setup complete. Activate with: source venv/bin/activate && python3 secbreach.py <target>\e[0m"