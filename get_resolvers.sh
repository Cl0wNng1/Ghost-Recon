#!/bin/bash
# get_resolvers.sh - Updates the high-speed DNS resolver list for Step 02
echo "[*] Downloading fresh trusted resolvers..."
curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt > resolvers.txt
echo "[+] resolvers.txt updated. MassDNS is now ready for Step 02."