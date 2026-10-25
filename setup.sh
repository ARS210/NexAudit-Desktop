#!/usr/bin/env bash
#
# NexAudit setup script
# Checks for required system tools and offers to install missing ones
# on Debian/Ubuntu-based systems. Safe to re-run.

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${BOLD}NexAudit setup${RESET}"
echo "Checking prerequisites..."
echo

missing=()

check_cmd() {
    local cmd="$1"
    if command -v "$cmd" >/dev/null 2>&1; then
        echo -e "  [${GREEN}ok${RESET}] $cmd found"
    else
        echo -e "  [${RED}missing${RESET}] $cmd not found"
        missing+=("$cmd")
    fi
}

check_cmd python3
check_cmd airmon-ng
check_cmd airodump-ng

echo
if python3 -c "import tkinter" >/dev/null 2>&1; then
    echo -e "  [${GREEN}ok${RESET}] python3 tkinter module available"
else
    echo -e "  [${RED}missing${RESET}] python3 tkinter module not available"
    missing+=("python3-tk")
fi

echo

if [ ${#missing[@]} -eq 0 ]; then
    echo -e "${GREEN}All prerequisites satisfied.${RESET} Run: python3 main.py"
    exit 0
fi

echo -e "${YELLOW}Missing components:${RESET} ${missing[*]}"

if command -v apt-get >/dev/null 2>&1; then
    echo
    read -rp "Install missing packages with apt now? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        sudo apt-get update
        sudo apt-get install -y aircrack-ng python3-tk
        echo -e "${GREEN}Done.${RESET} Re-run setup.sh to verify, then: python3 main.py"
    else
        echo "Skipped. Install manually with:"
        echo "  sudo apt-get install aircrack-ng python3-tk"
    fi
else
    echo "Automatic install is only wired up for apt-based distros here."
    echo "Install the aircrack-ng suite and python3-tk using your"
    echo "distro's package manager, then re-run this script."
fi
