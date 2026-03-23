#!/bin/bash

# OAI-UPF Web Monitoring System - Startup Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
WEBUI_DIR="$SCRIPT_DIR"
PORT=5001

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       OAI-UPF Web Monitoring System - Startup Script${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# 1. [New] Check Root permission
# BPF tools (bpftool) require Root permission to read maps
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this script with sudo!${NC}"
  echo -e "Usage: sudo ./webui/start_webui.sh"
  exit 1
fi

# 2. [New] Auto cleanup old processes occupying the port
echo -e "${YELLOW}Checking port $PORT status...${NC}"
# Find PID of process occupying port 5001
PID=$(lsof -t -i:$PORT)
if [ -n "$PID" ]; then
    echo -e "${YELLOW}Port $PORT is occupied (PID: $PID), cleaning up...${NC}"
    kill -9 $PID
    sleep 1
    echo -e "${GREEN}✓${NC} Old process cleaned up"
else
    echo -e "${GREEN}✓${NC} Port $PORT is available"
fi

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 not found, please install Python 3 first${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Python3 installed: $(python3 --version)"

# Check pip3
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 not found, please install pip3 first${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} pip3 installed"

# Check if dependencies need to be installed
REQUIREMENTS_FILE="$WEBUI_DIR/requirements.txt"
if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo -e "${RED}Error: requirements.txt not found${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Checking Python dependencies...${NC}"

# Check and install dependencies (simplified check logic)
# Directly try to install, pip will skip if already installed, which is safer
pip3 install -r "$REQUIREMENTS_FILE" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}⚠ Dependency installation may have issues, trying to continue...${NC}"
else
    echo -e "${GREEN}✓${NC} Python dependencies check completed"
fi

# Check data directory
DATA_DIR="$WEBUI_DIR/data"
if [ ! -d "$DATA_DIR" ]; then
    echo -e "${YELLOW}Creating data directory...${NC}"
    mkdir -p "$DATA_DIR"
    echo -e "${GREEN}✓${NC} Data directory created: $DATA_DIR"
fi

# Check bpftool
echo ""
echo -e "${YELLOW}Checking BPF tools...${NC}"
if ! command -v bpftool &> /dev/null; then
    echo -e "${YELLOW}⚠${NC}  Warning: bpftool not found, BPF statistics feature will be unavailable"
    echo -e "${YELLOW}   Hint: Please run 'apt-get install linux-tools-common linux-tools-generic' to install${NC}"
else
    echo -e "${GREEN}✓${NC} bpftool installed"
fi

# Check config file
CONFIG_FILE="$SCRIPT_DIR/../etc/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}⚠${NC}  Warning: UPF config file not found: $CONFIG_FILE"
    echo -e "${YELLOW}   Config panel may display incomplete information${NC}"
else
    echo -e "${GREEN}✓${NC} UPF config file found"
fi

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${GREEN}Starting Web Monitoring Server...${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "Local access: ${GREEN}http://localhost:$PORT${NC}"
# Get first non-loopback IP
HOST_IP=$(hostname -I | awk '{print $1}')
echo -e "Remote access: ${GREEN}http://$HOST_IP:$PORT${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo ""

# Start Flask server
cd "$BACKEND_DIR"
# Use sudo -E to preserve environment variables (optional)
python3 api_server.py