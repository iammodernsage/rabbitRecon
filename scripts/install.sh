#!/bin/bash
# rabbitRecon installation script

set -e

# Check for root on Linux
if [[ "$OSTYPE" == "linux-gnu"* ]] && [ "$EUID" -ne 0 ]; then
  echo "Please run as root for installation"
  exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BLUE='\033[0;34m'

# Check dependencies
check_deps() {
  local missing=0

  # Required tools
  for cmd in python3 pip3 gcc make; do
    if ! command -v $cmd &> /dev/null; then
      echo -e "${RED}[ERROR] Missing required tool: $cmd${NC}"
      missing=1
    fi
  done

  # Python version check
  PYTHON_VERSION=$(python3 -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')
  if [[ "$PYTHON_VERSION" < "3.7" ]]; then
    echo -e "${RED}[ERROR] Python 3.7 or higher required${NC}"
    missing=1
  fi

  return $missing
}

# Install Python dependencies
install_python_deps() {
  echo -e "${YELLOW}[INFO] Installing Python dependencies...${NC}"
  pip3 install -r requirements.txt
}

# Build C components
build_core() {
  echo -e "${YELLOW}[INFO] Building core components...${NC}"
  make -C "$(pwd)" build
}

# Install the tool
install_tool() {
  echo -e "${YELLOW}[INFO] Installing rabbitRecon...${NC}"

  # Install Python package
  pip3 install .

  # Install core library
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    cp core/libreconx.so /usr/local/lib/
    ldconfig
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    cp core/libreconx.so /usr/local/lib/
  fi

  # Create config directory
  mkdir -p /etc/rabbitRecon
  cp rabbitRecon.conf.example /etc/rabbitRecon/rabbitRecon.conf

  echo -e "${GREEN}[SUCCESS] Installation completed!${NC}"
}

# Main installation flow
echo -e "${YELLOW}Starting rabbitRecon installation...${NC}"

if ! check_deps; then
  echo -e "${RED}[ERROR] Missing dependencies, please install them first${NC}"
  exit 1
fi

install_python_deps
build_core
install_tool

echo -e "${BLUE}rabbitRecon has been successfully installed!${NC}"
echo "Run 'rabbitRecon --help' to get started"
