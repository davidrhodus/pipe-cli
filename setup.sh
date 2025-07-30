#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}🎯 Installing system dependencies...${NC}"
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev git curl

MIN_RUST_VERSION="1.70.0"
should_install_rust=false

if command -v rustc &> /dev/null && command -v cargo &> /dev/null; then
    INSTALLED_RUST_VERSION=$(rustc --version | awk '{print $2}')
    echo -e "${CYAN}🔍 Detected rustc ${INSTALLED_RUST_VERSION}${NC}"

    if [ "$(printf '%s\n' "$INSTALLED_RUST_VERSION" "$MIN_RUST_VERSION" | sort -V | head -n1)" != "$MIN_RUST_VERSION" ]; then
        echo -e "${YELLOW}⚠️ Rust version is too old (< ${MIN_RUST_VERSION}). Updating via rustup...${NC}"
        should_install_rust=true
    else
        echo -e "${GREEN}✅ Rust version is sufficient. Skipping installation.${NC}"
    fi
else
    echo -e "${YELLOW}🚫 Rust or Cargo not found.${NC}"
    should_install_rust=true
fi

if [ "$should_install_rust" = true ]; then
    echo -e "${CYAN}🚀 Installing rustup (Rust & Cargo)...${NC}"
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source $HOME/.cargo/env
fi

# Handle --force flag
if [[ "$1" == "--force" ]]; then
    echo -e "${YELLOW}⚠️ --force enabled. Removing existing 'pipe' folder...${NC}"
    rm -rf pipe
fi

if [ -d "pipe" ]; then
    echo -e "${YELLOW}📁 'pipe' folder already exists. Skipping clone.${NC}"
else
    echo -e "${CYAN}📦 Cloning Pipe repo...${NC}"
    git clone https://github.com/PipeNetwork/pipe.git
fi
cd pipe

echo -e "${CYAN}🔧 Building Pipe CLI...${NC}"
if cargo install --path .; then
    echo -e "${GREEN}✅ Build successful!${NC}"
else
    echo -e "${RED}❌ Build failed. Please check the error log.${NC}"
    exit 1
fi

if command -v pipe &> /dev/null; then
    echo -e "\n${GREEN}🚀 All set! You can now run:${NC}"
    echo -e "    ${CYAN}pipe --help${NC}\n"
else
    echo -e "\n${RED}⚠️ Setup complete, but 'pipe' command not found in PATH.${NC}"
    echo -e "${YELLOW}You might need to restart your terminal or add ~/.cargo/bin to PATH.${NC}\n"
fi
