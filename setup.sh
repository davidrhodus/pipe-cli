#!/bin/bash

set -e

echo "🎯 Installing system dependencies..."
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev git curl

# Check if Rust is already installed
if command -v rustc &> /dev/null
then
    echo "✅ Rust is already installed. Skipping rustup installation."
else
    echo "🚀 Installing rustup..."
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source $HOME/.cargo/env
fi

echo "📦 Cloning Pipe repo..."
git clone https://github.com/PipeNetwork/pipe.git
cd pipe

echo "🔧 Building pipe CLI..."
cargo install --path .

echo "✅ Done! Test with:"
echo ""
echo "    pipe --help"
