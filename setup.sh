#!/bin/bash

set -e

echo "🚀 Installing rustup..."
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env

echo "🎯 install Dependensi..."
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev git curl

echo "📦 Cloning Pipe repo..."
git clone https://github.com/PipeNetwork/pipe.git
cd pipe

echo "🔧 Building pipe CLI..."
cargo install --path .

echo "📁 Moving pipe binary to /usr/local/bin..."
sudo cp target/release/pipe /usr/local/bin/pipe

echo "✅ Done! Test with:"
echo ""
echo "    pipe --help"
