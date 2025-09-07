#!/bin/bash

# Privacy Engine WebAssembly Build Script

set -e

echo "🔐 Building Privacy Engine for WebAssembly..."

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ wasm-pack is not installed. Installing..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Please run this script from the project root directory"
    exit 1
fi

# Create wasm-client directory if it doesn't exist
mkdir -p wasm-client

# Build for web target
echo "📦 Building for web target..."
wasm-pack build --target web --out-dir wasm-client/pkg --dev

# Build for bundler target (for use with webpack, etc.)
echo "📦 Building for bundler target..."
wasm-pack build --target bundler --out-dir wasm-client/pkg-bundler --dev

# Build for nodejs target
echo "📦 Building for nodejs target..."
wasm-pack build --target nodejs --out-dir wasm-client/pkg-nodejs --dev

echo "✅ WebAssembly build completed!"
echo ""
echo "📁 Output directories:"
echo "   - wasm-client/pkg/ (web target)"
echo "   - wasm-client/pkg-bundler/ (bundler target)"
echo "   - wasm-client/pkg-nodejs/ (nodejs target)"
echo ""
echo "🚀 To test the demo:"
echo "   1. cd demo"
echo "   2. python -m http.server 8000"
echo "   3. Open http://localhost:8000 in your browser"
echo ""
echo "📚 For production builds, use --release flag:"
echo "   wasm-pack build --target web --out-dir wasm-client/pkg --release"
