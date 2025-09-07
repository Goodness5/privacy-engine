#!/bin/bash

# Simple Privacy Engine WebAssembly Build Script

set -e

echo "🔐 Building Privacy Engine for WebAssembly (Simple Version)..."

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
mkdir -p wasm-client/pkg

# Build for web target with optimizations
echo "📦 Building for web target with optimizations..."
wasm-pack build --target web --out-dir wasm-client/pkg --release

echo "✅ WebAssembly build completed!"
echo ""
echo "📁 Output directory: wasm-client/pkg/"
echo ""
echo "🚀 To test the simple demo:"
echo "   1. Open demo/simple.html in your browser"
echo "   2. Or serve it with: python -m http.server 8000"
echo "   3. Then open http://localhost:8000/demo/simple.html"
echo ""
echo "📚 For development builds, use --dev flag:"
echo "   wasm-pack build --target web --out-dir wasm-client/pkg --dev"
