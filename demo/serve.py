#!/usr/bin/env python3
"""
Simple HTTP server for serving the Privacy Engine demo
"""

import http.server
import socketserver
import os
import sys
from pathlib import Path

# Get the project root directory
project_root = Path(__file__).parent.parent
demo_dir = Path(__file__).parent

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers for WASM
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_GET(self):
        # Handle WASM files with correct MIME type
        if self.path.endswith('.wasm'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/wasm')
            self.end_headers()
            with open(demo_dir / '..' / 'wasm-client' / 'pkg' / 'privacy_engine_bg.wasm', 'rb') as f:
                self.wfile.write(f.read())
            return
        
        # Handle JS files
        if self.path.endswith('.js'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.end_headers()
            with open(demo_dir / '..' / 'wasm-client' / 'pkg' / 'privacy_engine.js', 'r') as f:
                self.wfile.write(f.read().encode())
            return
        
        # Default handling
        super().do_GET()

def main():
    port = 8000
    
    # Change to demo directory
    os.chdir(demo_dir)
    
    print(f"🚀 Starting Privacy Engine Demo Server")
    print(f"📁 Serving from: {demo_dir}")
    print(f"🌐 Server running at: http://localhost:{port}")
    print(f"📄 Demo pages:")
    print(f"   - Working Demo: http://localhost:{port}/working-demo.html")
    print(f"   - Simple Demo: http://localhost:{port}/simple.html")
    print(f"   - Argent Demo: http://localhost:{port}/argent-demo.html")
    print(f"   - Full Demo: http://localhost:{port}/index.html")
    print(f"\n⏹️  Press Ctrl+C to stop the server")
    
    try:
        with socketserver.TCPServer(("", port), CustomHTTPRequestHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n🛑 Server stopped")
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"❌ Port {port} is already in use. Try a different port:")
            print(f"   python3 serve.py --port 8001")
        else:
            print(f"❌ Error starting server: {e}")
            sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--port":
        port = int(sys.argv[2])
    main()
