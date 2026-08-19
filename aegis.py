#!/usr/bin/env python3
"""
Aegis Core Utility for QARMR - API Edition
This module handles core integrity checks, system logging,
and now features an embedded HTTP API to serve telemetry.
"""

import os
import sys
import json
import hashlib
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

class AegisSystem:
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.version = "1.1.0"
        self.boot_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def generate_checksum(self, file_path):
        """Generates a SHA-256 checksum for a given file to ensure integrity."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return None

    def audit_environment(self):
        """Performs a basic environment and file structure audit."""
        report = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "python_version": sys.version.split(" ")[0],
            "platform": sys.platform,
            "working_directory": os.getcwd(),
            "files_present": os.listdir(".")[:10]
        }
        return report

class AegisAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handles incoming GET requests."""
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            aegis = AegisSystem()
            response_data = {
                "status": "online",
                "identity": "Aegis Core for QARMR",
                "telemetry": aegis.audit_environment()
            }
            self.wfile.write(json.dumps(response_data, indent=2).encode('utf-8'))
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            error_msg = {"error": "Endpoint not found"}
            self.wfile.write(json.dumps(error_msg).encode('utf-8'))

    def log_message(self, format, *args):
        """Custom logging format to keep terminal clean."""
        print(f"[Aegis API Log] {self.client_address[0]} requested {self.path} - Status: {args[1]}")

def run_server(port=19023):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, AegisAPIHandler)

    aegis = AegisSystem()
    print(f"[Aegis v{aegis.version}] Initializing system at {aegis.boot_time}...")
    print(f"[Aegis API] Server listening on http://127.0.0.1:{port}")
    print(f"[Aegis API] Waiting for requests... (Press Ctrl+C to stop)")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Aegis] Shutting down gracefully.")
        httpd.server_close()

if __name__ == "__main__":
    run_server()

