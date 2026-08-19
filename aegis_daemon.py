import http.server
import socketserver
import json
import gc
import psutil
import datetime
import os

PORT = 19023

class AegisRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/api/telemetry", "/telemetry"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            mem = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=None)
            net = psutil.net_io_counters()

            payload = {
                "status": "online",
                "system": "Aegis Core v1.2.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "telemetry": {
                    "ram_total_gb": round(mem.total / (1024**3), 2),
                    "ram_used_gb": round(mem.used / (1024**3), 2),
                    "ram_percentage": mem.percent,
                    "cpu_load_pct": cpu,
                    "bytes_sent": net.bytes_sent,
                    "bytes_recv": net.bytes_recv
                }
            }
            self.wfile.write(json.dumps(payload, indent=2).encode('utf-8'))

        elif self.path == "/api/gc":
            collected = gc.collect()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"status": "ok", "python_objects_collected": collected}
            self.wfile.write(json.dumps(response).encode('utf-8'))

        else:
            if self.path == "/" or not os.path.exists(self.path[1:]):
                self.path = "/index.html"
            return super().do_GET()

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), AegisRequestHandler) as httpd:
        print(f"/{datetime.datetime.now().isoformat()}] Aegis v1.2.0 Core Active")
        print(f"[Aegis API] Operational Console live at http://127.0.0.1:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[Aegis] Shutting down gracefully.")

if __name__ == "__main__":
    run_server()