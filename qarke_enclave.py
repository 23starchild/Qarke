#!/usr/bin/env python3
import socket
import json
import hashlib
import time
import hmac

# --- ENCLAVE CONFIGURATION ---
ENCLAVE_HOST = '127.0.0.1'
ENCLAVE_PORT = 50051 # Highly restricted loopback port
ENCLAVE_SECRET = b"QARKE_SUPER_SECRET_ENCLAVE_KEY_2026"
ALLOWED_ALGORITHMS = ["CRYSTALS-Kyber", "NTRU-HRSS", "SPHINCS+"]

def generate_validation_token(payload):
    """Generates an Enclave Validation Token (EVT) if the payload is valid."""
    # 1. Check for Quantum-Agile algorithm compliance
    if payload.get("kyber_alg") not in ALLOWED_ALGORITHMS:
        return {"status": "REJECTED", "reason": "Unsupported Quantum Algorithm"}
    
    # 2. Verify structure
    if not payload.get("public_key_capsule") or not payload.get("nonce"):
        return {"status": "REJECTED", "reason": "Malformed Cryptographic Metadata"}

    # 3. Generate EVT (Enclave Validation Token)
    msg = f"{payload['kyber_alg']}:{payload['nonce']}:{payload['public_key_capsule']}".encode()
    signature = hmac.new(ENCLAVE_SECRET, msg, hashlib.sha256).hexdigest()
    
    return {
        "status": "VALIDATED",
        "timestamp": time.time(),
        "enclave_signature": signature
    }

def start_enclave():
    """Starts the isolated enclave listener."""
    print(f"[ENCLAVE] Booting QARKE Key-Enclave Validator on {ENCLAVE_HOST}:{ENCLAVE_PORT}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Prevent port blocking during rapid Termux testing
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        s.bind((ENCLAVE_HOST, ENCLAVE_PORT))
        s.listen()
        print("[ENCLAVE] Awaiting router payloads... (Zero-Trust Mode Active)")
        
        while True:
            conn, addr = s.accept()
            with conn:
                # In a real environment, we'd verify the PID/UID of the router here
                data = conn.recv(4096)
                if not data:
                    break
                
                try:
                    payload = json.loads(data.decode('utf-8'))
                    print(f"[ENCLAVE] Received state validation request. Algorithm: {payload.get('kyber_alg')}")
                    
                    # Validate and sign
                    response = generate_validation_token(payload)
                    
                    if response["status"] == "VALIDATED":
                        print(f"[ENCLAVE] [PASS] Payload validated. Issuing token.")
                    else:
                        print(f"[ENCLAVE] [FAIL] Payload rejected: {response.get('reason')}")
                        
                    conn.sendall(json.dumps(response).encode('utf-8'))
                except json.JSONDecodeError:
                    print("[ENCLAVE] [FATAL] Invalid JSON structure received.")
                    conn.sendall(json.dumps({"status": "REJECTED", "reason": "JSON Parse Error"}).encode('utf-8'))

if __name__ == "__main__":
    try:
        start_enclave()
    except KeyboardInterrupt:
        print("\n[ENCLAVE] Shutting down.")
