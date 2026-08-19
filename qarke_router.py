#!/usr/bin/env python3
import socket
import json
import time

# --- ROUTER CONFIGURATION ---
ENCLAVE_HOST = '127.0.0.1'
ENCLAVE_PORT = 50051

# Simulated incoming packet from a client
MOCK_INCOMING_PACKET = {
    "session_id": "QARKE-TX-9982",
    "kyber_alg": "CRYSTALS-Kyber",
    "nonce": "8f8a9b2c1d",
    "public_key_capsule": "base64_encoded_quantum_capsule_data_here",
    "routing_destination": "10.0.0.55"
}

def request_enclave_validation(payload):
    """Sends cryptographic metadata to the isolated enclave for validation."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ENCLAVE_HOST, ENCLAVE_PORT))
            s.sendall(json.dumps(payload).encode('utf-8'))
            data = s.recv(4096)
            return json.loads(data.decode('utf-8'))
    except ConnectionRefusedError:
        print("[ROUTER] [ERROR] Connection to Enclave refused. Is the daemon running?")
        return {"status": "FATAL", "reason": "Enclave Unreachable"}

def run_state_machine():
    print("[ROUTER] QARKE Router Initialized.")
    print(f"[ROUTER] Intercepted incoming packet: {MOCK_INCOMING_PACKET['session_id']}")
    
    # STATE: ENCLAVE HOLD
    print("[ROUTER] State shift -> ENCLAVE HOLD. Suspending transit.")
    time.sleep(1) # Simulate processing delay
    
    # Strip routing data, send ONLY cryptographic metadata to the enclave
    crypto_metadata = {
        "kyber_alg": MOCK_INCOMING_PACKET["kyber_alg"],
        "nonce": MOCK_INCOMING_PACKET["nonce"],
        "public_key_capsule": MOCK_INCOMING_PACKET["public_key_capsule"]
    }
    
    validation_response = request_enclave_validation(crypto_metadata)
    
    if validation_response.get("status") == "VALIDATED":
        # STATE: FORWARD
        evt = validation_response.get("enclave_signature")
        print(f"[ROUTER] State shift -> FORWARD. Enclave signature verified: {evt[:10]}...")
        print(f"[ROUTER] Injecting EVT into packet and routing to {MOCK_INCOMING_PACKET['routing_destination']}")
    else:
        # STATE: DROP
        print(f"[ROUTER] State shift -> DROP. Enclave rejected payload: {validation_response.get('reason')}")
        print("[ROUTER] Terminating connection.")

if __name__ == "__main__":
    run_state_machine()

