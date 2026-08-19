#!/usr/bin/env python3
import socket
import json

# --- TEST CONFIGURATION ---
ENCLAVE_HOST = '127.0.0.1'
ENCLAVE_PORT = 50051

def send_to_enclave(payload_name, payload):
    print(f"\n[TEST] Sending: {payload_name}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ENCLAVE_HOST, ENCLAVE_PORT))
            
            # Handle raw strings for the malformed JSON test
            if isinstance(payload, str):
                s.sendall(payload.encode('utf-8'))
            else:
                s.sendall(json.dumps(payload).encode('utf-8'))
            
            data = s.recv(4096)
            response = json.loads(data.decode('utf-8'))
            
            if response.get("status") == "REJECTED":
                print(f"[SUCCESS] Enclave correctly rejected payload. Reason: {response.get('reason')}")
            else:
                print(f"[FAIL] Enclave unexpectedly accepted bad payload! Response: {response}")
                
    except ConnectionRefusedError:
        print("[ERROR] Connection to Enclave refused. Is it running?")
    except json.JSONDecodeError:
        print("[SUCCESS] Enclave dropped the connection or sent non-JSON (expected for garbage data).")

def run_tamper_tests():
    print("=== QARKE ENCLAVE ADVERSARIAL TESTS ===")
    
    # Test 1: Unsupported Algorithm (Simulating a downgrade attack)
    bad_alg = {
        "kyber_alg": "RSA-2048", 
        "nonce": "1a2b3c999",
        "public_key_capsule": "valid_looking_base64_data"
    }
    send_to_enclave("Unsupported Algorithm Test", bad_alg)

    # Test 2: Missing Capsule Data (Simulating a malformed intercept)
    bad_structure = {
        "kyber_alg": "CRYSTALS-Kyber",
        "nonce": "1a2b3c999"
    }
    send_to_enclave("Missing Metadata Test", bad_structure)

    # Test 3: Total JSON Garbage (Simulating a raw fuzzing attack)
    send_to_enclave("Malformed JSON Test", "{bad_json: missing_quotes, [unclosed_brackets}")

if __name__ == "__main__":
    run_tamper_tests()

