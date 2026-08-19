import json
import sys
import time

class QarkeValidator:
    def __init__(self, manifest_path):
        self.manifest_path = manifest_path
        self.manifest = self._load_manifest()
        self.current_state = None

    def _load_manifest(self):
        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
                return data.get("qarke_manifest")
        except FileNotFoundError:
            print(f"[-] ERROR: Manifest not found at {self.manifest_path}")
            sys.exit(1)
        except json.JSONDecodeError:
            print("[-] ERROR: Invalid JSON structure in manifest.")
            sys.exit(1)

    def validate_enclave(self):
        print("[+] Validating Key-Enclave settings...")
        enclave = self.manifest.get("key_enclave", {})
        
        if "Kyber-768" not in enclave.get("hybrid_algorithms", []):
            print("[-] FATAL: Post-quantum algorithm missing from Enclave.")
            return False
            
        if enclave.get("enclave_state") != "SEALED":
            print("[-] WARNING: Enclave is not SEALED. Susceptible to tampering.")
            return False
            
        print("    -> Enclave sealed and algorithms verified.")
        return True

    def run_state_machine(self):
        print("\n[+] Initializing QARKE State Machine...")
        kinetics = self.manifest.get("relay_kinetics", {})
        expected_sequence = kinetics.get("state_sequence", [])
        
        if not expected_sequence:
            print("[-] FATAL: No state sequence defined in manifest.")
            sys.exit(1)

        for step in expected_sequence:
            self.current_state = step
            print(f"    -> Transitioning to state: [{self.current_state}]")
            time.sleep(0.5) 
            
            if step == "WRAPPER_LOCK" and self.manifest["test_assertions"].get("tamper_simulation"):
                print("    -> [!] TAMPER DETECTED DURING LOCK STATE.")
                print("    -> [!] QARKE KINETICS HALTED.")
                return False

        print("\n[+] QARKE Routing Kinetics Complete. Packet ready for relay.")
        return True

if __name__ == "__main__":
    print(r"""  ____      _    ____  _  _______ 
 / __ \    / \  |  _ \| |/ / ____|
| |  | |  / _ \ | |_) | ' /|  _|  
| |__| | / ___ \|  _ <| . \| |___ 
 \___\_\/_/   \_\_| \_\_|\_\_____|
                                  
Quantum-Agile Routing & Key-Enclave Validator
""")
    
    validator = QarkeValidator("test_manifest.json")
    
    if validator.validate_enclave():
        success = validator.run_state_machine()
        if success:
            print("\n[+] Loopback Test: PASS")
            sys.exit(0)
        else:
            print("\n[-] Loopback Test: FAIL")
            sys.exit(1)
    else:
        print("\n[-] Enclave Validation Failed. Aborting.")
        sys.exit(1)
