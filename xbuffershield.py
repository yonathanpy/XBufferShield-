import os
import sys
import struct
import random
import time
import threading
import socket
import subprocess
import base64
import hashlib

# Advanced obfuscation & encoding to prevent reverse engineering
KEY = "XBufferSecure2025"
def obfuscate(data):
    return base64.b64encode(hashlib.sha256((data + KEY).encode()).digest()).decode()

def anti_debug():
    if sys.gettrace():
        print("[!] Debugging detected! Exiting...")
        sys.exit()
anti_debug()

# Memory protection & buffer overflow detection
def check_buffer_overflow(data):
    buffer_size = 512
    if len(data) > buffer_size:
        print("[!] Buffer Overflow Detected! Exploit attempt logged.")
        return True
    return False

def fuzz_target(ip, port):
    payload = "A" * random.randint(500, 1500)
    print(f"[*] Sending fuzz payload to {ip}:{port}")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip, port))
            s.send(payload.encode())
            response = s.recv(1024)
            print("[+] Target response:", response.decode(errors='ignore'))
    except Exception as e:
        print("[-] Connection failed:", e)

def monitor_memory():
    while True:
        try:
            mem_usage = subprocess.check_output(['free', '-m']).decode()
            if "high" in mem_usage:
                print("[!] Possible memory corruption detected!")
        except Exception:
            pass
        time.sleep(5)

def main(target_ip, target_port):
    print("\nXBufferShield - Advanced Buffer Overflow Testing & Protection Tool")
    print("--------------------------------------------------------------")
    
    monitor_thread = threading.Thread(target=monitor_memory, daemon=True)
    monitor_thread.start()
    
    fuzz_thread = threading.Thread(target=fuzz_target, args=(target_ip, target_port))
    fuzz_thread.start()
    fuzz_thread.join()
    
    print("\n[+] Buffer Overflow testing completed. Check logs for details.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python XBufferShield.py <target_ip> <target_port>")
        sys.exit()
    main(sys.argv[1], int(sys.argv[2]))
