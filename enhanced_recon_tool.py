#!/usr/bin/env python3

import os
import sys
import subprocess
import threading
import time
import socket
import requests
from datetime import datetime
import json
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class AdvancedRecon:
    def __init__(self, target, output_dir="recon_results"):
        self.target = target
        self.output_dir = output_dir
        self.results = {}
        self.create_output_structure()
        
    def create_output_structure(self):
        """Create organized output directory structure"""
        dirs = [
            self.output_dir,
            f"{self.output_dir}/nmap",
            f"{self.output_dir}/web",
            f"{self.output_dir}/dns",
            f"{self.output_dir}/enum",
            f"{self.output_dir}/vuln",
            f"{self.output_dir}/logs"
        ]
        
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
    
    def print_banner(self):
        banner = f"""
{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                         🎯 ADVANCED RECONNAISSANCE SUITE                         ║
║                                  v2.0 Enhanced                                   ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  Target: {self.target:<66} ║
║  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<68} ║
║  Output: {self.output_dir:<65} ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
    
    def run_command(self, cmd, output_file=None, timeout=300):
        """Execute command with timeout and error handling"""
        try:
            print(f"{Colors.BLUE}[*] Running: {cmd}{Colors.END}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(f"Command: {cmd}\n")
                    f.write(f"Return Code: {result.returncode}\n")
                    f.write(f"STDOUT:\n{result.stdout}\n")
                    f.write(f"STDERR:\n{result.stderr}\n")
            
            return result.returncode == 0, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[!] Command timed out: {cmd}{Colors.END}")
            return False, "", "Command timed out"
        except Exception as e:
            print(f"{Colors.RED}[!] Error running command: {e}{Colors.END}")
            return False, "", str(e)
    
    def host_discovery(self):
        """Enhanced host discovery with multiple techniques"""
        print(f"{Colors.YELLOW}[+] Phase 1: Host Discovery{Colors.END}")
        
        # Ping sweep
        ping_cmd = f"ping -c 4 {self.target}"
        success, stdout, stderr = self.run_command(ping_cmd, f"{self.output_dir}/logs/ping.txt")
        
        if success:
            print(f"{Colors.GREEN}[✓] Host is alive{Colors.END}")
            self.results['host_alive'] = True
        else:
            print(f"{Colors.RED}[✗] Host may be down or blocking ping{Colors.END}")
            self.results['host_alive'] = False
        
        # ARP scan for local network
        if self.is_local_network():
            arp_cmd = f"arp-scan -l | grep {self.target}"
            self.run_command(arp_cmd, f"{self.output_dir}/logs/arp_scan.txt")
    
    def is_local_network(self):
        """Check if target is in local network"""
        try:
            ip = ipaddress.ip_address(self.target)
            return ip.is_private
        except:
            return False
    
    def port_scanning(self):
        """Comprehensive port scanning"""
        print(f"{Colors.YELLOW}[+] Phase 2: Port Scanning{Colors.END}")
        
        # Quick scan for common ports
        quick_scan = f"nmap -sS -O -sV -T4 --top-ports 1000 {self.target}"
        self.run_command(quick_scan, f"{self.output_dir}/nmap/quick_scan.txt")
        
        # Full TCP scan
        full_tcp = f"nmap -sS -O -sV -p- -T4 {self.target}"
        self.run_command(full_tcp, f"{self.output_dir}/nmap/full_tcp.txt", timeout=1800)
        
        # UDP scan (top 1000 ports)
        udp_scan = f"nmap -sU --top-ports 1000 -T4 {self.target}"
        self.run_command(udp_scan, f"{self.output_dir}/nmap/udp_scan.txt", timeout=900)
        
        # Aggressive scan
        aggressive = f"nmap -A -T4 {self.target}"
        self.run_command(aggressive, f"{self.output_dir}/nmap/aggressive.txt")
        
        print(f"{Colors.GREEN}[✓] Port scanning completed{Colors.END}")
    
    def service_enumeration(self):
        """Service-specific enumeration"""
        print(f"{Colors.YELLOW}[+] Phase 3: Service Enumeration{Colors.END}")
        
        # Extract open ports from nmap results
        ports = self.extract_open_ports()
        
        for port in ports:
            if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
                self.enumerate_service(port)
    
    def extract_open_ports(self):
        """Extract open ports from nmap results"""
        ports = []
        try:
            with open(f"{self.output_dir}/nmap/quick_scan.txt", 'r') as f:
                content = f.read()
                # Simple port extraction logic
                lines = content.split('\n')
                for line in lines:
                    if '/tcp' in line and 'open' in line:
                        port = line.split('/')[0].strip()
                        if port.isdigit():
                            ports.append(int(port))
        except:
            pass
        return ports
    
    def enumerate_service(self, port):
        """Enumerate specific service"""
        if port == 21:  # FTP
            cmd = f"nmap -sV -p21 --script=ftp-* {self.target}"
            self.run_command(cmd, f"{self.output_dir}/enum/ftp_enum.txt")
        
        elif port == 22:  # SSH
            cmd = f"nmap -sV -p22 --script=ssh-* {self.target}"
            self.run_command(cmd, f"{self.output_dir}/enum/ssh_enum.txt")
        
        elif port == 80 or port == 443:  # HTTP/HTTPS
            self.web_enumeration(port)
        
        elif port == 139 or port == 445:  # SMB
            self.smb_enumeration()
        
        elif port == 53:  # DNS
            self.dns_enumeration()
    
    def web_enumeration(self, port):
        """Comprehensive web enumeration"""
        print(f"{Colors.BLUE}[*] Enumerating web service on port {port}{Colors.END}")
        
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{self.target}:{port}"
        
        # Nikto scan
        nikto_cmd = f"nikto -h {url} -output {self.output_dir}/web/nikto.txt"
        self.run_command(nikto_cmd, f"{self.output_dir}/web/nikto_full.txt")
        
        # Directory bruteforce
        dirb_cmd = f"dirb {url} -o {self.output_dir}/web/dirb.txt"
        self.run_command(dirb_cmd, f"{self.output_dir}/web/dirb_full.txt")
        
        # Gobuster
        gobuster_cmd = f"gobuster dir -u {url} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o {self.output_dir}/web/gobuster.txt"
        self.run_command(gobuster_cmd, f"{self.output_dir}/web/gobuster_full.txt")
        
        # Web application technology detection
        whatweb_cmd = f"whatweb {url}"
        self.run_command(whatweb_cmd, f"{self.output_dir}/web/whatweb.txt")
    
    def smb_enumeration(self):
        """SMB enumeration"""
        print(f"{Colors.BLUE}[*] Enumerating SMB services{Colors.END}")
        
        # enum4linux
        enum4linux_cmd = f"enum4linux {self.target}"
        self.run_command(enum4linux_cmd, f"{self.output_dir}/enum/enum4linux.txt")
        
        # SMB client
        smbclient_cmd = f"smbclient -L {self.target} -N"
        self.run_command(smbclient_cmd, f"{self.output_dir}/enum/smbclient.txt")
        
        # nmap SMB scripts
        smb_scripts = f"nmap -p445 --script=smb-* {self.target}"
        self.run_command(smb_scripts, f"{self.output_dir}/enum/smb_scripts.txt")
    
    def dns_enumeration(self):
        """DNS enumeration"""
        print(f"{Colors.BLUE}[*] Enumerating DNS service{Colors.END}")
        
        # DNS zone transfer
        dns_cmd = f"dig axfr @{self.target}"
        self.run_command(dns_cmd, f"{self.output_dir}/dns/zone_transfer.txt")
        
        # DNS bruteforce
        dnsrecon_cmd = f"dnsrecon -d {self.target} -t brt"
        self.run_command(dnsrecon_cmd, f"{self.output_dir}/dns/dnsrecon.txt")
    
    def vulnerability_scanning(self):
        """Vulnerability scanning"""
        print(f"{Colors.YELLOW}[+] Phase 4: Vulnerability Scanning{Colors.END}")
        
        # Nmap vulnerability scripts
        vuln_cmd = f"nmap -sV --script=vuln {self.target}"
        self.run_command(vuln_cmd, f"{self.output_dir}/vuln/nmap_vuln.txt", timeout=600)
        
        # OpenVAS alternative - using nmap scripts for now
        common_vulns = f"nmap -sV --script=smb-vuln-*,http-vuln-* {self.target}"
        self.run_command(common_vulns, f"{self.output_dir}/vuln/common_vulns.txt")
    
    def generate_report(self):
        """Generate comprehensive report"""
        print(f"{Colors.YELLOW}[+] Phase 5: Generating Report{Colors.END}")
        
        report_path = f"{self.output_dir}/FINAL_REPORT.txt"
        
        with open(report_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("ADVANCED RECONNAISSANCE REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Report Generated By: Advanced Recon Suite v2.0\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary
            f.write("EXECUTIVE SUMMARY:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Host Status: {'ALIVE' if self.results.get('host_alive') else 'UNKNOWN'}\n")
            f.write(f"Total Files Generated: {len(os.listdir(self.output_dir))}\n")
            f.write("\n")
            
            # File structure
            f.write("FILES GENERATED:\n")
            f.write("-" * 40 + "\n")
            for root, dirs, files in os.walk(self.output_dir):
                level = root.replace(self.output_dir, '').count(os.sep)
                indent = ' ' * 2 * level
                f.write(f"{indent}{os.path.basename(root)}/\n")
                subindent = ' ' * 2 * (level + 1)
                for file in files:
                    f.write(f"{subindent}{file}\n")
        
        print(f"{Colors.GREEN}[✓] Report generated: {report_path}{Colors.END}")
    
    def run_full_recon(self):
        """Execute full reconnaissance"""
        self.print_banner()
        
        try:
            self.host_discovery()
            self.port_scanning()
            self.service_enumeration()
            self.vulnerability_scanning()
            self.generate_report()
            
            print(f"\n{Colors.GREEN}[✓] Full reconnaissance completed!{Colors.END}")
            print(f"{Colors.CYAN}[i] Results saved to: {self.output_dir}{Colors.END}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Reconnaissance interrupted by user{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error during reconnaissance: {e}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Reconnaissance Suite")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-o", "--output", default="recon_results", help="Output directory")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    args = parser.parse_args()
    
    # Validate target
    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{Colors.RED}[!] Invalid target: {args.target}{Colors.END}")
        sys.exit(1)
    
    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"{args.output}_{args.target}_{timestamp}"
    
    recon = AdvancedRecon(args.target, output_dir)
    recon.run_full_recon()

if __name__ == "__main__":
    main()
