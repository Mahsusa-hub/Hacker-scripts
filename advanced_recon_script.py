#!/usr/bin/env python3
"""
Advanced Ethical Hacking Reconnaissance Script
Created for educational and authorized penetration testing only
"""

import os
import sys
import threading
import subprocess
import socket
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class AdvancedRecon:
    def __init__(self, target, output_dir=None):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.output_dir = output_dir or f"advanced-recon-{target}-{self.timestamp}"
        self.results = {}
        self.open_ports = []
        self.services = {}
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize log file
        self.log_file = os.path.join(self.output_dir, "scan_log.txt")
        self.write_log(f"Advanced Reconnaissance started for {target}")
        
    def write_log(self, message):
        """Write to log file and print to console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        with open(self.log_file, 'a') as f:
            f.write(log_message + '\n')
    
    def run_command(self, command, description, output_file=None):
        """Run system command and capture output"""
        try:
            self.write_log(f"Running {description}...")
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            
            if output_file:
                output_path = os.path.join(self.output_dir, output_file)
                with open(output_path, 'w') as f:
                    f.write(f"Command: {command}\n")
                    f.write(f"Exit Code: {result.returncode}\n")
                    f.write("=" * 50 + "\n")
                    f.write("STDOUT:\n")
                    f.write(result.stdout)
                    f.write("\nSTDERR:\n")
                    f.write(result.stderr)
            
            if result.returncode == 0:
                self.write_log(f"✅ {description} completed successfully")
                return result.stdout
            else:
                self.write_log(f"❌ {description} failed with exit code {result.returncode}")
                return None
                
        except subprocess.TimeoutExpired:
            self.write_log(f"⏰ {description} timed out")
            return None
        except Exception as e:
            self.write_log(f"❌ {description} error: {str(e)}")
            return None
    
    def host_discovery(self):
        """Basic host discovery and ping"""
        self.write_log(f"{Colors.CYAN}[1/15] Host Discovery & Ping{Colors.END}")
        
        # Ping scan
        ping_cmd = f"ping -c 4 {self.target}"
        self.run_command(ping_cmd, "Ping scan", "01_ping.txt")
        
        # Host discovery with nmap
        host_cmd = f"nmap -sn {self.target}"
        self.run_command(host_cmd, "Host discovery", "01_host_discovery.txt")
    
    def dns_enumeration(self):
        """Comprehensive DNS enumeration"""
        self.write_log(f"{Colors.CYAN}[2/15] DNS Enumeration{Colors.END}")
        
        # Basic DNS lookup
        dns_cmd = f"nslookup {self.target}"
        self.run_command(dns_cmd, "DNS lookup", "02_dns_lookup.txt")
        
        # Reverse DNS
        reverse_cmd = f"nslookup {self.target}"
        self.run_command(reverse_cmd, "Reverse DNS", "02_reverse_dns.txt")
        
        # DNS zone transfer attempt
        zone_cmd = f"dig axfr @{self.target}"
        self.run_command(zone_cmd, "DNS zone transfer", "02_zone_transfer.txt")
        
        # DNS enumeration with dnsrecon (if available)
        dnsrecon_cmd = f"dnsrecon -d {self.target}"
        self.run_command(dnsrecon_cmd, "DNS reconnaissance", "02_dnsrecon.txt")
    
    def whois_lookup(self):
        """WHOIS information gathering"""
        self.write_log(f"{Colors.CYAN}[3/15] WHOIS Lookup{Colors.END}")
        
        whois_cmd = f"whois {self.target}"
        self.run_command(whois_cmd, "WHOIS lookup", "03_whois.txt")
    
    def port_scanning(self):
        """Comprehensive port scanning"""
        self.write_log(f"{Colors.CYAN}[4/15] Port Scanning{Colors.END}")
        
        # Quick TCP scan
        quick_cmd = f"nmap -sS -T4 -F {self.target}"
        self.run_command(quick_cmd, "Quick TCP scan", "04_quick_ports.txt")
        
        # Full TCP port scan
        full_cmd = f"nmap -sS -T4 -p- {self.target}"
        self.run_command(full_cmd, "Full TCP port scan", "04_full_tcp.txt")
        
        # UDP scan (top 1000 ports)
        udp_cmd = f"nmap -sU -T4 --top-ports 1000 {self.target}"
        self.run_command(udp_cmd, "UDP port scan", "04_udp_scan.txt")
        
        # Extract open ports for later use
        self.extract_open_ports()
    
    def extract_open_ports(self):
        """Extract open ports from nmap results"""
        try:
            quick_scan_file = os.path.join(self.output_dir, "04_quick_ports.txt")
            if os.path.exists(quick_scan_file):
                with open(quick_scan_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    for line in lines:
                        if '/tcp' in line and 'open' in line:
                            port = line.split('/')[0].strip()
                            if port.isdigit():
                                self.open_ports.append(int(port))
        except Exception as e:
            self.write_log(f"Error extracting ports: {e}")
    
    def service_enumeration(self):
        """Service and version detection"""
        self.write_log(f"{Colors.CYAN}[5/15] Service Enumeration{Colors.END}")
        
        # Service detection
        service_cmd = f"nmap -sV -sC -O {self.target}"
        self.run_command(service_cmd, "Service detection", "05_services.txt")
        
        # Aggressive scan
        aggressive_cmd = f"nmap -A -T4 {self.target}"
        self.run_command(aggressive_cmd, "Aggressive scan", "05_aggressive.txt")
    
    def vulnerability_scanning(self):
        """Vulnerability detection"""
        self.write_log(f"{Colors.CYAN}[6/15] Vulnerability Scanning{Colors.END}")
        
        # Nmap vulnerability scripts
        vuln_cmd = f"nmap --script vuln {self.target}"
        self.run_command(vuln_cmd, "Vulnerability scan", "06_vulnerabilities.txt")
        
        # Common vulnerability checks
        common_vulns = [
            "nmap --script smb-vuln-ms17-010",
            "nmap --script smb-vuln-ms08-067",
            "nmap --script ssl-cert,ssl-enum-ciphers",
            "nmap --script http-enum,http-vuln-*"
        ]
        
        for i, vuln_script in enumerate(common_vulns):
            cmd = f"{vuln_script} {self.target}"
            self.run_command(cmd, f"Vulnerability check {i+1}", f"06_vuln_check_{i+1}.txt")
    
    def web_enumeration(self):
        """Web application enumeration"""
        self.write_log(f"{Colors.CYAN}[7/15] Web Enumeration{Colors.END}")
        
        # Check if web ports are open
        web_ports = [80, 443, 8080, 8443, 8000, 3000, 5000]
        open_web_ports = [port for port in web_ports if port in self.open_ports]
        
        if not open_web_ports:
            self.write_log("No common web ports found open")
            return
        
        for port in open_web_ports:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{self.target}:{port}"
            
            # Nikto scan
            nikto_cmd = f"nikto -h {url}"
            self.run_command(nikto_cmd, f"Nikto scan on port {port}", f"07_nikto_{port}.txt")
            
            # Directory enumeration
            dirb_cmd = f"dirb {url}"
            self.run_command(dirb_cmd, f"Directory enumeration on port {port}", f"07_dirb_{port}.txt")
            
            # Gobuster (if available)
            gobuster_cmd = f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt"
            self.run_command(gobuster_cmd, f"Gobuster scan on port {port}", f"07_gobuster_{port}.txt")
    
    def smb_enumeration(self):
        """SMB/NetBIOS enumeration"""
        self.write_log(f"{Colors.CYAN}[8/15] SMB/NetBIOS Enumeration{Colors.END}")
        
        # SMB ports check
        smb_ports = [139, 445]
        if not any(port in self.open_ports for port in smb_ports):
            self.write_log("No SMB ports found open")
            return
        
        # enum4linux
        enum4linux_cmd = f"enum4linux -a {self.target}"
        self.run_command(enum4linux_cmd, "enum4linux scan", "08_enum4linux.txt")
        
        # smbclient
        smbclient_cmd = f"smbclient -L //{self.target} -N"
        self.run_command(smbclient_cmd, "SMB shares enumeration", "08_smbclient.txt")
        
        # NBT scan
        nbtscan_cmd = f"nbtscan {self.target}"
        self.run_command(nbtscan_cmd, "NBT scan", "08_nbtscan.txt")
    
    def ftp_enumeration(self):
        """FTP enumeration"""
        self.write_log(f"{Colors.CYAN}[9/15] FTP Enumeration{Colors.END}")
        
        if 21 not in self.open_ports:
            self.write_log("FTP port 21 not open")
            return
        
        # FTP banner grabbing
        ftp_cmd = f"nmap -sV -p 21 --script ftp-* {self.target}"
        self.run_command(ftp_cmd, "FTP enumeration", "09_ftp.txt")
    
    def ssh_enumeration(self):
        """SSH enumeration"""
        self.write_log(f"{Colors.CYAN}[10/15] SSH Enumeration{Colors.END}")
        
        if 22 not in self.open_ports:
            self.write_log("SSH port 22 not open")
            return
        
        # SSH enumeration
        ssh_cmd = f"nmap -sV -p 22 --script ssh-* {self.target}"
        self.run_command(ssh_cmd, "SSH enumeration", "10_ssh.txt")
    
    def database_enumeration(self):
        """Database enumeration"""
        self.write_log(f"{Colors.CYAN}[11/15] Database Enumeration{Colors.END}")
        
        # Common database ports
        db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 1521: 'Oracle', 27017: 'MongoDB'}
        
        for port, db_type in db_ports.items():
            if port in self.open_ports:
                cmd = f"nmap -sV -p {port} --script {db_type.lower()}-* {self.target}"
                self.run_command(cmd, f"{db_type} enumeration", f"11_{db_type.lower()}.txt")
    
    def snmp_enumeration(self):
        """SNMP enumeration"""
        self.write_log(f"{Colors.CYAN}[12/15] SNMP Enumeration{Colors.END}")
        
        if 161 not in self.open_ports:
            self.write_log("SNMP port 161 not open")
            return
        
        # SNMP enumeration
        snmp_cmd = f"nmap -sU -p 161 --script snmp-* {self.target}"
        self.run_command(snmp_cmd, "SNMP enumeration", "12_snmp.txt")
        
        # snmpwalk
        snmpwalk_cmd = f"snmpwalk -c public -v1 {self.target}"
        self.run_command(snmpwalk_cmd, "SNMP walk", "12_snmpwalk.txt")
    
    def dns_server_enumeration(self):
        """DNS server enumeration"""
        self.write_log(f"{Colors.CYAN}[13/15] DNS Server Enumeration{Colors.END}")
        
        if 53 not in self.open_ports:
            self.write_log("DNS port 53 not open")
            return
        
        # DNS enumeration
        dns_cmd = f"nmap -sU -p 53 --script dns-* {self.target}"
        self.run_command(dns_cmd, "DNS server enumeration", "13_dns_server.txt")
    
    def ssl_tls_enumeration(self):
        """SSL/TLS enumeration"""
        self.write_log(f"{Colors.CYAN}[14/15] SSL/TLS Enumeration{Colors.END}")
        
        # Check for SSL/TLS ports
        ssl_ports = [443, 993, 995, 8443]
        open_ssl_ports = [port for port in ssl_ports if port in self.open_ports]
        
        if not open_ssl_ports:
            self.write_log("No SSL/TLS ports found open")
            return
        
        for port in open_ssl_ports:
            # SSL enumeration
            ssl_cmd = f"nmap -sV -p {port} --script ssl-* {self.target}"
            self.run_command(ssl_cmd, f"SSL enumeration on port {port}", f"14_ssl_{port}.txt")
            
            # SSLyze (if available)
            sslyze_cmd = f"sslyze {self.target}:{port}"
            self.run_command(sslyze_cmd, f"SSLyze scan on port {port}", f"14_sslyze_{port}.txt")
    
    def generate_report(self):
        """Generate comprehensive report"""
        self.write_log(f"{Colors.CYAN}[15/15] Generating Report{Colors.END}")
        
        report_file = os.path.join(self.output_dir, "REPORT.txt")
        with open(report_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("ADVANCED RECONNAISSANCE REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Output Directory: {self.output_dir}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("DISCOVERED OPEN PORTS:\n")
            f.write("-" * 30 + "\n")
            if self.open_ports:
                for port in sorted(self.open_ports):
                    f.write(f"Port {port}/tcp - OPEN\n")
            else:
                f.write("No open ports discovered\n")
            
            f.write("\nSCAN MODULES EXECUTED:\n")
            f.write("-" * 30 + "\n")
            modules = [
                "Host Discovery & Ping",
                "DNS Enumeration", 
                "WHOIS Lookup",
                "Port Scanning",
                "Service Enumeration",
                "Vulnerability Scanning",
                "Web Enumeration",
                "SMB/NetBIOS Enumeration",
                "FTP Enumeration",
                "SSH Enumeration", 
                "Database Enumeration",
                "SNMP Enumeration",
                "DNS Server Enumeration",
                "SSL/TLS Enumeration"
            ]
            
            for i, module in enumerate(modules, 1):
                f.write(f"{i:2d}. {module}\n")
            
            f.write("\nFILES GENERATED:\n")
            f.write("-" * 30 + "\n")
            files = sorted(os.listdir(self.output_dir))
            for file in files:
                if file != "REPORT.txt":
                    f.write(f"- {file}\n")
        
        self.write_log(f"Report generated: {report_file}")
    
    def run_full_scan(self):
        """Execute all reconnaissance modules"""
        start_time = time.time()
        
        self.write_log(f"{Colors.BOLD}{Colors.GREEN}Starting Advanced Reconnaissance on {self.target}{Colors.END}")
        self.write_log(f"Output directory: {self.output_dir}")
        
        try:
            # Execute all enumeration modules
            self.host_discovery()
            self.dns_enumeration()
            self.whois_lookup()
            self.port_scanning()
            self.service_enumeration()
            self.vulnerability_scanning()
            self.web_enumeration()
            self.smb_enumeration()
            self.ftp_enumeration()
            self.ssh_enumeration()
            self.database_enumeration()
            self.snmp_enumeration()
            self.dns_server_enumeration()
            self.ssl_tls_enumeration()
            self.generate_report()
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.write_log(f"{Colors.BOLD}{Colors.GREEN}✅ Advanced reconnaissance completed!{Colors.END}")
            self.write_log(f"Total scan time: {duration:.2f} seconds")
            self.write_log(f"Results saved in: {self.output_dir}")
            
        except KeyboardInterrupt:
            self.write_log(f"{Colors.YELLOW}Scan interrupted by user{Colors.END}")
        except Exception as e:
            self.write_log(f"{Colors.RED}Error during scan: {str(e)}{Colors.END}")

def main():
    print(f"""
{Colors.CYAN}
    ╔═══════════════════════════════════════════════════════════════╗
    ║                 ADVANCED RECONNAISSANCE TOOL                  ║
    ║                For Educational Purposes Only                  ║
    ║              Authorized Penetration Testing Only              ║
    ╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
    """)
    
    parser = argparse.ArgumentParser(description='Advanced Reconnaissance Tool')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-o', '--output', help='Output directory', default=None)
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target:
        print(f"{Colors.RED}Error: Target is required{Colors.END}")
        sys.exit(1)
    
    # Create reconnaissance instance
    recon = AdvancedRecon(args.target, args.output)
    
    # Run full scan
    recon.run_full_scan()

if __name__ == "__main__":
    main()
