#!/usr/bin/env python3
"""
Professional Network Vulnerability Scanner
Author: Ethical Hacker
Purpose: Authorized security assessments only
"""

import socket
import threading
import subprocess
import json
import time
from datetime import datetime
import argparse
import nmap
import sys

class NetworkVulnerabilityScanner:
    def __init__(self, target, output_file="network_scan_report.html"):
        self.target = target
        self.output_file = output_file
        self.open_ports = []
        self.vulnerabilities = []
        self.services = []
        self.nm = nmap.PortScanner()
        
    def banner_grabbing(self, ip, port):
        """Perform banner grabbing on open ports"""
        try:
            socket.setdefaulttimeout(2)
            s = socket.socket()
            s.connect((ip, port))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            return banner.strip()
        except:
            return "Unable to retrieve banner"
    
    def service_detection(self, ip, port):
        """Detect services running on ports"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 27017: "MongoDB"
        }
        return common_services.get(port, "Unknown")
    
    def port_scan(self, start_port=1, end_port=1000):
        """Perform comprehensive port scanning"""
        print(f"[+] Starting port scan on {self.target} (ports {start_port}-{end_port})")
        
        try:
            # Using nmap for comprehensive scanning
            scan_args = f"-sS -sV -sC -p {start_port}-{end_port}"
            self.nm.scan(self.target, arguments=scan_args)
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        if state == 'open':
                            service = self.nm[host][proto][port]['name']
                            version = self.nm[host][proto][port].get('version', 'Unknown')
                            banner = self.banner_grabbing(host, port)
                            
                            port_info = {
                                'port': port,
                                'service': service,
                                'version': version,
                                'banner': banner,
                                'protocol': proto
                            }
                            self.open_ports.append(port_info)
                            print(f"[+] Found open port: {port}/{proto} - {service} {version}")
                            
        except Exception as e:
            print(f"[-] Nmap scan failed: {e}")
            # Fallback to basic socket scanning
            self.basic_port_scan(start_port, end_port)
    
    def basic_port_scan(self, start_port, end_port):
        """Basic socket-based port scanning as fallback"""
        print("[+] Using basic socket scanning...")
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((self.target, port))
                    if result == 0:
                        service = self.service_detection(self.target, port)
                        banner = self.banner_grabbing(self.target, port)
                        port_info = {
                            'port': port,
                            'service': service,
                            'version': 'Unknown',
                            'banner': banner,
                            'protocol': 'tcp'
                        }
                        self.open_ports.append(port_info)
                        print(f"[+] Found open port: {port}/tcp - {service}")
            except:
                pass
    
    def vulnerability_checks(self):
        """Perform basic vulnerability checks"""
        print("[+] Performing vulnerability checks...")
        
        for port_info in self.open_ports:
            port = port_info['port']
            service = port_info['service'].lower()
            version = port_info['version'].lower()
            
            # FTP checks
            if port == 21 and 'anonymous' in port_info['banner'].lower():
                self.vulnerabilities.append({
                    'type': 'High',
                    'service': 'FTP',
                    'port': port,
                    'description': 'Anonymous FTP login allowed',
                    'recommendation': 'Disable anonymous FTP access'
                })
            
            # SSH checks
            if port == 22 and 'openssh' in version and '7.' in version:
                self.vulnerabilities.append({
                    'type': 'Medium',
                    'service': 'SSH',
                    'port': port,
                    'description': 'Older SSH version detected',
                    'recommendation': 'Update to latest OpenSSH version'
                })
            
            # HTTP checks
            if port == 80:
                if 'apache' in version and '2.2' in version:
                    self.vulnerabilities.append({
                        'type': 'High',
                        'service': 'HTTP',
                        'port': port,
                        'description': 'Outdated Apache version',
                        'recommendation': 'Update Apache to latest version'
                    })
    
    def generate_report(self):
        """Generate professional HTML report"""
        print(f"[+] Generating report: {self.output_file}")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Vulnerability Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .high {{ color: #e74c3c; font-weight: bold; }}
                .medium {{ color: #f39c12; font-weight: bold; }}
                .low {{ color: #f1c40f; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Vulnerability Assessment Report</h1>
                <p>Target: {self.target} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>Scan completed on {datetime.now().strftime('%Y-%m-%d')}. Found {len(self.open_ports)} open ports and {len(self.vulnerabilities)} potential vulnerabilities.</p>
            </div>
            
            <div class="section">
                <h2>Open Ports & Services</h2>
                <table>
                    <tr><th>Port</th><th>Service</th><th>Version</th><th>Banner</th></tr>
        """
        
        for port in self.open_ports:
            html_content += f"""
                    <tr>
                        <td>{port['port']}/{port['protocol']}</td>
                        <td>{port['service']}</td>
                        <td>{port['version']}</td>
                        <td>{port['banner'][:100]}</td>
                    </tr>
            """
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
        """
        
        if self.vulnerabilities:
            html_content += """
                <table>
                    <tr><th>Severity</th><th>Service</th><th>Port</th><th>Description</th><th>Recommendation</th></tr>
            """
            for vuln in self.vulnerabilities:
                html_content += f"""
                    <tr>
                        <td class="{vuln['type'].lower()}">{vuln['type']}</td>
                        <td>{vuln['service']}</td>
                        <td>{vuln['port']}</td>
                        <td>{vuln['description']}</td>
                        <td>{vuln['recommendation']}</td>
                    </tr>
                """
            html_content += "</table>"
        else:
            html_content += "<p>No critical vulnerabilities detected.</p>"
        
        html_content += """
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    <li>Close all unnecessary ports</li>
                    <li>Keep services updated to latest versions</li>
                    <li>Implement proper firewall rules</li>
                    <li>Regularly monitor and audit network services</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(self.output_file, 'w') as f:
            f.write(html_content)
        
        print(f"[+] Report saved as: {self.output_file}")
    
    def run_scan(self):
        """Execute complete vulnerability scan"""
        start_time = time.time()
        print(f"[+] Starting network vulnerability scan for: {self.target}")
        print(f"[+] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self.port_scan(1, 1000)
        self.vulnerability_checks()
        self.generate_report()
        
        end_time = time.time()
        print(f"[+] Scan completed in {end_time - start_time:.2f} seconds")
        print(f"[+] Found {len(self.open_ports)} open ports and {len(self.vulnerabilities)} vulnerabilities")

def main():
    parser = argparse.ArgumentParser(description='Network Vulnerability Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-o', '--output', default='network_scan_report.html', 
                       help='Output report filename')
    
    args = parser.parse_args()
    
    # Disclaimer
    print("=" * 60)
    print("ETHICAL HACKING TOOL - FOR AUTHORIZED TESTING ONLY")
    print("Ensure you have proper authorization before use!")
    print("=" * 60)
    
    scanner = NetworkVulnerabilityScanner(args.target, args.output)
    scanner.run_scan()

if __name__ == "__main__":
    main()