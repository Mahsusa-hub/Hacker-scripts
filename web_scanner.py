#!/usr/bin/env python3
"""
Professional Web Vulnerability Scanner
Author: Ethical Hacker
Purpose: Authorized security assessments only
"""

import requests
import argparse
import threading
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse
import re
import json
import sys

class WebVulnerabilityScanner:
    def __init__(self, target_url, output_file="web_scan_report.html"):
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def check_connection(self):
        """Verify target is reachable"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            return response.status_code in [200, 301, 302]
        except:
            return False
    
    def sql_injection_test(self):
        """Test for basic SQL injection vulnerabilities"""
        print("[+] Testing for SQL Injection vulnerabilities...")
        
        test_paths = [
            "/product?id=1",
            "/user?id=1", 
            "/page?id=1",
            "/category?id=1"
        ]
        
        payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users--"]
        
        for path in test_paths:
            full_url = urljoin(self.target_url, path)
            for payload in payloads:
                try:
                    test_url = f"{full_url}{payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for common SQL error messages
                    errors = [
                        "sql syntax", "mysql_fetch", "ora-", "microsoft odbc",
                        "postgresql", "sybase message"
                    ]
                    
                    if any(error in response.text.lower() for error in errors):
                        self.vulnerabilities.append({
                            'type': 'Critical',
                            'category': 'SQL Injection',
                            'url': test_url,
                            'description': 'Potential SQL injection vulnerability detected',
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        break
                except:
                    pass
    
    def xss_test(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        print("[+] Testing for XSS vulnerabilities...")
        
        test_paths = [
            "/search?q=",
            "/contact?name=",
            "/comment?text=",
            "/user?name="
        ]
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        for path in test_paths:
            full_url = urljoin(self.target_url, path)
            for payload in xss_payloads:
                try:
                    test_url = f"{full_url}{payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'High',
                            'category': 'Cross-Site Scripting (XSS)',
                            'url': test_url,
                            'description': 'Potential XSS vulnerability detected',
                            'recommendation': 'Implement proper output encoding and input validation'
                        })
                        break
                except:
                    pass
    
    def directory_traversal_test(self):
        """Test for directory traversal vulnerabilities"""
        print("[+] Testing for Directory Traversal vulnerabilities...")
        
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../etc/shadow"
        ]
        
        test_paths = [
            "/download?file=",
            "/file?name=",
            "/document?file=",
            "/load?file="
        ]
        
        for path in test_paths:
            full_url = urljoin(self.target_url, path)
            for payload in traversal_payloads:
                try:
                    test_url = f"{full_url}{payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    if "root:" in response.text or "[extensions]" in response.text:
                        self.vulnerabilities.append({
                            'type': 'Critical',
                            'category': 'Directory Traversal',
                            'url': test_url,
                            'description': 'Potential directory traversal vulnerability',
                            'recommendation': 'Validate and sanitize file path inputs'
                        })
                        break
                except:
                    pass
    
    def information_disclosure_test(self):
        """Check for information disclosure"""
        print("[+] Testing for Information Disclosure...")
        
        sensitive_files = [
            "/.git/config",
            "/.env",
            "/backup.zip",
            "/database.sql",
            "/wp-config.php",
            "/config.php",
            "/robots.txt",
            "/.htaccess"
        ]
        
        for file in sensitive_files:
            full_url = urljoin(self.target_url, file)
            try:
                response = self.session.get(full_url, timeout=5)
                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Medium',
                        'category': 'Information Disclosure',
                        'url': full_url,
                        'description': f'Sensitive file accessible: {file}',
                        'recommendation': 'Restrict access to sensitive files and directories'
                    })
            except:
                pass
    
    def security_headers_check(self):
        """Check for missing security headers"""
        print("[+] Checking security headers...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Prevents XSS attacks',
                'X-XSS-Protection': 'Browser XSS protection'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    self.vulnerabilities.append({
                        'type': 'Low',
                        'category': 'Security Headers',
                        'url': self.target_url,
                        'description': f'Missing security header: {header} - {description}',
                        'recommendation': f'Implement {header} security header'
                    })
        except:
            pass
    
    def server_info_disclosure(self):
        """Check for server information disclosure"""
        print("[+] Checking for server information disclosure...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            server_info = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            if server_info:
                self.vulnerabilities.append({
                    'type': 'Info',
                    'category': 'Information Disclosure',
                    'url': self.target_url,
                    'description': f'Server information disclosed: {server_info}',
                    'recommendation': 'Minimize server banner information'
                })
            
            if powered_by:
                self.vulnerabilities.append({
                    'type': 'Info',
                    'category': 'Information Disclosure',
                    'url': self.target_url,
                    'description': f'Technology stack disclosed: {powered_by}',
                    'recommendation': 'Remove X-Powered-By header'
                })
        except:
            pass
    
    def generate_report(self):
        """Generate professional HTML report"""
        print(f"[+] Generating report: {self.output_file}")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Vulnerability Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .critical {{ color: #e74c3c; font-weight: bold; }}
                .high {{ color: #e67e22; font-weight: bold; }}
                .medium {{ color: #f39c12; }}
                .low {{ color: #f1c40f; }}
                .info {{ color: #3498db; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Web Vulnerability Assessment Report</h1>
                <p>Target: {self.target_url} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>Web application security assessment completed on {datetime.now().strftime('%Y-%m-%d')}. 
                Found {len(self.vulnerabilities)} potential security issues.</p>
                
                <h3>Vulnerability Summary</h3>
                <ul>
        """
        
        # Count vulnerabilities by type
        vuln_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in self.vulnerabilities:
            vuln_count[vuln['type']] += 1
        
        for severity, count in vuln_count.items():
            if count > 0:
                html_content += f'<li>{severity}: {count} vulnerabilities</li>'
        
        html_content += """
                </ul>
            </div>
            
            <div class="section">
                <h2>Detailed Findings</h2>
        """
        
        if self.vulnerabilities:
            html_content += """
                <table>
                    <tr><th>Severity</th><th>Category</th><th>URL</th><th>Description</th><th>Recommendation</th></tr>
            """
            for vuln in self.vulnerabilities:
                html_content += f"""
                    <tr>
                        <td class="{vuln['type'].lower()}">{vuln['type']}</td>
                        <td>{vuln['category']}</td>
                        <td><a href="{vuln['url']}" target="_blank">{vuln['url'][:50]}...</a></td>
                        <td>{vuln['description']}</td>
                        <td>{vuln['recommendation']}</td>
                    </tr>
                """
            html_content += "</table>"
        else:
            html_content += "<p>No vulnerabilities detected during this scan.</p>"
        
        html_content += """
            </div>
            
            <div class="section">
                <h2>Security Recommendations</h2>
                <ul>
                    <li>Implement proper input validation and output encoding</li>
                    <li>Use parameterized queries to prevent SQL injection</li>
                    <li>Implement Content Security Policy (CSP)</li>
                    <li>Ensure all security headers are properly configured</li>
                    <li>Regularly update and patch web application frameworks</li>
                    <li>Conduct regular security testing and code reviews</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>Methodology</h2>
                <p>This assessment included tests for:</p>
                <ul>
                    <li>SQL Injection vulnerabilities</li>
                    <li>Cross-Site Scripting (XSS)</li>
                    <li>Directory Traversal</li>
                    <li>Information Disclosure</li>
                    <li>Security Headers Configuration</li>
                    <li>Server Information Disclosure</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(self.output_file, 'w') as f:
            f.write(html_content)
        
        print(f"[+] Report saved as: {self.output_file}")
    
    def run_scan(self):
        """Execute complete web vulnerability scan"""
        start_time = time.time()
        print(f"[+] Starting web vulnerability scan for: {self.target_url}")
        print(f"[+] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if not self.check_connection():
            print("[-] Target is not reachable. Please check the URL and network connection.")
            return
        
        # Run all vulnerability tests
        tests = [
            self.sql_injection_test,
            self.xss_test,
            self.directory_traversal_test,
            self.information_disclosure_test,
            self.security_headers_check,
            self.server_info_disclosure
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"[-] Test {test.__name__} failed: {e}")
        
        self.generate_report()
        
        end_time = time.time()
        print(f"[+] Scan completed in {end_time - start_time:.2f} seconds")
        print(f"[+] Found {len(self.vulnerabilities)} potential vulnerabilities")

def main():
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('target_url', help='Target URL (e.g., http://example.com)')
    parser.add_argument('-o', '--output', default='web_scan_report.html', 
                       help='Output report filename')
    
    args = parser.parse_args()
    
    # Disclaimer
    print("=" * 60)
    print("ETHICAL HACKING TOOL - FOR AUTHORIZED TESTING ONLY")
    print("Ensure you have proper authorization before use!")
    print("=" * 60)
    
    scanner = WebVulnerabilityScanner(args.target_url, args.output)
    scanner.run_scan()

if __name__ == "__main__":
    main()