#!/usr/bin/env python3
"""
BusinessRiskScan.py - Client-Focused Security Assessment
Answers: "How easy is it to hack us?" and "Is customer data protected?"
"""
import requests
import json
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime
import threading

class BusinessRiskScanner:
    def __init__(self, target_url, client_business_type):
        self.target_url = target_url
        self.client_business_type = client_business_type
        self.findings = []
        self.risk_score = 0
        self.max_risk = 100
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Professional Security Assessment'
        })
        
    def run_business_risk_assessment(self):
        """Run assessment focused on business risks"""
        print(f"🎯 Assessing business risk for: {self.target_url}")
        print(f"🏢 Business type: {self.client_business_type}")
        
        # Core security checks that answer client's questions
        checks = [
            self.check_data_protection,
            self.check_access_controls, 
            self.check_vulnerability_exposure,
            self.check_information_disclosure,
            self.check_security_fundamentals
        ]
        
        # Run all checks
        for check in checks:
            check()
        
        # Calculate overall risk score
        self.calculate_risk_score()
        
        # Generate business-focused report
        return self.generate_business_report()
    
    def check_data_protection(self):
        """Check how well customer data is protected"""
        print("🔒 Checking data protection...")
        
        # Check for SSL/TLS security
        try:
            if self.target_url.startswith('http:'):
                self.add_finding(
                    'Data in Transit', 
                    'HIGH', 
                    'No SSL Encryption',
                    'Customer data transmitted without encryption',
                    'Easy to intercept login credentials and personal data',
                    'Immediately enable HTTPS across entire site'
                )
                self.risk_score += 20
            else:
                # Check SSL configuration
                response = self.session.get(self.target_url, timeout=10)
                if response.url.startswith('https://'):
                    self.add_finding(
                        'Data in Transit',
                        'LOW',
                        'SSL Encryption Enabled', 
                        'Data transmitted over encrypted connection',
                        'Basic protection against eavesdropping',
                        'Maintain SSL certificate and consider HSTS'
                    )
        except:
            pass
        
        # Check for data exposure patterns
        self.check_sensitive_data_exposure()
    
    def check_sensitive_data_exposure(self):
        """Check for exposed sensitive data"""
        sensitive_patterns = [
            '/api/users', '/admin/users', '/customer/data',
            '/database/', '/backup/', '/config/'
        ]
        
        for pattern in sensitive_patterns:
            test_url = urljoin(self.target_url, pattern)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    # Check if it looks like sensitive data
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['email', 'password', 'user', 'customer']):
                        self.add_finding(
                            'Data Exposure',
                            'HIGH',
                            f'Sensitive data accessible at {pattern}',
                            'Customer information potentially exposed',
                            'Very easy to extract customer data',
                            'Immediately restrict access to sensitive endpoints'
                        )
                        self.risk_score += 25
            except:
                continue
    
    def check_access_controls(self):
        """Check how easy it is to access restricted areas"""
        print("🚪 Checking access controls...")
        
        common_admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/backend',
            '/login', '/signin', '/dashboard', '/controlpanel'
        ]
        
        for path in common_admin_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    # Check if it's a login page or admin area
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['login', 'password', 'admin', 'username']):
                        self.add_finding(
                            'Access Control',
                            'MEDIUM', 
                            f'Admin area found: {path}',
                            'Administrative interface is publicly accessible',
                            'Easy to find attack surface for password attacks',
                            'Restrict admin access to specific IPs or VPN'
                        )
                        self.risk_score += 15
                        
                elif response.status_code in [301, 302]:
                    # Redirect might indicate authentication required
                    self.add_finding(
                        'Access Control',
                        'LOW',
                        f'Protected area: {path}',
                        'Administrative access requires authentication',
                        'Basic access control in place',
                        'Ensure strong password policies and 2FA'
                    )
                        
            except:
                continue
    
    def check_vulnerability_exposure(self):
        """Check for obvious vulnerabilities"""
        print("⚠️ Checking vulnerability exposure...")
        
        # Test for common web vulnerabilities
        tests = [
            self.test_sql_injection_exposure,
            self.test_xss_exposure,
            self.test_server_misconfigurations
        ]
        
        for test in tests:
            test()
    
    def test_sql_injection_exposure(self):
        """Test for SQL injection vulnerability indicators"""
        test_params = ['id', 'product', 'user', 'category']
        test_payload = "' OR '1'='1"
        
        for param in test_params:
            test_url = f"{self.target_url}?{param}={test_payload}"
            try:
                response = self.session.get(test_url, timeout=8)
                content = response.text.lower()
                
                # Look for database error messages
                error_indicators = ['sql', 'syntax', 'mysql', 'oracle', 'database']
                if any(indicator in content for indicator in error_indicators):
                    self.add_finding(
                        'SQL Injection',
                        'HIGH',
                        f'SQL Injection vulnerability in {param} parameter',
                        'Database can be directly manipulated',
                        'Very easy to extract all customer data from database',
                        'Immediately implement parameterized queries and input validation'
                    )
                    self.risk_score += 30
                    break
                    
            except:
                continue
    
    def test_xss_exposure(self):
        """Test for XSS vulnerability indicators"""
        test_payload = "<script>alert('XSS')</script>"
        test_params = ['q', 'search', 'name', 'message']
        
        for param in test_params:
            test_url = f"{self.target_url}?{param}={test_payload}"
            try:
                response = self.session.get(test_url, timeout=8)
                if test_payload in response.text:
                    self.add_finding(
                        'Cross-Site Scripting (XSS)',
                        'MEDIUM',
                        f'XSS vulnerability in {param} parameter',
                        'Attackers can execute malicious scripts in user browsers',
                        'Easy to steal customer sessions and credentials',
                        'Implement input validation and output encoding'
                    )
                    self.risk_score += 20
                    
            except:
                continue
    
    def test_server_misconfigurations(self):
        """Check for server security misconfigurations"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Check security headers
            security_headers = {
                'Content-Security-Policy': 'Prevents XSS attacks',
                'X-Frame-Options': 'Prevents clickjacking',
                'Strict-Transport-Security': 'Forces SSL usage',
                'X-Content-Type-Options': 'Prevents MIME sniffing'
            }
            
            missing_headers = []
            for header, protection in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.add_finding(
                    'Security Headers',
                    'MEDIUM',
                    f'Missing security headers: {", ".join(missing_headers)}',
                    'Reduced protection against common web attacks',
                    'Easier for attackers to exploit other vulnerabilities',
                    'Implement missing security headers immediately'
                )
                self.risk_score += 15
            
            # Check server information disclosure
            server = headers.get('Server', '')
            if server:
                self.add_finding(
                    'Information Disclosure',
                    'LOW',
                    f'Server version disclosed: {server}',
                    'Attackers can target specific version vulnerabilities',
                    'Makes targeted attacks slightly easier',
                    'Remove or obscure server version information'
                )
                self.risk_score += 5
                
        except Exception as e:
            print(f"    ❌ Server check failed: {e}")
    
    def check_information_disclosure(self):
        """Check for information that helps attackers"""
        print("📄 Checking information disclosure...")
        
        sensitive_files = [
            '.env', '.git/config', 'backup.zip', 'wp-config.php',
            'config.json', 'robots.txt', '.htaccess', 'phpinfo.php'
        ]
        
        for file in sensitive_files:
            test_url = urljoin(self.target_url, file)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    self.add_finding(
                        'Information Disclosure',
                        'HIGH' if any(ext in file for ext in ['.env', 'config', 'backup']) else 'MEDIUM',
                        f'Sensitive file exposed: {file}',
                        'Configuration or system information publicly accessible',
                        'Very easy to find database passwords and system details',
                        'Immediately remove or restrict access to sensitive files'
                    )
                    self.risk_score += 20 if 'HIGH' else 15
                    
            except:
                continue
    
    def check_security_fundamentals(self):
        """Check basic security hygiene"""
        print("🛡️ Checking security fundamentals...")
        
        # Check for default or common content
        default_paths = [
            '/phpmyadmin', '/cpanel', '/webmail', '/test', '/demo'
        ]
        
        for path in default_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    self.add_finding(
                        'Security Hygiene',
                        'MEDIUM',
                        f'Default path accessible: {path}',
                        'Common attack target with known vulnerabilities',
                        'Easy for attackers to find and exploit',
                        'Remove or secure default installations'
                    )
                    self.risk_score += 10
                    
            except:
                continue
    
    def add_finding(self, category, severity, title, description, attacker_ease, recommendation):
        """Add a finding to results"""
        finding = {
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'attacker_ease': attacker_ease,
            'recommendation': recommendation,
            'business_impact': self.get_business_impact(category, severity)
        }
        self.findings.append(finding)
        
        print(f"  🔍 [{severity}] {title}")
    
    def get_business_impact(self, category, severity):
        """Translate technical finding to business impact"""
        impacts = {
            'HIGH': {
                'Data in Transit': 'Customer data can be intercepted and stolen',
                'Data Exposure': 'Direct loss of customer confidential information',
                'SQL Injection': 'Complete database compromise and data theft',
                'Information Disclosure': 'System credentials and configuration exposed'
            },
            'MEDIUM': {
                'Access Control': 'Administrative systems exposed to attack',
                'Cross-Site Scripting (XSS)': 'Customer account takeover possible',
                'Security Headers': 'Increased risk of successful attacks',
                'Security Hygiene': 'Known vulnerabilities easily exploitable'
            },
            'LOW': {
                'Information Disclosure': 'Attackers can gather intelligence',
                'Data in Transit': 'Basic protection in place but could be improved'
            }
        }
        
        return impacts.get(severity, {}).get(category, 'General security concern')
    
    def calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        # Ensure score doesn't exceed max
        self.risk_score = min(self.risk_score, self.max_risk)
        
        # Risk level interpretation
        if self.risk_score >= 70:
            self.risk_level = "CRITICAL"
        elif self.risk_score >= 50:
            self.risk_level = "HIGH" 
        elif self.risk_score >= 30:
            self.risk_level = "MEDIUM"
        elif self.risk_score >= 10:
            self.risk_level = "LOW"
        else:
            self.risk_level = "MINIMAL"
    
    def generate_business_report(self):
        """Generate client-focused business report"""
        print("\n📊 Generating business risk report...")
        
        report = {
            "business_security_assessment": {
                "client_website": self.target_url,
                "business_type": self.client_business_type,
                "assessment_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "executive_summary": {
                    "overall_risk_score": f"{self.risk_score}/{self.max_risk}",
                    "risk_level": self.risk_level,
                    "answer_to_client": self.generate_client_answer(),
                    "key_findings_count": len(self.findings),
                    "time_to_compromise": self.estimate_time_to_compromise()
                },
                "detailed_findings": self.findings,
                "priority_recommendations": self.get_priority_recommendations(),
                "next_steps": [
                    "Address critical findings immediately",
                    "Implement security monitoring",
                    "Schedule follow-up assessment",
                    "Consider ongoing security partnership"
                ]
            }
        }
        
        filename = f"Business_Risk_Assessment_{urlparse(self.target_url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.create_client_summary(report, filename)
        return filename
    
    def generate_client_answer(self):
        """Generate direct answer to client's questions"""
        if self.risk_level == "CRITICAL":
            return "VERY EASY to compromise - Customer data is NOT well protected"
        elif self.risk_level == "HIGH":
            return "EASY to compromise - Customer data protection needs immediate improvement"
        elif self.risk_level == "MEDIUM":
            return "MODERATELY difficult to compromise - Basic protections but significant gaps"
        elif self.risk_level == "LOW":
            return "DIFFICULT to compromise - Good baseline protection with minor improvements needed"
        else:
            return "VERY DIFFICULT to compromise - Well protected with strong security controls"
    
    def estimate_time_to_compromise(self):
        """Estimate how long it would take attackers"""
        if self.risk_score >= 70:
            return "Hours to days for skilled attacker"
        elif self.risk_score >= 50:
            return "Days to weeks for skilled attacker" 
        elif self.risk_score >= 30:
            return "Weeks to months for skilled attacker"
        else:
            return "Months or longer for skilled attacker"
    
    def get_priority_recommendations(self):
        """Get top 3 priority recommendations"""
        high_priority = [f for f in self.findings if f['severity'] == 'HIGH']
        medium_priority = [f for f in self.findings if f['severity'] == 'MEDIUM']
        
        priorities = []
        
        # Add high priority first
        for finding in high_priority[:2]:
            priorities.append({
                'priority': 'CRITICAL',
                'action': finding['recommendation'],
                'business_impact': finding['business_impact']
            })
        
        # Add medium priority if needed
        if len(priorities) < 3 and medium_priority:
            for finding in medium_priority[:3-len(priorities)]:
                priorities.append({
                    'priority': 'HIGH',
                    'action': finding['recommendation'], 
                    'business_impact': finding['business_impact']
                })
        
        return priorities
    
    def create_client_summary(self, report, json_filename):
        """Create beautiful client summary"""
        txt_filename = json_filename.replace('.json', '_CLIENT_SUMMARY.txt')
        
        with open(txt_filename, 'w') as f:
            f.write("="*80 + "\n")
            f.write("🔒 BUSINESS SECURITY ASSESSMENT - CLIENT SUMMARY\n")
            f.write("="*80 + "\n\n")
            
            f.write("DIRECT ANSWERS TO YOUR QUESTIONS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Question: How easy is it to hack our website?\n")
            f.write(f"Answer: {report['business_security_assessment']['executive_summary']['answer_to_client']}\n\n")
            
            f.write(f"Question: How well is customer data protected?\n")
            f.write(f"Answer: Risk Level: {report['business_security_assessment']['executive_summary']['risk_level']}\n")
            f.write(f"        Estimated Time to Compromise: {report['business_security_assessment']['executive_summary']['time_to_compromise']}\n\n")
            
            f.write("OVERALL RISK ASSESSMENT\n")
            f.write("-" * 80 + "\n")
            f.write(f"Risk Score: {report['business_security_assessment']['executive_summary']['overall_risk_score']}\n")
            f.write(f"Findings Identified: {report['business_security_assessment']['executive_summary']['key_findings_count']}\n\n")
            
            f.write("TOP PRIORITY ACTIONS\n")
            f.write("-" * 80 + "\n")
            for rec in report['business_security_assessment']['priority_recommendations']:
                f.write(f"• [{rec['priority']}] {rec['action']}\n")
                f.write(f"  Business Impact: {rec['business_impact']}\n\n")
            
            f.write("IMMEDIATE NEXT STEPS\n")
            f.write("-" * 80 + "\n")
            f.write("1. Review critical findings with your team\n")
            f.write("2. Implement priority recommendations\n") 
            f.write("3. Schedule technical deep dive if needed\n")
            f.write("4. Consider ongoing security monitoring\n")
            f.write("\n")
            
            f.write("="*80 + "\n")
            f.write("Professional Security Assessment - Confidential\n")
            f.write("="*80 + "\n")
        
        print(f"📄 Client summary: {txt_filename}")
        print(f"📋 Detailed report: {json_filename}")

# Usage example
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 BusinessRiskScan.py <url> <business_type>")
        print("Example: python3 BusinessRiskScan.py https://example.com ecommerce")
        print("Business types: ecommerce, healthcare, finance, saas, consulting, other")
        sys.exit(1)
    
    url = sys.argv[1]
    business_type = sys.argv[2]
    
    print("""
    🎯 BUSINESS SECURITY ASSESSMENT
    Answering: "How easy is it to hack us?" and "Is customer data protected?"
    """)
    
    scanner = BusinessRiskScanner(url, business_type)
    report_file = scanner.run_business_risk_assessment()
    
    print(f"\n✅ Assessment complete! Client report: {report_file}")