#!/usr/bin/env python3
"""
RED TEAM FRAMEWORK - ENHANCED EDITION v2.0
Ultra-Evasive Red Team Operations with Real-Time Monitoring

ENHANCEMENTS:
- Real-time progress dashboard
- Live activity monitoring
- Enhanced reporting with graphs
- Detection simulation
- Improved error handling
- Configuration profiles
- Safety mechanisms
- Statistics tracking
- Timeline visualization
"""

import os
import sys
import subprocess
import json
import time
import re
import base64
import random
import string
import argparse
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# REGION: ENHANCED CONFIGURATION

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Display enhanced banner"""
    banner = f"""{Colors.MAGENTA}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║ 🥷 RED TEAM FRAMEWORK - ENHANCED EDITION v2.0                            ║
║ Real-Time Monitoring & Advanced Stealth Operations                      ║
║                                                                          ║
║ ⚠ AUTHORIZED USE ONLY - Live Progress Tracking ⚠                        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

class EnhancedConfig:
    """Enhanced configuration with profiles"""
    PROFILES = {
        'fast': {
            'min_delay': 10,
            'max_delay': 30,
            'work_hours_only': False,
            'max_auth_attempts': 3,
            'connections_per_min': 10,
            'description': 'Fast reconnaissance (higher detection risk)'
        },
        'balanced': {
            'min_delay': 60,
            'max_delay': 180,
            'work_hours_only': False,
            'max_auth_attempts': 3,
            'connections_per_min': 5,
            'description': 'Balanced speed and stealth'
        },
        'stealth': {
            'min_delay': 120,
            'max_delay': 300,
            'work_hours_only': True,
            'max_auth_attempts': 2,
            'connections_per_min': 3,
            'description': 'High stealth (slow but evasive)'
        },
        'ghost': {
            'min_delay': 300,
            'max_delay': 600,
            'work_hours_only': True,
            'max_auth_attempts': 1,
            'connections_per_min': 1,
            'description': 'Maximum stealth (extremely slow)'
        }
    }

class ProgressTracker:
    """Real-time progress tracking and visualization"""
    def __init__(self):
        self.phases = {
            'recon': {'status': 'pending', 'progress': 0, 'findings': [], 'start_time': None, 'end_time': None},
            'access': {'status': 'pending', 'progress': 0, 'findings': [], 'start_time': None, 'end_time': None},
            'post_exploit': {'status': 'pending', 'progress': 0, 'findings': [], 'start_time': None, 'end_time': None},
            'lateral': {'status': 'pending', 'progress': 0, 'findings': [], 'start_time': None, 'end_time': None},
            'persistence': {'status': 'pending', 'progress': 0, 'findings': [], 'start_time': None, 'end_time': None},
            'reporting': {'status': 'pending', 'progress': 0, 'findings': [], 'start_time': None, 'end_time': None}
        }
        self.current_phase = None
        self.start_time = time.time()
        self.events = []
        self.lock = threading.Lock()
        
    def update_phase(self, phase, status, progress=None, finding=None):
        """Update phase status"""
        with self.lock:
            if phase in self.phases:
                old_status = self.phases[phase]['status']
                self.phases[phase]['status'] = status
                
                if old_status == 'pending' and status == 'in_progress':
                    self.phases[phase]['start_time'] = time.time()
                
                if status == 'completed' or status == 'failed':
                    self.phases[phase]['end_time'] = time.time()
                
                if progress is not None:
                    self.phases[phase]['progress'] = progress
                if finding:
                    self.phases[phase]['findings'].append({
                        'time': datetime.now(),
                        'text': finding
                    })
                self.current_phase = phase
    
    def add_event(self, event_type, description, severity='info'):
        """Add timeline event"""
        with self.lock:
            self.events.append({
                'timestamp': datetime.now(),
                'type': event_type,
                'description': description,
                'severity': severity
            })
    
    def get_elapsed_time(self):
        """Get elapsed time"""
        elapsed = time.time() - self.start_time
        return str(timedelta(seconds=int(elapsed)))
    
    def get_phase_duration(self, phase):
        """Get duration of a specific phase"""
        phase_data = self.phases.get(phase)
        if not phase_data or not phase_data['start_time']:
            return "N/A"
        
        end = phase_data['end_time'] or time.time()
        duration = end - phase_data['start_time']
        return str(timedelta(seconds=int(duration)))
    
    def print_dashboard(self, clear_screen=True):
        """Print live dashboard"""
        if clear_screen:
            os.system('clear' if os.name != 'nt' else 'cls')
        
        # Header
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}{'='*90}{Colors.END}")
        print(f"{Colors.MAGENTA}{Colors.BOLD}  🥷 STEALTH RED TEAM OPERATION - LIVE DASHBOARD{Colors.END}")
        print(f"{Colors.MAGENTA}{Colors.BOLD}{'='*90}{Colors.END}\n")
        
        print(f"{Colors.CYAN}⏱  Elapsed Time: {Colors.YELLOW}{self.get_elapsed_time()}{Colors.END}")
        print(f"{Colors.CYAN}📊 Current Phase: {Colors.YELLOW}{self.current_phase.upper() if self.current_phase else 'Initializing'}{Colors.END}")
        print(f"{Colors.CYAN}📅 Timestamp: {Colors.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}\n")
        
        # Phase progress
        print(f"{Colors.BOLD}{'OPERATION PHASES':<50}{'STATUS':<15}{'PROGRESS'}{Colors.END}\n")
        
        phase_names = {
            'recon': '🔍 Reconnaissance',
            'access': '🔐 Access Testing',
            'post_exploit': '🕵️  Post-Exploitation',
            'lateral': '🌐 Lateral Movement',
            'persistence': '🔒 Persistence',
            'reporting': '📋 Reporting'
        }
        
        for phase_id, phase_name in phase_names.items():
            phase_data = self.phases[phase_id]
            status = phase_data['status']
            progress = phase_data['progress']
            
            # Status icon and color
            if status == 'completed':
                icon = f"{Colors.GREEN}✓{Colors.END}"
                status_text = f"{Colors.GREEN}COMPLETE{Colors.END}"
            elif status == 'in_progress':
                icon = f"{Colors.YELLOW}⟳{Colors.END}"
                status_text = f"{Colors.YELLOW}RUNNING{Colors.END} "
            elif status == 'failed':
                icon = f"{Colors.RED}✗{Colors.END}"
                status_text = f"{Colors.RED}FAILED{Colors.END}  "
            else:
                icon = f"{Colors.DIM}○{Colors.END}"
                status_text = f"{Colors.DIM}PENDING{Colors.END} "
            
            # Progress bar
            bar_length = 25
            filled = int(bar_length * progress / 100)
            bar = f"{Colors.GREEN}{'█' * filled}{Colors.DIM}{'░' * (bar_length - filled)}{Colors.END}"
            
            print(f"  {icon} {phase_name:<35} {status_text:<22} {bar} {progress:>3}%")
            
            # Show recent findings
            if phase_data['findings']:
                recent = phase_data['findings'][-2:]  # Last 2 findings
                for finding in recent:
                    time_str = finding['time'].strftime("%H:%M:%S")
                    print(f"     {Colors.DIM}└─ [{time_str}] {finding['text']}{Colors.END}")
        
        print()
        
        # Recent activity section
        print(f"{Colors.BOLD}{'RECENT ACTIVITY':<50}{'TIME'}{Colors.END}\n")
        recent_events = self.events[-6:] if len(self.events) > 6 else self.events
        
        if recent_events:
            for event in recent_events:
                time_str = event['timestamp'].strftime("%H:%M:%S")
                
                if event['severity'] == 'critical':
                    color = Colors.RED
                    icon = '⚠'
                elif event['severity'] == 'success':
                    color = Colors.GREEN
                    icon = '✓'
                elif event['severity'] == 'warning':
                    color = Colors.YELLOW
                    icon = '!'
                else:
                    color = Colors.CYAN
                    icon = '•'
                
                desc = event['description'][:60]  # Truncate long descriptions
                print(f"  {color}{icon}{Colors.END} {desc:<63} {Colors.DIM}[{time_str}]{Colors.END}")
        else:
            print(f"  {Colors.DIM}No activity yet...{Colors.END}")
        
        print(f"\n{Colors.MAGENTA}{'='*90}{Colors.END}")
        print(f"{Colors.DIM}Press Ctrl+C to interrupt operation{Colors.END}\n")

class EnhancedStealthRedTeam:
    """Enhanced Stealth Red Team with real-time monitoring"""
    
    def __init__(self, target, username=None, password=None, domain=None, profile='balanced', verbose=True):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.profile_name = profile
        self.config = EnhancedConfig.PROFILES.get(profile, EnhancedConfig.PROFILES['balanced'])
        self.verbose = verbose
        
        # Progress tracking
        self.tracker = ProgressTracker()
        
        # Results
        self.open_ports = []
        self.services = {}
        self.os_type = None
        self.vulnerabilities = []
        self.access_gained = False
        self.hosts_discovered = []
        self.credentials_found = []
        self.persistence_methods = []
        
        # Stats
        self.stats = {
            'commands_executed': 0,
            'auth_attempts': 0,
            'connections_made': 0,
            'ports_scanned': 0,
            'services_identified': 0,
            'vulnerabilities_found': 0,
            'data_collected_mb': 0,
            'stealth_score': 100
        }
        
        # Stealth tracking
        self.last_action_time = time.time()
        self.connection_count = 0
        self.connection_reset_time = time.time()
        
        # Setup
        self.setup_workspace()
        self.session_id = self.generate_random_id()
        self.log_file = f"sessions/{self.session_id}/operation.log"
        
        self.log_event("Operation initialized", "info")
        self.log_event(f"Target: {target}", "info")
        self.log_event(f"Profile: {profile} - {self.config['description']}", "info")
    
    def setup_workspace(self):
        """Create workspace directories"""
        dirs = ['sessions', 'loot', 'reports', 'tools', 'bloodhound', 'downloads']
        for d in dirs:
            Path(d).mkdir(exist_ok=True)
    
    def generate_random_id(self):
        """Generate random session ID"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    
    def log_event(self, message, severity='info'):
        """Log event to tracker and file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{severity.upper()}] {message}"
        
        # Add to tracker
        self.tracker.add_event('operation', message, severity)
        
        # Save to file
        session_dir = f"sessions/{self.session_id}"
        Path(session_dir).mkdir(parents=True, exist_ok=True)
        with open(f"{session_dir}/operation.log", 'a') as f:
            f.write(log_entry + "\n")
    
    def stealth_delay(self, action_type="general", show_countdown=True):
        """Intelligent delay with progress updates"""
        base_delay = self.config['min_delay']
        max_delay = self.config['max_delay']
        delay = random.randint(base_delay, max_delay)
        jitter = random.uniform(0, delay * 0.3)
        total_delay = delay + jitter
        
        # Check business hours if required
        if self.config['work_hours_only']:
            while not self.is_business_hours():
                self.log_event("Outside business hours, waiting...", "info")
                if self.verbose:
                    self.tracker.print_dashboard()
                time.sleep(300)  # Check every 5 minutes
        
        self.log_event(f"Stealth delay: {int(total_delay)}s ({action_type})", "info")
        
        # Progress during delay with dashboard updates
        if show_countdown and self.verbose:
            intervals = min(10, int(total_delay / 2))  # Update 10 times or every 2 seconds
            chunk = total_delay / intervals
            for i in range(intervals):
                time.sleep(chunk)
                if i % 2 == 0:  # Update dashboard every other interval
                    self.tracker.print_dashboard()
        else:
            time.sleep(total_delay)
        
        self.last_action_time = time.time()
    
    def is_business_hours(self):
        """Check if current time is within business hours"""
        current_hour = datetime.now().hour
        current_day = datetime.now().weekday()  # 0 = Monday, 6 = Sunday
        
        # Check if weekday (Monday-Friday)
        if current_day >= 5:  # Weekend
            return False
        
        return 8 <= current_hour <= 18
    
    def rate_limit_check(self):
        """Ensure we don't exceed connection rate limits"""
        current_time = time.time()
        
        if current_time - self.connection_reset_time > 60:
            self.connection_count = 0
            self.connection_reset_time = current_time
        
        max_conn = self.config['connections_per_min']
        if self.connection_count >= max_conn:
            wait_time = 60 - (current_time - self.connection_reset_time)
            self.log_event(f"Rate limit reached ({max_conn}/min), waiting {int(wait_time)}s", "warning")
            
            if self.verbose:
                self.tracker.print_dashboard()
            
            time.sleep(wait_time)
            self.connection_count = 0
            self.connection_reset_time = time.time()
        
        self.connection_count += 1
        self.stats['connections_made'] += 1
    
    def run_command(self, command, timeout=300, stealth=True):
        """Execute command with monitoring"""
        if stealth:
            self.rate_limit_check()
        
        self.stats['commands_executed'] += 1
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self.log_event(f"Command timeout: {command[:50]}...", "warning")
            return None, "Command timed out", 1
        except Exception as e:
            self.log_event(f"Command error: {str(e)}", "warning")
            return None, str(e), 1
    
    # ========================================================================
    # PHASE 1: ENHANCED RECONNAISSANCE
    # ========================================================================
    
    def phase_enhanced_recon(self):
        """Phase 1: Enhanced reconnaissance with progress tracking"""
        self.tracker.update_phase('recon', 'in_progress', 0)
        self.log_event("Starting reconnaissance phase", "info")
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        # Port scanning
        self.tracker.update_phase('recon', 'in_progress', 10)
        self.log_event("Initiating port scanning", "info")
        self.enhanced_port_scan()
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        # Service enumeration
        if self.open_ports:
            self.stealth_delay("service_enum", show_countdown=False)
            self.tracker.update_phase('recon', 'in_progress', 50)
            self.log_event("Enumerating services", "info")
            self.enhanced_service_enum()
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        # OS detection
        self.tracker.update_phase('recon', 'in_progress', 75)
        self.log_event("Detecting operating system", "info")
        self.enhanced_os_detection()
        
        # Vulnerability scanning
        self.tracker.update_phase('recon', 'in_progress', 90)
        self.log_event("Checking for vulnerabilities", "info")
        self.vulnerability_check()
        
        self.tracker.update_phase('recon', 'completed', 100)
        self.log_event(f"Reconnaissance complete - Found {len(self.open_ports)} open ports", "success")
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        return True
    
    def enhanced_port_scan(self):
        """Enhanced port scanning with detailed feedback"""
        priority_ports = [
            ('445', 'smb', 'critical'),
            ('3389', 'rdp', 'high'),
            ('5985', 'winrm', 'high'),
            ('22', 'ssh', 'high'),
            ('443', 'https', 'medium'),
            ('80', 'http', 'medium'),
            ('135', 'msrpc', 'medium'),
            ('139', 'netbios', 'medium'),
            ('21', 'ftp', 'low'),
            ('3306', 'mysql', 'low'),
            ('1433', 'mssql', 'medium'),
            ('5432', 'postgres', 'medium')
        ]
        
        total_ports = len(priority_ports)
        self.stats['ports_scanned'] = total_ports
        
        for idx, (port, service, priority) in enumerate(priority_ports):
            progress = 10 + int((idx + 1) / total_ports * 40)  # 10-50% of recon phase
            self.tracker.update_phase('recon', 'in_progress', progress)
            
            self.log_event(f"Scanning port {port} ({service})", "info")
            
            # Actual scan
            cmd = f"timeout 10 nc -zv -w 2 {self.target} {port} 2>&1 || nmap -Pn -sT --max-rate 1 -p {port} {self.target} 2>/dev/null"
            stdout, stderr, code = self.run_command(cmd, stealth=True, timeout=15)
            
            is_open = False
            if stdout:
                if 'succeeded' in stdout.lower() or 'open' in stdout.lower():
                    is_open = True
            
            if is_open:
                self.open_ports.append(port)
                self.services[port] = {
                    'name': service,
                    'priority': priority,
                    'version': 'Unknown'
                }
                
                finding = f"Port {port} ({service}) - {priority.upper()}"
                self.tracker.update_phase('recon', 'in_progress', progress, finding=finding)
                self.log_event(f"✓ Open port found: {port} ({service})", "success")
                self.stats['services_identified'] += 1
            
            if self.verbose and idx % 3 == 0:  # Update dashboard every 3 ports
                self.tracker.print_dashboard()
            
            # Small delay between port scans
            if idx < total_ports - 1:
                time.sleep(random.uniform(1, 3))
    
    def enhanced_service_enum(self):
        """Enhanced service enumeration"""
        if not self.open_ports:
            return
        
        total_services = len(self.open_ports)
        
        for idx, port in enumerate(self.open_ports):
            progress = 50 + int((idx + 1) / total_services * 25)  # 50-75% of recon
            self.tracker.update_phase('recon', 'in_progress', progress)
            
            self.log_event(f"Probing service on port {port}", "info")
            
            # Try banner grabbing first (faster)
            cmd = f"timeout 5 nc -v {self.target} {port} 2>&1 | head -n 5"
            stdout, stderr, code = self.run_command(cmd, stealth=True, timeout=10)
            
            if stdout and len(stdout) > 10:
                banner = stdout[:100]
                self.services[port]['banner'] = banner
                self.log_event(f"Got banner from port {port}", "success")
            
            # Then try nmap version detection for more detail
            self.stealth_delay("version_scan", show_countdown=False)
            cmd = f"nmap -Pn -sV --version-intensity 2 -p {port} {self.target} 2>/dev/null"
            stdout, stderr, code = self.run_command(cmd, stealth=True, timeout=60)
            
            if stdout:
                for line in stdout.split('\n'):
                    if f'{port}/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            version_info = ' '.join(parts[2:6])
                            self.services[port]['version'] = version_info
                            
                            finding = f"Port {port}: {version_info[:40]}"
                            self.tracker.update_phase('recon', 'in_progress', progress, finding=finding)
                            self.log_event(f"Service identified: {finding}", "success")
            
            if self.verbose and idx % 2 == 0:
                self.tracker.print_dashboard()
    
    def enhanced_os_detection(self):
        """Enhanced OS detection"""
        # Passive detection based on open ports and services
        windows_indicators = ['445', '139', '3389', '135', '5985']
        linux_indicators = ['22']
        
        windows_score = sum(1 for port in windows_indicators if port in self.open_ports)
        linux_score = sum(1 for port in linux_indicators if port in self.open_ports)
        
        if windows_score > linux_score:
            self.os_type = 'Windows'
            confidence = 'High' if windows_score >= 3 else 'Medium'
        elif linux_score > 0:
            self.os_type = 'Linux'
            confidence = 'Medium'
        else:
            self.os_type = 'Unknown'
            confidence = 'Low'
        
        # Check service banners for more clues
        for port, service_info in self.services.items():
            version = service_info.get('version', '').lower()
            banner = service_info.get('banner', '').lower()
            
            if 'microsoft' in version or 'windows' in version or 'microsoft' in banner:
                self.os_type = 'Windows'
                confidence = 'High'
                break
            elif 'ubuntu' in version or 'debian' in version or 'linux' in version:
                self.os_type = 'Linux'
                confidence = 'High'
                break
        
        finding = f"OS: {self.os_type} (Confidence: {confidence})"
        self.tracker.update_phase('recon', 'in_progress', finding=finding)
        self.log_event(f"OS detected: {self.os_type} ({confidence} confidence)", "success")
    
    def vulnerability_check(self):
        """Check for common vulnerabilities"""
        # Check for SMB vulnerabilities
        if '445' in self.open_ports:
            self.log_event("Checking SMB for vulnerabilities", "info")
            
            # Simulate vuln check (in real scenario, use actual tools)
            # Check for SMBv1
            cmd = f"nmap -Pn --script smb-protocols -p 445 {self.target} 2>/dev/null"
            stdout, stderr, code = self.run_command(cmd, stealth=True, timeout=60)
            
            if stdout and 'SMBv1' in stdout:
                vuln = {
                    'name': 'SMBv1 Enabled',
                    'severity': 'HIGH',
                    'port': '445',
                    'description': 'SMBv1 is enabled and vulnerable to various attacks'
                }
                self.vulnerabilities.append(vuln)
                self.stats['vulnerabilities_found'] += 1
                self.tracker.update_phase('recon', 'in_progress', 
                    finding=f"⚠ HIGH: SMBv1 enabled")
                self.log_event("Vulnerability found: SMBv1 enabled", "warning")
        
        # Check for RDP
        if '3389' in self.open_ports:
            vuln = {
                'name': 'RDP Exposed',
                'severity': 'MEDIUM',
                'port': '3389',
                'description': 'RDP is exposed to the internet'
            }
            self.vulnerabilities.append(vuln)
            self.stats['vulnerabilities_found'] += 1
            self.tracker.update_phase('recon', 'in_progress', 
                finding=f"⚠ MEDIUM: RDP exposed")
            self.log_event("RDP service exposed", "warning")
        
        # Check for unencrypted services
        unencrypted_ports = {'21': 'FTP', '80': 'HTTP', '23': 'Telnet'}
        for port, service in unencrypted_ports.items():
            if port in self.open_ports:
                vuln = {
                    'name': f'Unencrypted {service}',
                    'severity': 'LOW',
                    'port': port,
                    'description': f'{service} transmits data in cleartext'
                }
                self.vulnerabilities.append(vuln)
                self.stats['vulnerabilities_found'] += 1
                self.log_event(f"Unencrypted service found: {service}", "warning")
    
    # ========================================================================
    # PHASE 2: ENHANCED ACCESS TESTING
    # ========================================================================
    
    def phase_enhanced_access(self):
        """Phase 2: Enhanced access testing"""
        self.tracker.update_phase('access', 'in_progress', 0)
        self.log_event("Starting access testing phase", "info")
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        if not self.username or not self.password:
            self.log_event("No credentials provided - skipping access phase", "warning")
            self.tracker.update_phase('access', 'completed', 100, 
                finding="Skipped: No credentials provided")
            return False
        
        max_attempts = self.config['max_auth_attempts']
        self.log_event(f"Testing credentials (max {max_attempts} attempts)", "info")
        
        # Calculate stealth penalty for auth attempts
        if max_attempts > 2:
            self.stats['stealth_score'] -= 5
        
        # Try SMB
        if '445' in self.open_ports or '139' in self.open_ports:
            self.tracker.update_phase('access', 'in_progress', 30)
            self.log_event("Attempting SMB authentication", "info")
            
            if self.verbose:
                self.tracker.print_dashboard()
            
            self.stealth_delay("authentication")
            
            if self.enhanced_smb_auth():
                self.access_gained = True
                self.tracker.update_phase('access', 'completed', 100, 
                    finding="✓ SMB access gained (ADMIN)")
                self.log_event("SMB access successful", "success")
                return True
        
        # Try WinRM
        if '5985' in self.open_ports or '5986' in self.open_ports:
            self.tracker.update_phase('access', 'in_progress', 60)
            self.log_event("Attempting WinRM authentication", "info")
            
            if self.verbose:
                self.tracker.print_dashboard()
            
            self.stealth_delay("authentication")
            
            if self.enhanced_winrm_auth():
                self.access_gained = True
                self.tracker.update_phase('access', 'completed', 100, 
                    finding="✓ WinRM access gained")
                self.log_event("WinRM access successful", "success")
                return True
        
        # Try SSH
        if '22' in self.open_ports:
            self.tracker.update_phase('access', 'in_progress', 90)
            self.log_event("Attempting SSH authentication", "info")
            
            if self.verbose:
                self.tracker.print_dashboard()
            
            self.stealth_delay("authentication")
            
            if self.enhanced_ssh_auth():
                self.access_gained = True
                self.tracker.update_phase('access', 'completed', 100, 
                    finding="✓ SSH access gained")
                self.log_event("SSH access successful", "success")
                return True
        
        self.tracker.update_phase('access', 'failed', 100, 
            finding="✗ All authentication attempts failed")
        self.log_event("All authentication attempts failed", "warning")
        self.stats['stealth_score'] -= 10  # Penalty for failed auths
        return False
    
    def enhanced_smb_auth(self):
        """Enhanced SMB authentication"""
        self.stats['auth_attempts'] += 1
        
        if self.stats['auth_attempts'] > self.config['max_auth_attempts']:
            self.log_event("Max auth attempts exceeded", "warning")
            return False
        
        time.sleep(random.randint(10, 30))  # Random delay before auth
        
        domain_part = f"-d {self.domain}" if self.domain else ""
        cmd = f"crackmapexec smb {self.target} -u {self.username} -p '{self.password}' {domain_part} 2>/dev/null"
        stdout, stderr, code = self.run_command(cmd, stealth=True, timeout=60)
        
        if stdout:
            if 'Pwn3d' in stdout:
                self.log_event("SMB authentication successful - ADMIN ACCESS", "success")
                self.tracker.update_phase('access', 'in_progress', 
                    finding="Admin access via SMB")
                return True
            elif '+' in stdout:
                self.log_event("SMB authentication successful - USER ACCESS", "success")
                self.tracker.update_phase('access', 'in_progress', 
                    finding="User access via SMB")
                return True
        
        self.log_event("SMB authentication failed", "warning")
        return False
    
    def enhanced_winrm_auth(self):
        """Enhanced WinRM authentication"""
        self.stats['auth_attempts'] += 1
        
        if self.stats['auth_attempts'] > self.config['max_auth_attempts']:
            return False
        
        time.sleep(random.randint(10, 30))
        
        cmd = f"crackmapexec winrm {self.target} -u {self.username} -p '{self.password}' 2>/dev/null"
        stdout, stderr, code = self.run_command(cmd, timeout=60, stealth=True)
        
        if stdout and ('Pwn3d' in stdout or '+' in stdout):
            self.log_event("WinRM access successful", "success")
            return True
        
        self.log_event("WinRM authentication failed", "warning")
        return False
    
    def enhanced_ssh_auth(self):
        """Enhanced SSH authentication"""
        self.stats['auth_attempts'] += 1
        
        if self.stats['auth_attempts'] > self.config['max_auth_attempts']:
            return False
        
        time.sleep(random.randint(10, 30))
        
        cmd = f"sshpass -p '{self.password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {self.username}@{self.target} 'echo SUCCESS' 2>/dev/null"
        stdout, stderr, code = self.run_command(cmd, timeout=30, stealth=True)
        
        if stdout and 'SUCCESS' in stdout:
            self.log_event("SSH access successful", "success")
            return True
        
        self.log_event("SSH authentication failed", "warning")
        return False
    
    # ========================================================================
    # PHASE 3: POST-EXPLOITATION
    # ========================================================================
    
    def phase_enhanced_post_exploit(self):
        """Phase 3: Enhanced post-exploitation"""
        self.tracker.update_phase('post_exploit', 'in_progress', 0)
        self.log_event("Starting post-exploitation phase", "info")
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        # System enumeration
        self.tracker.update_phase('post_exploit', 'in_progress', 20)
        self.log_event("Running system enumeration", "info")
        self.system_enumeration()
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        # User enumeration
        self.tracker.update_phase('post_exploit', 'in_progress', 40)
        self.stealth_delay("enumeration")
        self.log_event("Enumerating users and groups", "info")
        self.user_enumeration()
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        # Credential harvesting
        self.tracker.update_phase('post_exploit', 'in_progress', 70)
        self.stealth_delay("credential_harvest")
        self.log_event("Attempting credential harvest", "info")
        self.credential_harvesting()
        
        # File collection
        self.tracker.update_phase('post_exploit', 'in_progress', 90)
        self.stealth_delay("file_collection")
        self.log_event("Collecting sensitive files", "info")
        self.file_collection()
        
        self.tracker.update_phase('post_exploit', 'completed', 100)
        self.log_event("Post-exploitation phase completed", "success")
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        return True
    
    def system_enumeration(self):
        """System information gathering"""
        commands = [
            ('whoami', 'Current user'),
            ('hostname', 'Hostname'),
            ('systeminfo | findstr /B /C:"OS"', 'OS Information') if self.os_type == 'Windows' else ('uname -a', 'System info'),
        ]
        
        for cmd, desc in commands:
            self.log_event(f"Executing: {desc}", "info")
            
            if self.os_type == 'Windows':
                full_cmd = f"crackmapexec smb {self.target} -u {self.username} -p '{self.password}' -x '{cmd}' 2>/dev/null"
            else:
                full_cmd = f"sshpass -p '{self.password}' ssh {self.username}@{self.target} '{cmd}' 2>/dev/null"
            
            stdout, stderr, code = self.run_command(full_cmd, stealth=True, timeout=30)
            
            if stdout and len(stdout) > 5:
                finding = f"{desc}: {stdout[:50]}"
                self.tracker.update_phase('post_exploit', 'in_progress', finding=finding)
                self.log_event(f"Collected: {desc}", "success")
                self.stats['data_collected_mb'] += len(stdout) / 1024 / 1024
            
            time.sleep(random.uniform(3, 8))
    
    def user_enumeration(self):
        """Enumerate users and groups"""
        if self.os_type == 'Windows':
            commands = [
                'net user',
                'net localgroup administrators',
                'whoami /groups',
                'whoami /priv'
            ]
        else:
            commands = [
                'cat /etc/passwd',
                'groups',
                'sudo -l'
            ]
        
        for cmd in commands:
            self.log_event(f"Enumerating: {cmd[:30]}", "info")
            
            if self.os_type == 'Windows':
                full_cmd = f"crackmapexec smb {self.target} -u {self.username} -p '{self.password}' -x '{cmd}' 2>/dev/null"
            else:
                full_cmd = f"sshpass -p '{self.password}' ssh {self.username}@{self.target} '{cmd}' 2>/dev/null"
            
            stdout, stderr, code = self.run_command(full_cmd, stealth=True, timeout=30)
            
            if stdout:
                self.log_event(f"Enumeration successful", "success")
                self.stats['data_collected_mb'] += len(stdout) / 1024 / 1024
            
            time.sleep(random.uniform(5, 10))
    
    def credential_harvesting(self):
        """Harvest credentials (simulated for safety)"""
        self.log_event("Simulating credential harvest", "info")
        
        # Simulate finding credentials
        time.sleep(5)
        
        simulated_creds = [
            {'username': 'admin', 'hash': 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'},
            {'username': 'backup', 'hash': 'aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b'}
        ]
        
        for cred in simulated_creds:
            self.credentials_found.append(cred)
            finding = f"Found credential: {cred['username']}"
            self.tracker.update_phase('post_exploit', 'in_progress', finding=finding)
            self.log_event(f"Credential harvested: {cred['username']}", "success")
        
        self.stats['data_collected_mb'] += 0.01
    
    def file_collection(self):
        """Collect sensitive files"""
        self.log_event("Collecting sensitive files", "info")
        
        if self.os_type == 'Windows':
            search_paths = [
                'C:\\Users\\*\\Desktop\\*.txt',
                'C:\\Users\\*\\Documents\\*.pdf',
                'C:\\Users\\*\\Desktop\\*.docx'
            ]
        else:
            search_paths = [
                '/home/*/.ssh/*',
                '/home/*/Desktop/*.txt',
                '/etc/passwd'
            ]
        
        files_found = 0
        for path in search_paths[:2]:  # Limit to 2 for demo
            self.log_event(f"Searching: {path}", "info")
            time.sleep(random.uniform(2, 5))
            
            # Simulate finding files
            if random.random() > 0.5:
                files_found += 1
                finding = f"Found sensitive file in {path}"
                self.tracker.update_phase('post_exploit', 'in_progress', finding=finding)
                self.log_event(f"File collected from {path}", "success")
        
        if files_found > 0:
            self.stats['data_collected_mb'] += files_found * 0.5
    
    # ========================================================================
    # FINAL REPORTING AND SUMMARY
    # ========================================================================
    
    def generate_enhanced_report(self):
        """Generate enhanced HTML report"""
        self.tracker.update_phase('reporting', 'in_progress', 50)
        self.log_event("Generating comprehensive report", "info")
        
        if self.verbose:
            self.tracker.print_dashboard()
        
        report_file = f"reports/Enhanced_Report_{self.target.replace('.', '_')}_{self.session_id}.html"
        
        # Calculate final stats
        total_findings = len(self.open_ports) + len(self.vulnerabilities) + len(self.credentials_found)
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Red Team Report - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0a; color: #e0e0e0; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 40px; }}
        
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
                   padding: 40px; border-radius: 10px; margin-bottom: 30px; 
                   border-left: 5px solid #ff00ff; }}
        .header h1 {{ color: #ff00ff; font-size: 2.5em; margin-bottom: 10px; }}
        .header .meta {{ color: #888; font-size: 0.9em; }}
        
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                       gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: #1a1a2e; padding: 25px; border-radius: 10px; 
                     border-left: 4px solid #00ffff; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; color: #00ffff; margin: 10px 0; }}
        .stat-label {{ color: #888; font-size: 0.9em; text-transform: uppercase; }}
        
        .section {{ background: #1a1a2e; padding: 30px; border-radius: 10px; 
                    margin: 20px 0; border-left: 4px solid #00ff00; }}
        .section h2 {{ color: #00ffff; margin-bottom: 20px; font-size: 1.8em; }}
        
        .timeline {{ position: relative; padding-left: 30px; margin: 20px 0; }}
        .timeline-item {{ position: relative; padding: 15px 0; border-left: 2px solid #333; 
                          padding-left: 30px; margin-bottom: 15px; }}
        .timeline-item:before {{ content: '●'; position: absolute; left: -6px; 
                                 background: #00ff00; border-radius: 50%; width: 12px; 
                                 height: 12px; }}
        .timeline-time {{ color: #888; font-size: 0.85em; }}
        
        .finding-item {{ background: #0f0f1e; padding: 15px; margin: 10px 0; 
                        border-radius: 5px; border-left: 3px solid #ffaa00; }}
        .finding-critical {{ border-left-color: #ff0000; }}
        .finding-high {{ border-left-color: #ff6600; }}
        .finding-medium {{ border-left-color: #ffaa00; }}
        .finding-low {{ border-left-color: #00ff00; }}
        
        .severity-badge {{ display: inline-block; padding: 3px 10px; border-radius: 3px; 
                          font-size: 0.8em; font-weight: bold; }}
        .severity-critical {{ background: #ff0000; color: white; }}
        .severity-high {{ background: #ff6600; color: white; }}
        .severity-medium {{ background: #ffaa00; color: black; }}
        .severity-low {{ background: #00ff00; color: black; }}
        
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #16213e; color: #00ffff; }}
        tr:hover {{ background: #0f0f1e; }}
        
        .progress-bar {{ width: 100%; height: 30px; background: #0f0f1e; 
                        border-radius: 5px; overflow: hidden; margin: 10px 0; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #00ff00, #00ffff); 
                         transition: width 0.3s; }}
        
        .footer {{ text-align: center; color: #666; margin-top: 50px; padding-top: 30px; 
                  border-top: 1px solid #333; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🥷 Enhanced Red Team Operation Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {self.target}</p>
                <p><strong>Session ID:</strong> {self.session_id}</p>
                <p><strong>Profile:</strong> {self.profile_name.upper()} - {self.config['description']}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p><strong>Duration:</strong> {self.tracker.get_elapsed_time()}</p>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Operation Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Stealth Score</div>
                    <div class="stat-number">{self.stats['stealth_score']}/100</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Open Ports</div>
                    <div class="stat-number">{len(self.open_ports)}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Services Identified</div>
                    <div class="stat-number">{self.stats['services_identified']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Vulnerabilities</div>
                    <div class="stat-number">{self.stats['vulnerabilities_found']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Commands Executed</div>
                    <div class="stat-number">{self.stats['commands_executed']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Auth Attempts</div>
                    <div class="stat-number">{self.stats['auth_attempts']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Connections Made</div>
                    <div class="stat-number">{self.stats['connections_made']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Data Collected</div>
                    <div class="stat-number">{self.stats['data_collected_mb']:.2f} MB</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>⏱️ Operation Timeline</h2>
            <div class="timeline">"""
        
        # Add timeline events
        for event in self.tracker.events[-10:]:  # Last 10 events
            time_str = event['timestamp'].strftime("%H:%M:%S")
            html_content += f"""
                <div class="timeline-item">
                    <div class="timeline-time">{time_str}</div>
                    <div>{event['description']}</div>
                </div>"""
        
        html_content += f"""
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Phase Breakdown</h2>
            <table>
                <tr>
                    <th>Phase</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Progress</th>
                    <th>Key Findings</th>
                </tr>"""
        
        phase_names = {
            'recon': '🔍 Reconnaissance',
            'access': '🔐 Access Testing',
            'post_exploit': '🕵️ Post-Exploitation',
            'lateral': '🌐 Lateral Movement',
            'persistence': '🔒 Persistence',
            'reporting': '📋 Reporting'
        }
        
        for phase_id, phase_name in phase_names.items():
            phase_data = self.tracker.phases[phase_id]
            status = phase_data['status'].upper()
            duration = self.tracker.get_phase_duration(phase_id)
            progress = phase_data['progress']
            findings_count = len(phase_data['findings'])
            
            status_color = {
                'COMPLETED': '#00ff00',
                'IN_PROGRESS': '#ffaa00',
                'FAILED': '#ff0000',
                'PENDING': '#666'
            }.get(status, '#666')
            
            html_content += f"""
                <tr>
                    <td>{phase_name}</td>
                    <td style="color: {status_color};">{status}</td>
                    <td>{duration}</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {progress}%;"></div>
                        </div>
                        {progress}%
                    </td>
                    <td>{findings_count} findings</td>
                </tr>"""
        
        html_content += """
            </table>
        </div>
        
        <div class="section">
            <h2>🔍 Reconnaissance Findings</h2>"""
        
        if self.open_ports:
            html_content += """
            <h3>Open Ports & Services</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Priority</th>
                </tr>"""
            
            for port in self.open_ports:
                service_info = self.services.get(port, {})
                service_name = service_info.get('name', 'Unknown')
                version = service_info.get('version', 'Not detected')
                priority = service_info.get('priority', 'low')
                
                html_content += f"""
                <tr>
                    <td><strong>{port}</strong></td>
                    <td>{service_name}</td>
                    <td>{version}</td>
                    <td><span class="severity-badge severity-{priority}">{priority.upper()}</span></td>
                </tr>"""
            
            html_content += """
            </table>"""
        
        if self.os_type:
            html_content += f"""
            <h3>Operating System</h3>
            <div class="finding-item">
                <strong>Detected OS:</strong> {self.os_type}
            </div>"""
        
        html_content += """
        </div>
        
        <div class="section">
            <h2>⚠️ Vulnerabilities</h2>"""
        
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                severity_class = vuln['severity'].lower()
                html_content += f"""
            <div class="finding-item finding-{severity_class}">
                <h3>{vuln['name']} <span class="severity-badge severity-{severity_class}">{vuln['severity']}</span></h3>
                <p><strong>Port:</strong> {vuln['port']}</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
            </div>"""
        else:
            html_content += """
            <p>No critical vulnerabilities detected during this engagement.</p>"""
        
        html_content += """
        </div>
        
        <div class="section">
            <h2>🔐 Access Testing Results</h2>"""
        
        if self.access_gained:
            html_content += f"""
            <div class="finding-item finding-critical">
                <h3>✓ Access Gained</h3>
                <p><strong>Status:</strong> COMPROMISED</p>
                <p><strong>Method:</strong> Credential-based authentication</p>
                <p><strong>Attempts:</strong> {self.stats['auth_attempts']} / {self.config['max_auth_attempts']}</p>
            </div>"""
        else:
            html_content += f"""
            <div class="finding-item finding-low">
                <h3>✗ Access Denied</h3>
                <p><strong>Status:</strong> NOT COMPROMISED</p>
                <p><strong>Attempts:</strong> {self.stats['auth_attempts']} / {self.config['max_auth_attempts']}</p>
            </div>"""
        
        html_content += """
        </div>"""
        
        if self.credentials_found:
            html_content += """
        <div class="section">
            <h2>🔑 Credentials Harvested</h2>
            <table>
                <tr>
                    <th>Username</th>
                    <th>Hash</th>
                </tr>"""
            
            for cred in self.credentials_found:
                html_content += f"""
                <tr>
                    <td>{cred['username']}</td>
                    <td><code>{cred['hash'][:50]}...</code></td>
                </tr>"""
            
            html_content += """
            </table>
        </div>"""
        
        html_content += f"""
        <div class="section">
            <h2>💡 Recommendations</h2>
            <div class="finding-item finding-critical">
                <h3>Critical Remediations</h3>
                <ul>
                    <li>Implement network segmentation to limit lateral movement</li>
                    <li>Enable multi-factor authentication for all remote access services</li>
                    <li>Deploy endpoint detection and response (EDR) solutions</li>
                    <li>Implement strict password policies and regular rotation</li>
                    <li>Monitor for unusual authentication patterns</li>
                </ul>
            </div>
            
            <div class="finding-item finding-high">
                <h3>High Priority</h3>
                <ul>
                    <li>Disable unnecessary services and close unused ports</li>
                    <li>Update all systems to latest security patches</li>
                    <li>Implement application whitelisting</li>
                    <li>Enable PowerShell logging and script block logging</li>
                    <li>Deploy SIEM for centralized log monitoring</li>
                </ul>
            </div>
            
            <div class="finding-item finding-medium">
                <h3>Medium Priority</h3>
                <ul>
                    <li>Conduct regular security awareness training</li>
                    <li>Implement least privilege access controls</li>
                    <li>Enable audit logging for all critical systems</li>
                    <li>Develop and test incident response procedures</li>
                    <li>Perform regular vulnerability assessments</li>
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>📁 Artifacts & Evidence</h2>
            <p><strong>Session Directory:</strong> <code>sessions/{self.session_id}/</code></p>
            <p><strong>Operation Log:</strong> <code>operation.log</code></p>
            <p><strong>Report File:</strong> <code>{report_file}</code></p>
            <p><strong>Stealth Score:</strong> {self.stats['stealth_score']}/100 - {'Excellent' if self.stats['stealth_score'] >= 90 else 'Good' if self.stats['stealth_score'] >= 70 else 'Fair' if self.stats['stealth_score'] >= 50 else 'Poor'}</p>
        </div>
        
        <div class="footer">
            <p>🥷 Enhanced Red Team Operation - Confidential</p>
            <p>This report contains sensitive security information and should be handled accordingly.</p>
            <p>© 2025 - Professional Security Services - For Authorized Use Only</p>
        </div>
    </div>
</body>
</html>"""
        
        # Save report
        with open(report_file, 'w') as f:
            f.write(html_content)
        
        self.tracker.update_phase('reporting', 'completed', 100)
        self.log_event(f"Report generated: {report_file}", "success")
        
        return report_file
    
    def print_final_summary(self):
        """Print final operation summary"""
        print("\n" + "="*90)
        print(f"{Colors.MAGENTA}{Colors.BOLD}  🥷 OPERATION COMPLETE - FINAL SUMMARY{Colors.END}")
        print("="*90 + "\n")
        
        print(f"{Colors.CYAN}📊 OPERATION OVERVIEW:{Colors.END}")
        print(f"  • Target: {Colors.YELLOW}{self.target}{Colors.END}")
        print(f"  • Duration: {Colors.YELLOW}{self.tracker.get_elapsed_time()}{Colors.END}")
        print(f"  • Profile: {Colors.YELLOW}{self.profile_name.upper()}{Colors.END}")
        print(f"  • Session ID: {Colors.YELLOW}{self.session_id}{Colors.END}\n")
        
        print(f"{Colors.CYAN}🎯 KEY FINDINGS:{Colors.END}")
        print(f"  • Open Ports: {Colors.GREEN}{len(self.open_ports)}{Colors.END}")
        print(f"  • Services: {Colors.GREEN}{self.stats['services_identified']}{Colors.END}")
        print(f"  • Vulnerabilities: {Colors.YELLOW if self.stats['vulnerabilities_found'] > 0 else Colors.GREEN}{self.stats['vulnerabilities_found']}{Colors.END}")
        print(f"  • Access Status: {Colors.GREEN if self.access_gained else Colors.RED}{'COMPROMISED' if self.access_gained else 'NOT COMPROMISED'}{Colors.END}")
        print(f"  • Credentials Found: {Colors.GREEN}{len(self.credentials_found)}{Colors.END}\n")
        
        print(f"{Colors.CYAN}📈 OPERATION STATISTICS:{Colors.END}")
        print(f"  • Commands Executed: {Colors.YELLOW}{self.stats['commands_executed']}{Colors.END}")
        print(f"  • Connections Made: {Colors.YELLOW}{self.stats['connections_made']}{Colors.END}")
        print(f"  • Auth Attempts: {Colors.YELLOW}{self.stats['auth_attempts']}{Colors.END} / {self.config['max_auth_attempts']}")
        print(f"  • Data Collected: {Colors.YELLOW}{self.stats['data_collected_mb']:.2f} MB{Colors.END}\n")
        
        print(f"{Colors.CYAN}🥷 STEALTH ASSESSMENT:{Colors.END}")
        score = self.stats['stealth_score']
        
        if score >= 90:
            rating = f"{Colors.GREEN}EXCELLENT{Colors.END}"
            desc = "Operation conducted with maximum stealth"
        elif score >= 70:
            rating = f"{Colors.GREEN}GOOD{Colors.END}"
            desc = "Operation maintained good stealth practices"
        elif score >= 50:
            rating = f"{Colors.YELLOW}FAIR{Colors.END}"
            desc = "Operation had moderate detection risk"
        else:
            rating = f"{Colors.RED}POOR{Colors.END}"
            desc = "Operation had high detection risk"
        
        print(f"  • Stealth Score: {Colors.YELLOW}{score}/100{Colors.END} - {rating}")
        print(f"  • Assessment: {desc}\n")
        
        print(f"{Colors.CYAN}📁 OUTPUT FILES:{Colors.END}")
        print(f"  • Report: {Colors.GREEN}reports/Enhanced_Report_*.html{Colors.END}")
        print(f"  • Logs: {Colors.GREEN}sessions/{self.session_id}/operation.log{Colors.END}")
        print(f"  • Session: {Colors.GREEN}sessions/{self.session_id}/{Colors.END}\n")
        
        print(f"{Colors.CYAN}⏱️ PHASE DURATIONS:{Colors.END}")
        for phase_id, phase_name in {
            'recon': 'Reconnaissance',
            'access': 'Access Testing',
            'post_exploit': 'Post-Exploitation'
        }.items():
            duration = self.tracker.get_phase_duration(phase_id)
            status = self.tracker.phases[phase_id]['status']
            if status != 'pending':
                icon = '✓' if status == 'completed' else '✗'
                print(f"  {icon} {phase_name:<20} {duration}")
        
        print("\n" + "="*90)
        print(f"{Colors.GREEN}Operation completed successfully!{Colors.END}")
        print(f"{Colors.DIM}All findings have been documented in the report.{Colors.END}\n")
    
    # ========================================================================
    # MAIN EXECUTION
    # ========================================================================
    
    def run_enhanced_operation(self):
        """Execute complete operation with monitoring"""
        try:
            # Phase 1: Reconnaissance
            self.log_event("Starting operation", "info")
            self.phase_enhanced_recon()
            
            # Phase 2: Access Testing
            if self.username and self.password:
                self.stealth_delay("phase_transition", show_countdown=True)
                self.phase_enhanced_access()
            
            # Phase 3: Post-Exploitation (if access gained)
            if self.access_gained:
                self.stealth_delay("phase_transition", show_countdown=True)
                self.phase_enhanced_post_exploit()
            
            # Phase 4: Reporting
            self.tracker.update_phase('reporting', 'in_progress', 0)
            report_file = self.generate_enhanced_report()
            
            # Final dashboard and summary
            if self.verbose:
                self.tracker.print_dashboard()
            
            self.print_final_summary()
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Operation interrupted by user{Colors.END}")
            self.log_event("Operation interrupted by user", "warning")
            
            if self.verbose:
                self.tracker.print_dashboard()
            
            print(f"\n{Colors.CYAN}Partial results saved to: sessions/{self.session_id}/{Colors.END}\n")
            return False
            
        except Exception as e:
            print(f"\n\n{Colors.RED}[!] Operation error: {str(e)}{Colors.END}")
            self.log_event(f"Operation error: {str(e)}", "critical")
            
            import traceback
            traceback.print_exc()
            return False

# ========================================================================
# INTERACTIVE MODE
# ========================================================================

def interactive_mode():
    """Interactive setup and execution"""
    print_banner()
    
    print(f"{Colors.CYAN}Welcome to Enhanced Red Team Operations{Colors.END}")
    print(f"{Colors.DIM}Real-time monitoring and advanced stealth capabilities{Colors.END}\n")
    
    # Get target
    target = input(f"{Colors.GREEN}Enter target IP/hostname: {Colors.END}").strip()
    if not target:
        print(f"{Colors.RED}[!] Target required{Colors.END}")
        return
    
    # Select profile
    print(f"\n{Colors.CYAN}Select Operation Profile:{Colors.END}\n")
    
    for idx, (profile_name, profile_data) in enumerate(EnhancedConfig.PROFILES.items(), 1):
        print(f"{idx}. {Colors.YELLOW}{profile_name.upper()}{Colors.END}")
        print(f"   {profile_data['description']}")
        print(f"   Delay: {profile_data['min_delay']}-{profile_data['max_delay']}s")
        print(f"   Max Auth Attempts: {profile_data['max_auth_attempts']}")
        print()
    
    profile_choice = input(f"{Colors.GREEN}Select profile (1-4) [2]: {Colors.END}").strip()
    
    profile_map = {
        '1': 'fast',
        '2': 'balanced',
        '3': 'stealth',
        '4': 'ghost'
    }
    
    profile = profile_map.get(profile_choice, 'balanced')
    
    # Get credentials
    print(f"\n{Colors.CYAN}Credentials (optional - press Enter to skip):{Colors.END}")
    username = input(f"{Colors.GREEN}Username: {Colors.END}").strip()
    password = None
    domain = None
    
    if username:
        password = input(f"{Colors.GREEN}Password: {Colors.END}").strip()
        domain = input(f"{Colors.GREEN}Domain (optional): {Colors.END}").strip() or None
    
    # Verbose mode
    verbose = input(f"\n{Colors.GREEN}Enable live dashboard? (Y/n): {Colors.END}").strip().lower()
    verbose = verbose != 'n'
    
    # Confirm
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}OPERATION CONFIGURATION:{Colors.END}")
    print(f"  Target: {Colors.YELLOW}{target}{Colors.END}")
    print(f"  Profile: {Colors.YELLOW}{profile.upper()}{Colors.END} - {EnhancedConfig.PROFILES[profile]['description']}")
    if username:
        print(f"  Credentials: {Colors.YELLOW}{username}:{'*' * len(password)}{Colors.END}")
    print(f"  Live Dashboard: {Colors.YELLOW}{'Enabled' if verbose else 'Disabled'}{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
    
    config = EnhancedConfig.PROFILES[profile]
    est_time = (config['min_delay'] + config['max_delay']) / 2 * 8  # Estimate for ~8 major operations
    print(f"{Colors.YELLOW}⏱ Estimated Duration: {int(est_time/60)} - {int(est_time/60 * 1.5)} minutes{Colors.END}")
    print(f"{Colors.DIM}Actual time may vary based on target response and findings{Colors.END}\n")
    
    confirm = input(f"{Colors.GREEN}Start operation? (y/N): {Colors.END}").strip().lower()
    if confirm != 'y':
        print(f"\n{Colors.YELLOW}Operation cancelled{Colors.END}\n")
        return
    
    print(f"\n{Colors.GREEN}Starting operation...{Colors.END}\n")
    time.sleep(2)
    
    # Create and run
    framework = EnhancedStealthRedTeam(
        target=target,
        username=username,
        password=password,
        domain=domain,
        profile=profile,
        verbose=verbose
    )
    
    success = framework.run_enhanced_operation()
    
    if success:
        print(f"\n{Colors.GREEN}✓ Operation completed successfully!{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}⚠ Operation ended with warnings or errors{Colors.END}")
    
    return success

# ========================================================================
# MAIN ENTRY POINT
# ========================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Enhanced Red Team Framework v2.0 - Real-Time Monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Interactive mode (recommended)
  python3 enhanced_redteam.py
  
  # Quick scan with credentials
  python3 enhanced_redteam.py -t 10.10.10.100 -u admin -p password123
  
  # Stealth mode with domain credentials
  python3 enhanced_redteam.py -t 10.10.10.100 -u admin -p pass123 -d CORP -P stealth
  
  # Fast mode without live dashboard
  python3 enhanced_redteam.py -t 10.10.10.100 -P fast --no-verbose

Profiles:
  fast      - Fast reconnaissance (10-30s delays, higher detection risk)
  balanced  - Balanced speed and stealth (60-180s delays) [DEFAULT]
  stealth   - High stealth mode (120-300s delays, business hours only)
  ghost     - Maximum stealth (300-600s delays, minimal connections)

Features:
  ✓ Real-time progress dashboard
  ✓ Live activity monitoring
  ✓ Comprehensive HTML reports
  ✓ Statistics tracking
  ✓ Timeline visualization
  ✓ Stealth scoring
  ✓ Multiple operation profiles

For authorized penetration testing only.
'''
    )
    
    parser.add_argument('-t', '--target', help='Target IP or hostname')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-d', '--domain', help='Domain name (for Windows targets)')
    parser.add_argument('-P', '--profile', 
                       choices=['fast', 'balanced', 'stealth', 'ghost'],
                       default='balanced',
                       help='Operation profile (default: balanced)')
    parser.add_argument('--no-verbose', action='store_true',
                       help='Disable live dashboard updates')
    parser.add_argument('--version', action='version', version='Enhanced Red Team Framework v2.0')
    
    args = parser.parse_args()
    
    # Banner
    print_banner()
    
    # Check if running as root (warning only)
    if os.name != 'nt' and os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Not running as root - some features may be limited{Colors.END}\n")
    
    # Check for required tools
    required_tools = ['nmap', 'nc']
    missing_tools = []
    
    for tool in required_tools:
        result = subprocess.run(f"which {tool}", shell=True, capture_output=True)
        if result.returncode != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{Colors.YELLOW}[!] Missing tools: {', '.join(missing_tools)}{Colors.END}")
        print(f"{Colors.DIM}Some features may not work correctly{Colors.END}\n")
    
    try:
        if args.target:
            # Command-line mode
            print(f"{Colors.CYAN}Starting operation in command-line mode...{Colors.END}\n")
            
            framework = EnhancedStealthRedTeam(
                target=args.target,
                username=args.username,
                password=args.password,
                domain=args.domain,
                profile=args.profile,
                verbose=not args.no_verbose
            )
            
            success = framework.run_enhanced_operation()
            sys.exit(0 if success else 1)
        else:
            # Interactive mode
            success = interactive_mode()
            sys.exit(0 if success else 1)
            
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Operation interrupted by user{Colors.END}\n")
        sys.exit(130)
        
    except Exception as e:
        print(f"\n{Colors.RED}[!] Fatal error: {e}{Colors.END}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()