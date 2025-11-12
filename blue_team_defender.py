#!/usr/bin/env python3
"""
BLUE TEAM DEFENDER - ACTIVE DEFENSE SCRIPT
Complements Red Team training by implementing detection and hardening

Author: Blue Team Operations
License: Authorized Use Only
"""

import os
import sys
import json
import time
import logging
import subprocess
import psutil
from datetime import datetime
from pathlib import Path

class BlueTeamDefender:
    def __init__(self, defense_level=3):
        self.defense_level = defense_level
        self.setup_logging()
        self.detected_threats = []
        self.defense_actions = []
        
    def setup_logging(self):
        """Setup defensive logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('blue_team_defense.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('BlueTeamDefender')

    # ========================================================================
    # DETECTION METHODS
    # ========================================================================

    def detect_wmi_persistence(self):
        """Detect WMI event subscription persistence"""
        self.logger.info("Scanning for WMI persistence...")
        
        try:
            # Check for suspicious WMI event filters
            cmd = "Get-WmiObject -Namespace root/subscription -Class __EventFilter | Select Name, Query"
            result = subprocess.run(['powershell', '-Command', cmd], capture_output=True, text=True)
            
            suspicious_patterns = [
                'Win32_PerfFormattedData_PerfOS_System',
                'SELECT * FROM __InstanceModificationEvent',
                'CommandLineEventConsumer'
            ]
            
            for line in result.stdout.split('\n'):
                if any(pattern in line for pattern in suspicious_patterns):
                    self.logger.warning(f"Suspicious WMI filter detected: {line}")
                    self.detected_threats.append({
                        'type': 'WMI Persistence',
                        'evidence': line.strip(),
                        'timestamp': datetime.now().isoformat()
                    })
                    return True
                    
        except Exception as e:
            self.logger.error(f"WMI detection failed: {e}")
            
        return False

    def monitor_powershell_activity(self):
        """Detect suspicious PowerShell behavior"""
        self.logger.info("Monitoring PowerShell activity...")
        
        suspicious_indicators = [
            '-WindowStyle Hidden',
            '-EncodedCommand',
            'IEX (New-Object Net.WebClient)',
            'AMSI bypass',
            'FromBase64String',
            'Invoke-Expression'
        ]
        
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if proc.info['name'] and 'powershell' in proc.info['name'].lower():
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    for indicator in suspicious_indicators:
                        if indicator in cmdline:
                            self.logger.warning(f"Suspicious PowerShell process: {cmdline}")
                            self.detected_threats.append({
                                'type': 'Suspicious PowerShell',
                                'process': cmdline,
                                'pid': proc.pid,
                                'timestamp': datetime.now().isoformat()
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def detect_credential_dumping(self):
        """Detect LSASS access and credential dumping attempts"""
        self.logger.info("Monitoring for credential dumping...")
        
        lsass_indicators = [
            'comsvcs.dll',
            'MiniDump',
            'lsass.exe',
            'procdump.exe'
        ]
        
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                for indicator in lsass_indicators:
                    if indicator.lower() in cmdline.lower():
                        self.logger.warning(f"Potential credential dumping: {cmdline}")
                        self.detected_threats.append({
                            'type': 'Credential Dumping',
                            'process': cmdline,
                            'pid': proc.pid,
                            'timestamp': datetime.now().isoformat()
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def analyze_network_connections(self):
        """Detect suspicious network patterns"""
        self.logger.info("Analyzing network connections...")
        
        suspicious_ports = [8080, 4444, 1337]  # Common C2 ports
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.raddr:
                if conn.raddr.port in suspicious_ports:
                    self.logger.warning(f"Suspicious connection to port {conn.raddr.port}")
                    self.detected_threats.append({
                        'type': 'Suspicious Network Connection',
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'timestamp': datetime.now().isoformat()
                    })

    # ========================================================================
    # HARDENING METHODS
    # ========================================================================

    def enable_powershell_logging(self):
        """Enable enhanced PowerShell logging"""
        self.logger.info("Enabling PowerShell logging...")
        
        logging_commands = [
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcript" -Name "EnableTranscript" -Value 1',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" -Name "EnableModuleLogging" -Value 1'
        ]
        
        for cmd in logging_commands:
            try:
                subprocess.run(['powershell', '-Command', cmd], capture_output=True)
                self.defense_actions.append(f"Enabled: {cmd}")
            except Exception as e:
                self.logger.error(f"Failed to enable PowerShell logging: {e}")

    def configure_wmi_auditing(self):
        """Enable WMI auditing"""
        self.logger.info("Configuring WMI auditing...")
        
        try:
            # Enable WMI activity auditing
            cmd = 'wevtutil set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true'
            subprocess.run(cmd, shell=True, capture_output=True)
            self.defense_actions.append("Enabled WMI activity logging")
        except Exception as e:
            self.logger.error(f"Failed to configure WMI auditing: {e}")

    def harden_lsass_protection(self):
        """Implement LSASS protection measures"""
        self.logger.info("Hardening LSASS protection...")
        
        try:
            # Enable LSA protection
            cmd = 'REG ADD "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f'
            subprocess.run(cmd, shell=True, capture_output=True)
            self.defense_actions.append("Enabled LSA protection")
        except Exception as e:
            self.logger.error(f"Failed to harden LSASS: {e}")

    def configure_account_policies(self):
        """Implement account security policies"""
        self.logger.info("Configuring account policies...")
        
        policies = [
            'net accounts /lockoutthreshold:5',
            'net accounts /lockoutduration:30',
            'net accounts /lockoutwindow:30'
        ]
        
        for policy in policies:
            try:
                subprocess.run(policy, shell=True, capture_output=True)
                self.defense_actions.append(f"Applied: {policy}")
            except Exception as e:
                self.logger.error(f"Failed to apply account policy: {e}")

    # ========================================================================
    # ACTIVE DEFENSE METHODS
    # ========================================================================

    def remove_wmi_persistence(self):
        """Remove detected WMI persistence"""
        self.logger.info("Removing WMI persistence...")
        
        try:
            cleanup_commands = [
                'Get-WmiObject -Namespace root/subscription -Class __EventFilter | Remove-WmiObject',
                'Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Remove-WmiObject',
                'Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Remove-WmiObject'
            ]
            
            for cmd in cleanup_commands:
                subprocess.run(['powershell', '-Command', cmd], capture_output=True)
                self.defense_actions.append(f"Executed: {cmd}")
                
        except Exception as e:
            self.logger.error(f"Failed to remove WMI persistence: {e}")

    def kill_suspicious_processes(self):
        """Terminate detected malicious processes"""
        self.logger.info("Terminating suspicious processes...")
        
        for threat in self.detected_threats:
            if 'pid' in threat:
                try:
                    proc = psutil.Process(threat['pid'])
                    proc.terminate()
                    self.logger.info(f"Terminated process PID {threat['pid']}")
                    self.defense_actions.append(f"Terminated PID {threat['pid']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

    # ========================================================================
    # MAIN DEFENSE OPERATIONS
    # ========================================================================

    def run_detection_phase(self):
        """Execute all detection methods"""
        self.logger.info("=== STARTING DETECTION PHASE ===")
        
        detections = [
            self.detect_wmi_persistence(),
            self.monitor_powershell_activity(),
            self.detect_credential_dumping(),
            self.analyze_network_connections()
        ]
        
        threats_found = any(detections)
        
        if threats_found:
            self.logger.warning(f"Detected {len(self.detected_threats)} potential threats")
            # Save detection results
            with open('threat_detections.json', 'w') as f:
                json.dump(self.detected_threats, f, indent=2)
        else:
            self.logger.info("No immediate threats detected")
            
        return threats_found

    def run_hardening_phase(self):
        """Execute all hardening methods"""
        self.logger.info("=== STARTING HARDENING PHASE ===")
        
        hardening_actions = [
            self.enable_powershell_logging(),
            self.configure_wmi_auditing(),
            self.harden_lsass_protection(),
            self.configure_account_policies()
        ]
        
        self.logger.info(f"Applied {len(self.defense_actions)} defense measures")
        
        # Save defense actions
        with open('defense_actions.json', 'w') as f:
            json.dump(self.defense_actions, f, indent=2)

    def run_active_defense_phase(self):
        """Execute active defense measures"""
        if self.detected_threats:
            self.logger.info("=== STARTING ACTIVE DEFENSE PHASE ===")
            
            self.remove_wmi_persistence()
            self.kill_suspicious_processes()
            
            self.logger.info("Active defense measures completed")

    def generate_defense_report(self):
        """Generate comprehensive defense report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'defense_level': self.defense_level,
            'threats_detected': self.detected_threats,
            'defense_actions': self.defense_actions,
            'summary': {
                'total_threats': len(self.detected_threats),
                'defense_measures': len(self.defense_actions),
                'status': 'SECURED' if not self.detected_threats else 'INVESTIGATION_NEEDED'
            }
        }
        
        with open('blue_team_defense_report.json', 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.info("Defense report generated: blue_team_defense_report.json")
        return report

    def run_full_defense_operation(self):
        """Execute complete defense operation"""
        self.logger.info("🚀 INITIATING BLUE TEAM DEFENSE OPERATION")
        
        # Phase 1: Detection
        threats_found = self.run_detection_phase()
        
        # Phase 2: Hardening
        self.run_hardening_phase()
        
        # Phase 3: Active Defense (if threats detected)
        if threats_found:
            self.run_active_defense_phase()
        
        # Phase 4: Reporting
        report = self.generate_defense_report()
        
        self.logger.info("🎯 BLUE TEAM DEFENSE OPERATION COMPLETE")
        return report

def main():
    """Main execution"""
    print("🔵 BLUE TEAM DEFENDER - ACTIVE DEFENSE SCRIPT")
    print("Complementary to Red Team training operations\n")
    
    try:
        defender = BlueTeamDefender(defense_level=3)
        report = defender.run_full_defense_operation()
        
        print(f"\n📊 DEFENSE OPERATION SUMMARY:")
        print(f"Threats Detected: {report['summary']['total_threats']}")
        print(f"Defense Measures: {report['summary']['defense_measures']}")
        print(f"Status: {report['summary']['status']}")
        print(f"\nDetailed reports saved to:")
        print("- blue_team_defense_report.json")
        print("- threat_detections.json")
        print("- defense_actions.json")
        print("- blue_team_defense.log")
        
    except Exception as e:
        print(f"❌ Defense operation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()