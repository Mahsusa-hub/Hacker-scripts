#!/usr/bin/env python3
"""
🏢 Active Directory Reconnaissance Tool
For authorized penetration testing of Windows AD environments
Author: Professional Red Teamer
"""

import subprocess
import json
import os
import sys
from datetime import datetime

class ADRecon:
    def __init__(self, output_dir="ad_recon_results"):
        self.output_dir = output_dir
        self.results = {}
        os.makedirs(output_dir, exist_ok=True)
    
    def run_powershell(self, cmd):
        """Execute PowerShell command and return output"""
        try:
            result = subprocess.run([
                'powershell', '-Command', cmd
            ], capture_output=True, text=True, timeout=60)
            return result.stdout.strip() if result.returncode == 0 else result.stderr
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_domain_info(self):
        """Get basic domain information"""
        print("[+] Gathering domain information...")
        
        # Domain info
        domain_info = self.run_powershell('Get-ADDomain | Select-Object Name,Forest,DomainMode,DomainControllers | ConvertTo-Json')
        # Current user in domain
        user_info = self.run_powershell('$env:USERDOMAIN + "\\" + $env:USERNAME')
        # Domain computers
        computers = self.run_powershell('Get-ADComputer -Filter * | Select-Object Name,OperatingSystem | ConvertTo-Json')
        
        self.results['domain_info'] = {
            'domain': user_info,
            'domain_data': domain_info,
            'computers': computers
        }
        print("[✅] Domain information gathered")
    
    def enumerate_users(self):
        """Enumerate all domain users"""
        print("[+] Enumerating domain users...")
        
        # Get all users with interesting properties
        users = self.run_powershell('''
        Get-ADUser -Filter * -Properties * | 
        Select-Object SamAccountName,DisplayName,EmailAddress,MemberOf,LastLogonDate,Enabled,PasswordLastSet,PasswordNeverExpires |
        ConvertTo-Json
        ''')
        
        # Get privileged users
        privileged = self.run_powershell('''
        Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName,Name | ConvertTo-Json
        ''')
        
        self.results['users'] = {
            'all_users': users,
            'domain_admins': privileged
        }
        print("[✅] User enumeration complete")
    
    def enumerate_groups(self):
        """Enumerate domain groups"""
        print("[+] Enumerating domain groups...")
        
        # Get all groups
        groups = self.run_powershell('''
        Get-ADGroup -Filter * -Properties * | 
        Select-Object Name,GroupCategory,GroupScope,MemberCount |
        ConvertTo-Json
        ''')
        
        # Get sensitive groups
        sensitive_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Backup Operators', 'Account Operators']
        sensitive_info = {}
        
        for group in sensitive_groups:
            members = self.run_powershell(f'Get-ADGroupMember "{group}" | Select-Object SamAccountName,Name | ConvertTo-Json')
            sensitive_info[group] = members
        
        self.results['groups'] = {
            'all_groups': groups,
            'sensitive_groups': sensitive_info
        }
        print("[✅] Group enumeration complete")
    
    def check_kerberoastable(self):
        """Find Kerberoastable accounts"""
        print("[+] Checking for Kerberoastable accounts...")
        
        kerberoastable = self.run_powershell('''
        Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName,PasswordLastSet,LastLogonDate |
        Select-Object SamAccountName,ServicePrincipalName,PasswordLastSet,LastLogonDate |
        ConvertTo-Json
        ''')
        
        self.results['kerberoastable'] = kerberoastable
        print("[✅] Kerberoastable accounts identified")
    
    def check_asreproastable(self):
        """Find AS-REP Roastable accounts"""
        print("[+] Checking for AS-REP Roastable accounts...")
        
        asreproastable = self.run_powershell('''
        Get-ADUser -Filter "DoesNotRequirePreAuth -eq 'True'" -Properties DoesNotRequirePreAuth,PasswordLastSet |
        Select-Object SamAccountName,PasswordLastSet |
        ConvertTo-Json
        ''')
        
        self.results['asreproastable'] = asreproastable
        print("[✅] AS-REP Roastable accounts identified")
    
    def get_gpo_info(self):
        """Get Group Policy information"""
        print("[+] Gathering Group Policy information...")
        
        gpos = self.run_powershell('''
        Get-GPO -All | Select-Object DisplayName,Id,GPOStatus,ModificationTime |
        ConvertTo-Json
        ''')
        
        self.results['gpos'] = gpos
        print("[✅] GPO information gathered")
    
    def check_bloodhound_requirements(self):
        """Check what BloodHound would collect"""
        print("[+] Checking BloodHound data requirements...")
        
        # Count objects for BloodHound
        counts = self.run_powershell('''
        $counts = @{
            Users = (Get-ADUser -Filter *).Count
            Computers = (Get-ADComputer -Filter *).Count
            Groups = (Get-ADGroup -Filter *).Count
            OUs = (Get-ADOrganizationalUnit -Filter *).Count
            GPOs = (Get-GPO -All).Count
        }
        $counts | ConvertTo-Json
        ''')
        
        self.results['bloodhound_counts'] = counts
        print("[✅] BloodHound requirements checked")
    
    def generate_sharphound_command(self):
        """Generate SharpHound command for data collection"""
        print("[+] Generating SharpHound collection commands...")
        
        sharphound_commands = {
            'default_collection': 'SharpHound.exe -c All',
            'stealth_collection': 'SharpHound.exe -c All --Stealth',
            'dc_only_collection': 'SharpHound.exe -c All -d domain.com --LdapUsername user --LdapPassword pass',
            'loop_collection': 'SharpHound.exe -c All --Loop',
            'zip_collection': 'SharpHound.exe -c All --ZipFilename ad_data.zip'
        }
        
        self.results['sharphound_commands'] = sharphound_commands
        print("[✅] SharpHound commands generated")
    
    def save_results(self):
        """Save all results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON results
        json_file = os.path.join(self.output_dir, f"ad_recon_{timestamp}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        
        # Save readable report
        report_file = os.path.join(self.output_dir, f"ad_recon_report_{timestamp}.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("ACTIVE DIRECTORY RECONNAISSANCE REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            # Domain info
            f.write("DOMAIN INFORMATION:\n")
            f.write(f"Current User: {self.results.get('domain_info', {}).get('domain', 'N/A')}\n\n")
            
            # User counts
            if 'users' in self.results:
                f.write("USER SUMMARY:\n")
                try:
                    users_data = json.loads(self.results['users'].get('all_users', '[]'))
                    f.write(f"Total Users: {len(users_data) if isinstance(users_data, list) else 'N/A'}\n")
                except:
                    f.write("Total Users: N/A\n")
                
                try:
                    admins_data = json.loads(self.results['users'].get('domain_admins', '[]'))
                    f.write(f"Domain Admins: {len(admins_data) if isinstance(admins_data, list) else 'N/A'}\n")
                except:
                    f.write("Domain Admins: N/A\n")
            
            # Kerberoastable
            if 'kerberoastable' in self.results:
                try:
                    kerb_data = json.loads(self.results['kerberoastable'])
                    f.write(f"Kerberoastable Accounts: {len(kerb_data) if isinstance(kerb_data, list) else 'N/A'}\n")
                except:
                    f.write("Kerberoastable Accounts: N/A\n")
            
            f.write("\n" + "=" * 50 + "\n")
            f.write("Next Steps:\n")
            f.write("1. Run SharpHound to collect detailed AD data\n")
            f.write("2. Use data_exfil.py to transfer zip files to Kali\n")
            f.write("3. Analyze in BloodHound for attack paths\n")
        
        print(f"[💾] JSON results saved: {json_file}")
        print(f"[📄] Readable report saved: {report_file}")
    
    def run_full_recon(self):
        """Run complete AD reconnaissance"""
        print("""
        🏢 ACTIVE DIRECTORY RECONNAISSANCE
        ===================================
        """)
        
        checks = [
            self.get_domain_info,
            self.enumerate_users,
            self.enumerate_groups,
            self.check_kerberoastable,
            self.check_asreproastable,
            self.get_gpo_info,
            self.check_bloodhound_requirements,
            self.generate_sharphound_command
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"[-] Check failed: {e}")
                continue
        
        self.save_results()
        print(f"\n[✅] AD reconnaissance complete! Check {self.output_dir} for results.")

def main():
    # Check if we're on Windows
    if os.name != 'nt':
        print("[-] This script requires Windows and Active Directory PowerShell module")
        print("[-] Run this on a domain-joined Windows machine")
        sys.exit(1)
    
    # Check for AD module
    try:
        result = subprocess.run([
            'powershell', '-Command', 'Get-Module -ListAvailable ActiveDirectory'
        ], capture_output=True, text=True)
        
        if "ActiveDirectory" not in result.stdout:
            print("[-] Active Directory PowerShell module not found")
            print("[-] Install RSAT tools or run on domain controller")
            sys.exit(1)
    except:
        print("[-] Could not check for AD module")
    
    recon = ADRecon()
    recon.run_full_recon()

if __name__ == "__main__":
    main()