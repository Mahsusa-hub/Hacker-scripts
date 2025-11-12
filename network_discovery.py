#!/usr/bin/env python3

import subprocess
import threading
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
import time

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

class NetworkDiscovery:
    def __init__(self, network_range):
        self.network_range = network_range
        self.live_hosts = []
        self.lock = threading.Lock()
    
    def ping_host(self, host):
        """Ping a single host"""
        try:
            # Use ping command
            result = subprocess.run(['ping', '-c', '1', '-W', '1', str(host)], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                hostname = self.get_hostname(str(host))
                with self.lock:
                    self.live_hosts.append({
                        'ip': str(host),
                        'hostname': hostname,
                        'response_time': self.extract_ping_time(result.stdout)
                    })
                    print(f"{Colors.GREEN}[✓] {host} ({hostname}) - ALIVE{Colors.END}")
                return True
            return False
        except:
            return False
    
    def get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def extract_ping_time(self, ping_output):
        """Extract ping time from output"""
        try:
            lines = ping_output.split('\n')
            for line in lines:
                if 'time=' in line:
                    time_part = line.split('time=')[1].split(' ')[0]
                    return time_part
        except:
            return "N/A"
        return "N/A"
    
    def discover_network(self, max_threads=50):
        """Discover live hosts in network"""
        print(f"{Colors.CYAN}[*] Discovering hosts in network: {self.network_range}{Colors.END}")
        print(f"{Colors.BLUE}[*] Using {max_threads} threads{Colors.END}")
        
        try:
            network = ipaddress.ip_network(self.network_range, strict=False)
            hosts = list(network.hosts())
            
            print(f"{Colors.YELLOW}[*] Scanning {len(hosts)} hosts...{Colors.END}")
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                executor.map(self.ping_host, hosts)
            
            return self.live_hosts
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
            return []
    
    def port_scan_host(self, host, ports):
        """Quick port scan for a host"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    open_ports.append(port)
                
                sock.close()
            except:
                pass
        
        return open_ports
    
    def quick_service_scan(self):
        """Quick service scan on discovered hosts"""
        if not self.live_hosts:
            print(f"{Colors.RED}[!] No live hosts found{Colors.END}")
            return
        
        print(f"\n{Colors.YELLOW}[*] Quick service scan on live hosts{Colors.END}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5432, 3306]
        
        for host_info in self.live_hosts:
            host = host_info['ip']
            print(f"{Colors.BLUE}[*] Scanning {host}...{Colors.END}")
            
            open_ports = self.port_scan_host(host, common_ports)
            
            if open_ports:
                print(f"{Colors.GREEN}[✓] {host} - Open ports: {', '.join(map(str, open_ports))}{Colors.END}")
                host_info['open_ports'] = open_ports
            else:
                print(f"{Colors.YELLOW}[i] {host} - No common ports open{Colors.END}")
                host_info['open_ports'] = []
    
    def generate_targets_file(self, filename="potential_targets.txt"):
        """Generate a file with potential targets"""
        with open(filename, 'w') as f:
            f.write("NETWORK DISCOVERY RESULTS\n")
            f.write("=" * 50 + "\n")
            f.write(f"Network Range: {self.network_range}\n")
            f.write(f"Discovery Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Live Hosts: {len(self.live_hosts)}\n")
            f.write("=" * 50 + "\n\n")
            
            for host_info in self.live_hosts:
                f.write(f"IP: {host_info['ip']}\n")
                f.write(f"Hostname: {host_info['hostname']}\n")
                f.write(f"Response Time: {host_info['response_time']}\n")
                
                if 'open_ports' in host_info:
                    f.write(f"Open Ports: {', '.join(map(str, host_info['open_ports']))}\n")
                
                f.write("-" * 30 + "\n")
        
        print(f"{Colors.GREEN}[✓] Results saved to: {filename}{Colors.END}")
    
    def print_summary(self):
        """Print discovery summary"""
        print(f"\n{Colors.CYAN}DISCOVERY SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}={'=' * 40}{Colors.END}")
        print(f"Network Range: {self.network_range}")
        print(f"Live Hosts Found: {len(self.live_hosts)}")
        
        if self.live_hosts:
            print(f"\n{Colors.YELLOW}RECOMMENDED TARGETS:{Colors.END}")
            
            for host_info in self.live_hosts:
                if 'open_ports' in host_info and host_info['open_ports']:
                    ports_str = ', '.join(map(str, host_info['open_ports']))
                    print(f"{Colors.GREEN}[HIGH] {host_info['ip']} ({host_info['hostname']}) - Ports: {ports_str}{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}[LOW] {host_info['ip']} ({host_info['hostname']}) - No services detected{Colors.END}")

def get_local_network():
    """Auto-detect local network range"""
    try:
        # Get default gateway
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            default_gateway = result.stdout.split()[2]
            
            # Get local IP
            result = subprocess.run(['hostname', '-I'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                local_ip = result.stdout.strip().split()[0]
                
                # Assume /24 network
                network_parts = local_ip.split('.')
                network = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"
                
                return network
    except:
        pass
    
    return "192.168.1.0/24"  # Default fallback

def main():
    print(f"""
{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                            🌐 NETWORK DISCOVERY TOOL                             ║
║                                Find Your Targets                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
""")
    
    if len(sys.argv) > 1:
        network_range = sys.argv[1]
    else:
        # Auto-detect network
        network_range = get_local_network()
        print(f"{Colors.YELLOW}[*] Auto-detected network: {network_range}{Colors.END}")
        
        user_input = input(f"{Colors.BLUE}Press Enter to scan this network or type a different range: {Colors.END}")
        if user_input.strip():
            network_range = user_input.strip()
    
    discovery = NetworkDiscovery(network_range)
    
    # Discover hosts
    live_hosts = discovery.discover_network()
    
    if live_hosts:
        # Quick service scan
        discovery.quick_service_scan()
        
        # Generate results
        discovery.generate_targets_file()
        discovery.print_summary()
        
        # Suggest next steps
        print(f"\n{Colors.CYAN}NEXT STEPS:{Colors.END}")
        print(f"1. Choose a target from the list above")
        print(f"2. Run: python3 enhanced_recon.py <target_ip>")
        print(f"3. Review results in the generated output directory")
        
    else:
        print(f"{Colors.RED}[!] No live hosts found in network: {network_range}{Colors.END}")

if __name__ == "__main__":
    main()
