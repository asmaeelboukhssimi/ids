#!/usr/bin/env python3
"""
AI-powered IDS Traffic Analysis Script
Analyzes network traffic from Elasticsearch and generates Suricata rules for APT detection
"""

import json
import requests
import sys
import subprocess
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
import re

class ElasticsearchAnalyzer:
    def __init__(self, es_host="localhost", es_port=9200):
        self.es_host = es_host
        self.es_port = es_port
        self.base_url = f"http://{es_host}:{es_port}"
        
    def query_recent_traffic(self, hours=24, size=1000):
        """Query recent traffic from Elasticsearch"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        query = {
            "size": size,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ]
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/suricata-*/_search",
                headers={"Content-Type": "application/json"},
                json=query,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error querying Elasticsearch: {e}")
            return None

    def extract_suspicious_patterns(self, traffic_data):
        """Extract suspicious patterns from traffic data"""
        patterns = {
            'suspicious_ips': set(),
            'suspicious_domains': set(),
            'suspicious_user_agents': set(),
            'port_scans': {},
            'data_exfiltration': [],
            'command_control': []
        }
        
        if not traffic_data or 'hits' not in traffic_data:
            return patterns
            
        for hit in traffic_data['hits']['hits']:
            source = hit.get('_source', {})
            
            # Extract basic fields
            src_ip = source.get('src_ip') or source.get('source', {}).get('ip')
            dest_ip = source.get('dest_ip') or source.get('destination', {}).get('ip')
            dest_port = source.get('dest_port') or source.get('destination', {}).get('port')
            
            # APT Detection patterns
            self._detect_apt_patterns(source, patterns)
            
            # Port scan detection
            if src_ip and dest_port:
                if src_ip not in patterns['port_scans']:
                    patterns['port_scans'][src_ip] = set()
                patterns['port_scans'][src_ip].add(dest_port)
        
        # Filter port scans (>10 different ports from same IP)
        patterns['port_scans'] = {
            ip: ports for ip, ports in patterns['port_scans'].items() 
            if len(ports) > 10
        }
        
        return patterns

    def _detect_apt_patterns(self, source, patterns):
        """Detect APT-specific patterns in network traffic"""
        
        # Check for suspicious domains (DGA, recently registered, etc.)
        dns_query = source.get('dns', {}).get('query')
        if dns_query:
            if self._is_suspicious_domain(dns_query):
                patterns['suspicious_domains'].add(dns_query)
        
        # Check HTTP traffic for APT indicators
        http = source.get('http', {})
        if http:
            user_agent = http.get('user_agent', '')
            hostname = http.get('hostname', '')
            uri = http.get('uri', '')
            
            # Suspicious User-Agents
            if self._is_suspicious_user_agent(user_agent):
                patterns['suspicious_user_agents'].add(user_agent)
            
            # C2 Communication patterns
            if self._is_c2_communication(hostname, uri, http):
                patterns['command_control'].append({
                    'hostname': hostname,
                    'uri': uri,
                    'method': http.get('method'),
                    'timestamp': source.get('@timestamp')
                })
            
            # Data exfiltration patterns
            if self._is_data_exfiltration(http):
                patterns['data_exfiltration'].append({
                    'hostname': hostname,
                    'uri': uri,
                    'length': http.get('length', 0),
                    'timestamp': source.get('@timestamp')
                })

    def _is_suspicious_domain(self, domain):
        """Check if domain shows DGA or other suspicious characteristics"""
        if not domain:
            return False
            
        # DGA patterns: long domains with random-looking strings
        if len(domain) > 20 and re.search(r'[a-z]{8,}\.', domain):
            return True
            
        # Recently registered domains (simplified check)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
            
        return False

    def _is_suspicious_user_agent(self, user_agent):
        """Check for suspicious User-Agent strings"""
        if not user_agent:
            return False
            
        suspicious_patterns = [
            r'python-requests',
            r'curl/',
            r'wget/',
            r'powershell',
            r'^[A-Za-z]{1,3}$',  # Very short UA
            r'bot|crawler|spider',  # Generic bots
        ]
        
        return any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in suspicious_patterns)

    def _is_c2_communication(self, hostname, uri, http):
        """Detect potential C2 communication patterns"""
        if not hostname:
            return False
            
        # Check for beaconing patterns
        method = http.get('method', '').upper()
        if method == 'POST' and uri:
            # Look for base64 or hex encoded data in URI
            if re.search(r'[A-Za-z0-9+/=]{20,}|[0-9A-Fa-f]{20,}', uri):
                return True
                
        # Suspicious paths
        suspicious_paths = ['/api/v1/', '/admin/', '/config/', '/upload/']
        if any(path in uri for path in suspicious_paths):
            return True
            
        return False

    def _is_data_exfiltration(self, http):
        """Detect potential data exfiltration"""
        method = http.get('method', '').upper()
        length = http.get('length', 0)
        
        # Large POST requests
        if method == 'POST' and length > 100000:  # >100KB
            return True
            
        return False

class AIRuleGenerator:
    def __init__(self):
        self.rule_counter = 3000000  # Start from high SID to avoid conflicts
        
    def generate_suricata_rules(self, patterns):
        """Generate Suricata rules based on detected patterns"""
        rules = []
        rules.append("# AI-Generated Suricata Rules for APT Detection")
        rules.append(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        rules.append("")
        
        # Generate rules for suspicious IPs
        for ip in patterns.get('suspicious_ips', []):
            rule = self._create_ip_rule(ip)
            if rule:
                rules.append(rule)
        
        # Generate rules for suspicious domains
        for domain in patterns.get('suspicious_domains', []):
            rule = self._create_domain_rule(domain)
            if rule:
                rules.append(rule)
                
        # Generate rules for suspicious User-Agents
        for ua in patterns.get('suspicious_user_agents', []):
            rule = self._create_user_agent_rule(ua)
            if rule:
                rules.append(rule)
                
        # Generate rules for port scans
        for ip, ports in patterns.get('port_scans', {}).items():
            rule = self._create_port_scan_rule(ip, len(ports))
            if rule:
                rules.append(rule)
                
        # Generate rules for C2 communication
        for c2 in patterns.get('command_control', []):
            rule = self._create_c2_rule(c2)
            if rule:
                rules.append(rule)
                
        return "\n".join(rules)

    def _create_ip_rule(self, ip):
        """Create rule for suspicious IP"""
        sid = self._get_next_sid()
        return f'alert ip any any -> {ip} any (msg:"Suspicious IP Communication - {ip}"; sid:{sid}; rev:1;)'

    def _create_domain_rule(self, domain):
        """Create rule for suspicious domain"""
        sid = self._get_next_sid()
        return f'alert dns any any -> any any (msg:"Suspicious Domain Query - {domain}"; dns_query; content:"{domain}"; sid:{sid}; rev:1;)'

    def _create_user_agent_rule(self, user_agent):
        """Create rule for suspicious User-Agent"""
        sid = self._get_next_sid()
        # Escape special characters
        escaped_ua = user_agent.replace('"', '\\"').replace('\\', '\\\\')
        return f'alert http any any -> any any (msg:"Suspicious User-Agent - APT Tool"; http_user_agent; content:"{escaped_ua}"; sid:{sid}; rev:1;)'

    def _create_port_scan_rule(self, ip):
        """Create rule for port scanning"""
        sid = self._get_next_sid()
        return f'alert tcp {ip} any -> any any (msg:"Port Scan Detected from {ip}"; threshold:type both, track by_src, count 10, seconds 60; sid:{sid}; rev:1;)'

    def _create_c2_rule(self, c2_data):
        """Create rule for C2 communication"""
        sid = self._get_next_sid()
        hostname = c2_data.get('hostname', '')
        uri = c2_data.get('uri', '')
        
        if hostname:
            return f'alert http any any -> any any (msg:"Potential C2 Communication - {hostname}"; http_host; content:"{hostname}"; sid:{sid}; rev:1;)'
        return None

    def _get_next_sid(self):
        """Get next available SID"""
        self.rule_counter += 1
        return self.rule_counter

def use_ai_analysis(patterns):
    """Use Ollama AI to enhance pattern analysis"""
    try:
        # Check if ollama is available
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=10)
        if 'llama3.2:3b' not in result.stdout:
            print("AI model not available, using rule-based analysis only")
            return patterns
            
        # Prepare data for AI analysis
        analysis_prompt = f"""
        Analyze the following network security patterns and identify additional APT indicators:
        
        Suspicious Domains: {list(patterns.get('suspicious_domains', []))}
        Suspicious User Agents: {list(patterns.get('suspicious_user_agents', []))}
        Port Scans: {len(patterns.get('port_scans', {}))} detected
        C2 Communications: {len(patterns.get('command_control', []))} detected
        
        Based on these patterns, suggest additional indicators of compromise (IoCs) and 
        potential APT group associations. Focus on:
        1. Domain generation algorithms
        2. Infrastructure patterns
        3. TTPs (Tactics, Techniques, Procedures)
        
        Respond with a JSON structure containing enhanced patterns.
        """
        
        # Call Ollama API
        response = subprocess.run([
            'ollama', 'run', 'llama3.2:3b', analysis_prompt
        ], capture_output=True, text=True, timeout=60)
        
        if response.returncode == 0:
            print("AI analysis completed successfully")
            # In a real implementation, you would parse the AI response
            # and enhance the patterns accordingly
            
    except Exception as e:
        print(f"AI analysis failed, continuing with rule-based analysis: {e}")
    
    return patterns

def main():
    print("Starting AI-powered IDS Traffic Analysis...")
    
    # Initialize components
    analyzer = ElasticsearchAnalyzer()
    rule_generator = AIRuleGenerator()
    
    # Query recent traffic
    print("Querying Elasticsearch for recent traffic...")
    traffic_data = analyzer.query_recent_traffic(hours=24)
    
    if not traffic_data:
        print("No traffic data found or Elasticsearch unavailable")
        sys.exit(1)
    
    print(f"Analyzed {traffic_data['hits']['total']['value']} traffic events")
    
    # Extract suspicious patterns
    print("Extracting suspicious patterns...")
    patterns = analyzer.extract_suspicious_patterns(traffic_data)
    
    # Use AI to enhance analysis
    print("Enhancing analysis with AI...")
    enhanced_patterns = use_ai_analysis(patterns)
    
    # Generate rules
    print("Generating Suricata rules...")
    rules = rule_generator.generate_suricata_rules(enhanced_patterns)
    
    # Save rules to file
    output_file = f"/home/asmae/ids/generated-rules-{datetime.now().strftime('%Y%m%d-%H%M%S')}.rules"
    with open(output_file, 'w') as f:
        f.write(rules)
    
    print(f"\nAnalysis Summary:")
    print(f"- Suspicious domains: {len(enhanced_patterns.get('suspicious_domains', []))}")
    print(f"- Suspicious user agents: {len(enhanced_patterns.get('suspicious_user_agents', []))}")
    print(f"- Port scans detected: {len(enhanced_patterns.get('port_scans', {}))}")
    print(f"- C2 communications: {len(enhanced_patterns.get('command_control', []))}")
    print(f"- Data exfiltration attempts: {len(enhanced_patterns.get('data_exfiltration', []))}")
    print(f"\nGenerated rules saved to: {output_file}")
    print("\nTo apply these rules:")
    print(f"1. Review the generated rules in {output_file}")
    print("2. Copy relevant rules to /home/asmae/ids/custom.rules")
    print("3. Restart Suricata: sudo systemctl restart suricata")

if __name__ == "__main__":
    main()