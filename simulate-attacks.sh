#!/bin/bash

echo "Attack Simulation Script for IDS Testing"
echo "========================================"

TARGET_IP="httpbin.org"
TARGET_PORT="80"

# Function to simulate HTTP requests
simulate_http_attack() {
    local attack_type="$1"
    local payload="$2"
    local description="$3"
    
    echo ""
    echo "Simulating: $description"
    echo "Payload: $payload"
    echo "----------------------------------------"
    
    # Use curl to send the attack payload
    curl -s -A "$payload" "http://$TARGET_IP:$TARGET_PORT/" > /dev/null 2>&1 || true
    
    # Also try as GET parameter
    curl -s "http://$TARGET_IP:$TARGET_PORT/?test=$payload" > /dev/null 2>&1 || true
    
    # Try as POST data
    curl -s -X POST -d "data=$payload" "http://$TARGET_IP:$TARGET_PORT/" > /dev/null 2>&1 || true
    
    echo "✓ Attack simulation sent"
    sleep 2
}

echo ""
echo "Starting attack simulations against $TARGET_IP:$TARGET_PORT"
echo "Make sure your target web server is running or the payloads will still be detected by Suricata"
echo ""

# SQLMap attacks
echo "=== SQLMap Attacks ==="
simulate_http_attack "sqlmap" "sqlmap/1.0-dev" "SQLMap User-Agent Detection"
simulate_http_attack "sqlmap" "Mozilla/5.0 sqlmap/1.2.3" "SQLMap in User-Agent String"

# SQL Injection attacks  
echo ""
echo "=== SQL Injection Attacks ==="
simulate_http_attack "sqli" "' OR '1'='1" "Basic SQL Injection"
simulate_http_attack "sqli" "1 UNION SELECT user(),version(),database()" "UNION SELECT Injection"
simulate_http_attack "sqli" "1; DROP TABLE users;" "DROP TABLE Injection"
simulate_http_attack "sqli" "1 OR 1=1" "OR 1=1 Injection"
simulate_http_attack "sqli" "admin' AND (SELECT * FROM information_schema.tables)" "Information Schema Query"
simulate_http_attack "sqli" "1 AND version()>0" "Version Function Call"

# XSS attacks
echo ""
echo "=== XSS Attacks ==="
simulate_http_attack "xss" "<script>alert('XSS')</script>" "Basic Script Tag XSS"
simulate_http_attack "xss" "javascript:alert('XSS')" "JavaScript Protocol XSS"
simulate_http_attack "xss" "<img src=x onerror=alert('XSS')>" "Image onerror XSS"
simulate_http_attack "xss" "<body onload=alert('XSS')>" "Body onload XSS"
simulate_http_attack "xss" "<script>document.cookie='stolen'</script>" "Cookie Stealing XSS"
simulate_http_attack "xss" "<script>eval('alert(1)')</script>" "Eval Function XSS"

# Nikto attacks
echo ""
echo "=== Nikto Scanner Simulation ==="
simulate_http_attack "nikto" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)" "Nikto Default User-Agent"
simulate_http_attack "nikto" "Mozilla/5.00 (Nikto)" "Nikto Short User-Agent"

# Directory traversal
echo ""
echo "=== Directory Traversal ==="
simulate_http_attack "traversal" "../../../etc/passwd" "Directory Traversal"
simulate_http_attack "traversal" "..\\..\\..\\windows\\system32\\config\\sam" "Windows Directory Traversal"

# Command injection
echo ""
echo "=== Command Injection ==="
simulate_http_attack "cmdi" "; /bin/sh -c 'id'" "Unix Command Injection"
simulate_http_attack "cmdi" "| cmd.exe /c dir" "Windows Command Injection"

echo ""
echo "Attack simulation completed!"
echo ""
echo "Check the following for detected alerts:"
echo "- Suricata fast.log: tail -f /var/log/suricata/fast.log"
echo "- Suricata eve.json: tail -f /var/log/suricata/eve.json"
echo "- Kibana dashboard: http://localhost:5601"
echo ""
echo "You can also run specific attack types:"
echo "./simulate-attacks.sh --help for options"