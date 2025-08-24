#!/bin/bash

echo "Starting AI-Powered IDS Services..."

# Check if configuration files are properly symlinked
echo "Verifying configuration symlinks..."
if [[ ! -L /etc/kibana/kibana.yml ]]; then
    echo "⚠️  Warning: kibana.yml not symlinked"
fi
if [[ ! -L /etc/logstash/conf.d/logstash.conf ]]; then
    echo "⚠️  Warning: logstash.conf not symlinked"
fi
if [[ ! -L /etc/suricata/suricata.yaml ]]; then
    echo "⚠️  Warning: suricata.yaml not symlinked"
fi
if [[ ! -L /etc/suricata/rules/custom.rules ]]; then
    echo "⚠️  Warning: custom.rules not symlinked"
fi

# Start Ollama AI service
echo "Starting Ollama AI service..."
if ! pgrep -f "ollama serve" > /dev/null; then
    ollama serve &
    sleep 5
    echo "✓ Ollama AI service started"
else
    echo "✓ Ollama AI service already running"
fi

# Create log directories
sudo mkdir -p /var/log/suricata
sudo chown -R suricata:suricata /var/log/suricata

# Start Elasticsearch
echo "Starting Elasticsearch..."
sudo systemctl start elasticsearch
sleep 10

# Check Elasticsearch status and health
if sudo systemctl is-active --quiet elasticsearch; then
    echo "✓ Elasticsearch is running"
    # Wait for Elasticsearch to be healthy
    echo "Waiting for Elasticsearch to be ready..."
    for i in {1..30}; do
        if curl -s -k https://localhost:9200/_cluster/health > /dev/null 2>&1; then
            echo "✓ Elasticsearch is healthy and accepting connections"
            break
        fi
        sleep 2
        if [ $i -eq 30 ]; then
            echo "⚠️  Warning: Elasticsearch may not be fully ready"
        fi
    done
else
    echo "✗ Elasticsearch failed to start"
    echo "Attempting to restart Elasticsearch..."
    sudo systemctl restart elasticsearch
    sleep 15
    if sudo systemctl is-active --quiet elasticsearch; then
        echo "✓ Elasticsearch restarted successfully"
    else
        echo "✗ Elasticsearch restart failed - check logs: sudo journalctl -u elasticsearch"
        exit 1
    fi
fi

# Start Kibana
echo "Starting Kibana..."
sudo systemctl start kibana
sleep 5

# Check Kibana status and connectivity
if sudo systemctl is-active --quiet kibana; then
    echo "✓ Kibana is running"
    # Wait for Kibana to be ready
    echo "Waiting for Kibana to be accessible..."
    for i in {1..30}; do
        if curl -s http://localhost:5601/api/status > /dev/null 2>&1; then
            echo "✓ Kibana is accessible at http://localhost:5601"
            break
        fi
        sleep 3
        if [ $i -eq 30 ]; then
            echo "⚠️  Warning: Kibana may not be fully ready - try accessing http://localhost:5601 in a few minutes"
            echo "   Check logs with: sudo journalctl -u kibana"
        fi
    done
else
    echo "✗ Kibana failed to start"
    echo "Attempting to restart Kibana..."
    sudo systemctl restart kibana
    sleep 10
    if sudo systemctl is-active --quiet kibana; then
        echo "✓ Kibana restarted successfully"
        echo "⏳ Kibana may take a few minutes to become fully accessible"
    else
        echo "⚠️  Kibana restart failed - check logs: sudo journalctl -u kibana"
    fi
fi

# Start Logstash
echo "Starting Logstash..."
sudo systemctl start logstash
sleep 5

# Check Logstash status
if sudo systemctl is-active --quiet logstash; then
    echo "✓ Logstash is running"
    # Check if Logstash is processing logs
    sleep 5
    if sudo ls /var/log/logstash/ > /dev/null 2>&1; then
        echo "✓ Logstash log directory accessible"
    fi
else
    echo "✗ Logstash failed to start"
    echo "Attempting to restart Logstash..."
    sudo systemctl restart logstash
    sleep 10
    if sudo systemctl is-active --quiet logstash; then
        echo "✓ Logstash restarted successfully"
    else
        echo "⚠️  Logstash restart failed - check logs: sudo journalctl -u logstash"
        echo "   Check configuration: sudo /usr/share/logstash/bin/logstash --config.test_and_exit"
    fi
fi

# Start Suricata
echo "Starting Suricata..."
sudo systemctl start suricata
sleep 3

# Check Suricata status
if sudo systemctl is-active --quiet suricata; then
    echo "✓ Suricata is running"
    # Check if Suricata is generating logs
    sleep 3
    if sudo test -f /var/log/suricata/eve.json; then
        echo "✓ Suricata is generating logs"
    else
        echo "⚠️  Suricata logs not found yet - may need time to initialize"
    fi
else
    echo "✗ Suricata failed to start"
    echo "Attempting to restart Suricata..."
    sudo systemctl restart suricata
    sleep 5
    if sudo systemctl is-active --quiet suricata; then
        echo "✓ Suricata restarted successfully"
    else
        echo "⚠️  Suricata restart failed - check logs: sudo journalctl -u suricata"
        echo "   Check configuration: sudo suricata -T -c /etc/suricata/suricata.yaml"
    fi
fi

echo ""
echo "Service Status:"
echo "==============="
sudo systemctl status elasticsearch --no-pager -l
echo ""
sudo systemctl status kibana --no-pager -l
echo ""
sudo systemctl status logstash --no-pager -l  
echo ""
sudo systemctl status suricata --no-pager -l

echo ""
echo "Access URLs:"
echo "============"
echo "Elasticsearch: https://localhost:9200 (elastic:6xdx8y-=dLZHdeH4EEm6)"
echo "Kibana: http://localhost:5601"
echo ""
echo "AI-Enhanced Tools:"
echo "=================="
echo "AI-IDS Manager: /opt/ai-ids/ai-ids-manager"
echo "Traffic Analyzer: /opt/ai-ids/analyze-traffic"
echo "APT Simulator: /opt/ai-ids/apt-simulator"
echo ""
echo "Log files:"
echo "=========="
echo "Suricata EVE: /var/log/suricata/eve.json"
echo "Suricata Fast: /var/log/suricata/fast.log"
echo "Suricata Main: /var/log/suricata/suricata.log"
echo "Generated Rules: /home/asmae/ids/generated-rules-*.rules"

echo ""
echo "Final Connectivity Check:"
echo "========================="

# Check Elasticsearch
if curl -s -k https://localhost:9200/_cluster/health > /dev/null 2>&1; then
    echo "✓ Elasticsearch: https://localhost:9200 - Ready"
else
    echo "✗ Elasticsearch: https://localhost:9200 - Not accessible"
fi

# Check Kibana  
if curl -s http://localhost:5601/api/status > /dev/null 2>&1; then
    echo "✓ Kibana: http://localhost:5601 - Ready"
else
    echo "✗ Kibana: http://localhost:5601 - Not accessible (may still be starting)"
    echo "  Try again in 2-3 minutes or check: sudo journalctl -u kibana"
fi

# Check AI service
if pgrep -f "ollama serve" > /dev/null && ollama list | grep -q "llama3.2:3b"; then
    echo "✓ AI Service: Ollama with Llama 3.2 3B - Ready"
else
    echo "⚠️  AI Service: Check with 'ollama list' or run 'ollama serve' manually"
fi

echo ""
echo "🚀 AI-Powered IDS startup complete!"
echo "If any service shows as not ready, wait a few minutes and check again."