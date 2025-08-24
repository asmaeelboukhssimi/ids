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

# Check Elasticsearch status
if sudo systemctl is-active --quiet elasticsearch; then
    echo "✓ Elasticsearch is running"
else
    echo "✗ Elasticsearch failed to start"
    exit 1
fi

# Start Kibana
echo "Starting Kibana..."
sudo systemctl start kibana
sleep 5

# Check Kibana status
if sudo systemctl is-active --quiet kibana; then
    echo "✓ Kibana is running"
else
    echo "✗ Kibana failed to start"
fi

# Start Logstash
echo "Starting Logstash..."
sudo systemctl start logstash
sleep 5

# Check Logstash status
if sudo systemctl is-active --quiet logstash; then
    echo "✓ Logstash is running"
else
    echo "✗ Logstash failed to start"
fi

# Start Suricata
echo "Starting Suricata..."
sudo systemctl start suricata
sleep 3

# Check Suricata status
if sudo systemctl is-active --quiet suricata; then
    echo "✓ Suricata is running"
else
    echo "✗ Suricata failed to start"
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