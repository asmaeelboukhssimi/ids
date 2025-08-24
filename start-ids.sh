#!/bin/bash

echo "Starting IDS Services..."

# Copy configuration files to proper locations
sudo cp /home/asmae/kibana.yml /etc/kibana/
sudo cp /home/asmae/logstash.conf /etc/logstash/conf.d/
sudo cp /home/asmae/suricata.yaml /etc/suricata/
sudo cp /home/asmae/custom.rules /etc/suricata/rules/

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
echo "Log files:"
echo "=========="
echo "Suricata EVE: /var/log/suricata/eve.json"
echo "Suricata Fast: /var/log/suricata/fast.log"
echo "Suricata Main: /var/log/suricata/suricata.log"