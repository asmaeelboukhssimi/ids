#!/bin/bash

echo "Stopping IDS Services..."

# Force stop all services
echo "Stopping Suricata..."
sudo systemctl stop suricata
sudo pkill -f suricata

echo "Stopping Logstash..."
sudo systemctl stop logstash
sudo pkill -f logstash

echo "Stopping Kibana..."
sudo systemctl stop kibana
sudo pkill -f kibana

echo "Stopping Elasticsearch..."
sudo systemctl stop elasticsearch
sudo pkill -f elasticsearch

echo ""
echo "Verifying all services are stopped:"
echo "===================================="

services=("elasticsearch" "kibana" "logstash" "suricata")

for service in "${services[@]}"; do
    if sudo systemctl is-active --quiet $service; then
        echo "✗ $service is still running"
    else
        echo "✓ $service is stopped"
    fi
done

echo ""
echo "Checking for remaining processes:"
echo "================================="
ps aux | grep -E "(elasticsearch|kibana|logstash|suricata)" | grep -v grep || echo "No IDS processes found"