# Intrusion Detection System (IDS) Setup

## Overview
Complete IDS setup with ELK Stack (Elasticsearch, Logstash, Kibana) and Suricata for network intrusion detection. The system is configured to capture and analyze HTTP traffic for security threats with minimal log noise.

## Configuration Files
- `kibana.yml` - Kibana configuration with kibana_system user authentication
- `logstash.conf` - Logstash pipeline for processing Suricata logs to Elasticsearch  
- `suricata.yaml` - Suricata configuration optimized for HTTP inspection (alerts + HTTP events only)
- `custom.rules` - Custom detection rules for web attacks

## Management Scripts
- `start-ids.sh` - Start all IDS services and show status
- `stop-ids.sh` - Force stop all IDS services
- `simulate-attacks.sh` - Simulate various attacks for testing

## System Credentials
- **Elasticsearch elastic user**: `elastic:6xdx8y-=dLZHdeH4EEm6`
- **Kibana service user**: `kibana_system:zjfl+ZnIbm8qDYnJX*=j`

## Access URLs
- **Elasticsearch**: https://localhost:9200
- **Kibana**: http://localhost:5601

## Detection Rules Included
- SQLMap detection
- Nikto scanner detection  
- SQL injection patterns
- XSS (Cross-site scripting) attacks
- Directory traversal
- Command injection

## Usage Instructions
1. **Start the system**: `./start-ids.sh`
2. **Access Kibana**: Navigate to http://localhost:5601
3. **Create index pattern**: In Kibana, create index pattern `suricata-*`
4. **View logs**: Go to Discover to see HTTP events and security alerts
5. **Test detection**: Run `./simulate-attacks.sh` to generate test traffic
6. **Stop system**: `./stop-ids.sh`

## Kibana Index Configuration
- **Index Pattern**: `suricata-*` 
- **Time Field**: `@timestamp`
- **Key Fields**: `event_type`, `http.hostname`, `http.url`, `alert.signature`, `alert.severity`

## Network Configuration
- **Monitored Interface**: `ens33` (external traffic)
- **Log Types**: HTTP events and security alerts only
- **Traffic Focus**: HTTP protocol inspection for web attacks

## Log Locations
- Suricata EVE: `/var/log/suricata/eve.json`
- Suricata Fast: `/var/log/suricata/fast.log`
- Suricata Main: `/var/log/suricata/suricata.log`
- Elasticsearch Index: `suricata-YYYY.MM.dd`

## Troubleshooting
- If no logs appear, restart Logstash: `sudo systemctl restart logstash`
- Check service status: `sudo systemctl status elasticsearch kibana logstash suricata`
- Verify Suricata is capturing traffic: `sudo tail -f /var/log/suricata/eve.json`