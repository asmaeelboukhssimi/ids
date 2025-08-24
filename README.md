# AI-Powered Intrusion Detection System (IDS)

## Overview
Complete IDS setup with ELK Stack (Elasticsearch, Logstash, Kibana), Suricata for network intrusion detection, and AI-powered traffic analysis. The system captures and analyzes network traffic for security threats with AI-enhanced APT detection capabilities.

## System Architecture

### Core Components
- **Elasticsearch**: Traffic data storage and indexing
- **Logstash**: Log processing pipeline  
- **Kibana**: Visualization and analysis dashboard
- **Suricata**: Network intrusion detection engine
- **Ollama + Llama 3.2 3B**: Offline AI model for pattern analysis

### AI Enhancement Components
- **Traffic Analyzer**: AI-powered traffic analysis and rule generation
- **APT Simulator**: Comprehensive attack simulation for testing
- **AI-IDS Manager**: Central management interface

## Configuration Files (All Symlinked)
- `kibana.yml` - Kibana configuration with kibana_system user authentication
- `logstash.conf` - Logstash pipeline for processing Suricata logs to Elasticsearch  
- `suricata.yaml` - Suricata configuration optimized for HTTP inspection
- `custom.rules` - Custom detection rules (includes AI-generated rules)

## Management Scripts
- `start-ids.sh` - Start all IDS services and show status
- `stop-ids.sh` - Force stop all IDS services
- `simulate-attacks.sh` - Basic attack simulation
- **`ai-ids-manager.py`** - **AI-powered central management interface**
- **`analyze-traffic.py`** - **AI traffic analysis and rule generation**
- **`apt-attack-simulator.py`** - **Advanced APT attack simulation**

## System Access
- **Elasticsearch**: https://localhost:9200
- **Kibana**: http://localhost:5601
- **Credentials**:
  - Elasticsearch elastic user: `elastic:6xdx8y-=dLZHdeH4EEm6`
  - Kibana service user: `kibana_system:zjfl+ZnIbm8qDYnJX*=j`

## AI-Powered Features

### 1. Traffic Analysis (`analyze-traffic.py`)
- Queries Elasticsearch for recent network traffic
- Detects suspicious patterns using rule-based and AI analysis
- Identifies APT indicators: DGA domains, C2 communication, data exfiltration
- Generates custom Suricata rules based on findings
- **Available at**: `/opt/ai-ids/analyze-traffic`

### 2. APT Attack Simulator (`apt-attack-simulator.py`)
- Simulates realistic APT attack campaigns
- Covers all attack phases: reconnaissance, initial access, C2, lateral movement, persistence, exfiltration
- Generates DGA domains and suspicious traffic patterns
- Perfect for testing IDS detection capabilities
- **Available at**: `/opt/ai-ids/apt-simulator`

### 3. AI-IDS Manager (`ai-ids-manager.py`)
- Central management interface for the AI-IDS system
- Interactive mode with menu-driven operations
- Handles full analysis cycles and rule deployment
- System health checks and dependency verification
- **Available at**: `/opt/ai-ids/ai-ids-manager`

### AI Model Details
- **Model**: Llama 3.2 3B (via Ollama)
- **Capabilities**: Offline, free, lightweight (2GB)
- **Purpose**: Enhanced pattern analysis and rule generation
- **Fallback**: Rule-based analysis if AI unavailable

## Usage Instructions

### Quick Start
```bash
# Traditional IDS management
./start-ids.sh                    # Start all services
./stop-ids.sh                     # Stop all services

# AI-Enhanced Management
/opt/ai-ids/ai-ids-manager        # Interactive AI management
/opt/ai-ids/analyze-traffic       # Run traffic analysis
/opt/ai-ids/apt-simulator         # Simulate APT attacks
```

### AI Analysis Workflow
1. **Start IDS Services**: `./start-ids.sh`
2. **Generate Traffic**: Normal operations or `/opt/ai-ids/apt-simulator`  
3. **Analyze Traffic**: `/opt/ai-ids/analyze-traffic`
4. **Review Generated Rules**: Check `generated-rules-*.rules` files
5. **Apply Rules**: Manually add relevant rules to `custom.rules`
6. **Restart Suricata**: Rules automatically active via symlinks
7. **Monitor**: Check Kibana dashboards for new alerts

### Command Line Options
```bash
# Analyze specific time periods
python3 ai-ids-manager.py --analyze --hours 24

# Run full analysis cycle
python3 ai-ids-manager.py --full-cycle

# Interactive mode (default)
python3 ai-ids-manager.py --interactive
```

## Detection Capabilities

### Traditional Rules (Built-in)
- SQLMap detection
- Nikto scanner detection  
- SQL injection patterns
- XSS (Cross-site scripting) attacks
- Directory traversal
- Command injection

### AI-Enhanced APT Detection
- **Domain Generation Algorithms (DGA)**: Detects algorithmically generated domains
- **C2 Communication**: Identifies command & control traffic patterns
- **Data Exfiltration**: Detects large data transfers and suspicious uploads
- **Port Scanning**: Identifies reconnaissance activities
- **Lateral Movement**: Detects SMB enumeration and WMI/WinRM attempts
- **Persistence**: Identifies persistence mechanism deployment

### Advanced Attack Simulation
- **Reconnaissance**: Port scanning, DNS enumeration
- **Initial Access**: Credential stuffing, web app scanning
- **Command & Control**: HTTP beacons, encoded communications
- **Lateral Movement**: SMB/WMI enumeration
- **Persistence**: Scheduled task simulation
- **Exfiltration**: Large file transfers, database dumps
- **DNS Tunneling**: Covert channel communication

## File Structure
```
/home/asmae/ids/
├── README.md                    # This documentation
├── start-ids.sh                # Service management
├── stop-ids.sh                 # Service management
├── simulate-attacks.sh          # Basic attack simulation
├── ai-ids-manager.py           # AI management interface
├── analyze-traffic.py          # AI traffic analysis
├── apt-attack-simulator.py     # APT attack simulation
├── custom.rules               # Active Suricata rules (symlinked)
├── kibana.yml                 # Kibana config (symlinked)
├── logstash.conf              # Logstash config (symlinked)
├── suricata.yaml              # Suricata config (symlinked)
└── generated-rules-*.rules    # AI-generated rules

/opt/ai-ids/                   # System-wide AI tools
├── ai-ids-manager -> /home/asmae/ids/ai-ids-manager.py
├── analyze-traffic -> /home/asmae/ids/analyze-traffic.py
└── apt-simulator -> /home/asmae/ids/apt-attack-simulator.py
```

## Generated Rules
AI-generated rules are saved as `/home/asmae/ids/generated-rules-YYYYMMDD-HHMMSS.rules`

**Example generated rules**:
- Suspicious IP communications
- DGA domain queries  
- APT tool User-Agent strings
- Port scan detection
- C2 communication patterns
- Data exfiltration indicators

## Kibana Configuration
- **Index Pattern**: `suricata-*` 
- **Time Field**: `@timestamp`
- **Key Fields**: `event_type`, `http.hostname`, `http.url`, `alert.signature`, `alert.severity`

## Network Configuration
- **Monitored Interface**: `ens33` (external traffic)
- **Log Types**: HTTP events and security alerts
- **Traffic Focus**: HTTP protocol + AI-enhanced APT detection

## Log Locations
- Suricata EVE: `/var/log/suricata/eve.json`
- Suricata Fast: `/var/log/suricata/fast.log`
- Suricata Main: `/var/log/suricata/suricata.log`
- Elasticsearch Index: `suricata-YYYY.MM.dd`

## Troubleshooting
- **No logs**: `sudo systemctl restart logstash`
- **Service status**: `sudo systemctl status elasticsearch kibana logstash suricata`
- **Traffic capture**: `sudo tail -f /var/log/suricata/eve.json`
- **AI model**: `ollama list` (should show llama3.2:3b)
- **AI service**: `ollama serve` (if not running in background)

## Advanced Features

### Symlinked Configuration
All configuration files are symlinked to their system locations, enabling:
- Git version control of all changes
- Easy deployment and rollback
- Centralized configuration management

### Offline Operation  
- AI model runs completely offline (no internet required)
- All analysis performed locally
- No data leaves your system

### Rule Management
- Generated rules use high SIDs (3000000+) to avoid conflicts
- Manual review required before rule deployment
- AI enhances but doesn't replace traditional detection
- Automatic backup of original configurations

## Security Notes
- All traffic analysis is performed locally
- AI model operates offline with no external dependencies
- Generated rules require manual review before activation
- System designed for controlled test environments
- Configuration changes are tracked in Git for audit trail