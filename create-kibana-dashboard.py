#!/usr/bin/env python3
"""
Kibana IDS Dashboard Creator
Creates comprehensive dashboards for Suricata IDS monitoring
"""

import requests
import json
import sys
import time
from datetime import datetime
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class KibanaDashboardCreator:
    def __init__(self, kibana_url="http://localhost:5601", es_username="elastic", es_password="6xdx8y-=dLZHdeH4EEm6"):
        self.kibana_url = kibana_url
        self.auth = (es_username, es_password)
        self.headers = {
            'Content-Type': 'application/json',
            'kbn-xsrf': 'true'
        }
        
    def login_kibana(self):
        """Login to Kibana and get session"""
        try:
            # Get login page to get session cookie
            response = requests.get(f"{self.kibana_url}/login", 
                                  auth=self.auth, 
                                  allow_redirects=False)
            
            # Try to login with credentials
            login_data = {
                'providerType': 'basic',
                'providerName': 'basic',
                'currentURL': f'{self.kibana_url}/login?next=%2F',
                'params': {
                    'username': self.auth[0],
                    'password': self.auth[1]
                }
            }
            
            response = requests.post(f"{self.kibana_url}/internal/security/login",
                                   json=login_data,
                                   headers=self.headers,
                                   cookies=response.cookies if response.cookies else None)
            
            if response.status_code in [200, 302]:
                print("✅ Successfully authenticated with Kibana")
                self.session_cookies = response.cookies
                return True
            else:
                print(f"⚠️  Kibana authentication status: {response.status_code}")
                return True  # Continue anyway, might work with API auth
                
        except Exception as e:
            print(f"⚠️  Kibana authentication issue: {e}")
            return True  # Continue anyway
    
    def create_index_pattern(self):
        """Create Suricata index pattern"""
        print("Creating Suricata index pattern...")
        
        index_pattern = {
            "attributes": {
                "title": "suricata-*",
                "timeFieldName": "@timestamp",
                "fields": json.dumps([
                    {"name": "@timestamp", "type": "date", "searchable": True, "aggregatable": True},
                    {"name": "event_type", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "alert.signature", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "alert.severity", "type": "number", "searchable": True, "aggregatable": True},
                    {"name": "alert.category", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "src_ip", "type": "ip", "searchable": True, "aggregatable": True},
                    {"name": "dest_ip", "type": "ip", "searchable": True, "aggregatable": True},
                    {"name": "dest_port", "type": "number", "searchable": True, "aggregatable": True},
                    {"name": "proto", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "http.hostname", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "http.url", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "http.user_agent", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "http.status", "type": "number", "searchable": True, "aggregatable": True}
                ])
            }
        }
        
        try:
            response = requests.post(
                f"{self.kibana_url}/api/saved_objects/index-pattern/suricata-*",
                headers=self.headers,
                json=index_pattern,
                auth=self.auth,
                cookies=getattr(self, 'session_cookies', None)
            )
            
            if response.status_code in [200, 409]:  # 409 means already exists
                print("✅ Suricata index pattern created/exists")
                return True
            else:
                print(f"⚠️  Index pattern creation status: {response.status_code}")
                print(response.text[:200])
                return False
                
        except Exception as e:
            print(f"❌ Error creating index pattern: {e}")
            return False
    
    def create_visualizations(self):
        """Create IDS visualizations"""
        print("Creating IDS visualizations...")
        
        visualizations = [
            # Alert Severity Distribution
            {
                "id": "ids-alert-severity",
                "type": "visualization",
                "attributes": {
                    "title": "Alert Severity Distribution",
                    "visState": json.dumps({
                        "title": "Alert Severity Distribution",
                        "type": "pie",
                        "aggs": [
                            {
                                "id": "1",
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            },
                            {
                                "id": "2",
                                "type": "terms",
                                "schema": "segment",
                                "params": {
                                    "field": "alert.severity",
                                    "size": 5,
                                    "order": "desc",
                                    "orderBy": "1"
                                }
                            }
                        ]
                    }),
                    "uiStateJSON": "{}",
                    "description": "Distribution of alert severities",
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "suricata-*",
                            "query": {
                                "match": {
                                    "event_type": "alert"
                                }
                            }
                        })
                    }
                }
            },
            
            # Top Attack Signatures
            {
                "id": "ids-top-signatures",
                "type": "visualization", 
                "attributes": {
                    "title": "Top Attack Signatures",
                    "visState": json.dumps({
                        "title": "Top Attack Signatures",
                        "type": "horizontal_bar",
                        "aggs": [
                            {
                                "id": "1",
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            },
                            {
                                "id": "2", 
                                "type": "terms",
                                "schema": "segment",
                                "params": {
                                    "field": "alert.signature.keyword",
                                    "size": 10,
                                    "order": "desc",
                                    "orderBy": "1"
                                }
                            }
                        ]
                    }),
                    "uiStateJSON": "{}",
                    "description": "Most common attack signatures detected",
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "suricata-*",
                            "query": {
                                "match": {
                                    "event_type": "alert"
                                }
                            }
                        })
                    }
                }
            },
            
            # Alerts Over Time
            {
                "id": "ids-alerts-timeline",
                "type": "visualization",
                "attributes": {
                    "title": "Alerts Over Time",
                    "visState": json.dumps({
                        "title": "Alerts Over Time",
                        "type": "line",
                        "aggs": [
                            {
                                "id": "1",
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            },
                            {
                                "id": "2",
                                "type": "date_histogram",
                                "schema": "segment",
                                "params": {
                                    "field": "@timestamp",
                                    "interval": "auto",
                                    "min_doc_count": 1
                                }
                            }
                        ]
                    }),
                    "uiStateJSON": "{}",
                    "description": "Alert frequency over time",
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "suricata-*",
                            "query": {
                                "match": {
                                    "event_type": "alert"
                                }
                            }
                        })
                    }
                }
            },
            
            # Top Source IPs
            {
                "id": "ids-top-source-ips",
                "type": "visualization",
                "attributes": {
                    "title": "Top Source IPs",
                    "visState": json.dumps({
                        "title": "Top Source IPs",
                        "type": "table",
                        "aggs": [
                            {
                                "id": "1",
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            },
                            {
                                "id": "2",
                                "type": "terms",
                                "schema": "bucket",
                                "params": {
                                    "field": "src_ip",
                                    "size": 10,
                                    "order": "desc",
                                    "orderBy": "1"
                                }
                            }
                        ]
                    }),
                    "uiStateJSON": "{}",
                    "description": "Source IPs generating most alerts",
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "suricata-*",
                            "query": {
                                "match": {
                                    "event_type": "alert"
                                }
                            }
                        })
                    }
                }
            },
            
            # HTTP Traffic Summary
            {
                "id": "ids-http-traffic",
                "type": "visualization",
                "attributes": {
                    "title": "HTTP Traffic Summary",
                    "visState": json.dumps({
                        "title": "HTTP Traffic Summary",
                        "type": "metric",
                        "aggs": [
                            {
                                "id": "1",
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            }
                        ]
                    }),
                    "uiStateJSON": "{}",
                    "description": "Total HTTP events captured",
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "suricata-*",
                            "query": {
                                "match": {
                                    "event_type": "http"
                                }
                            }
                        })
                    }
                }
            },
            
            # Protocol Distribution
            {
                "id": "ids-protocol-distribution",
                "type": "visualization",
                "attributes": {
                    "title": "Protocol Distribution",
                    "visState": json.dumps({
                        "title": "Protocol Distribution",
                        "type": "pie",
                        "aggs": [
                            {
                                "id": "1",
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            },
                            {
                                "id": "2",
                                "type": "terms",
                                "schema": "segment",
                                "params": {
                                    "field": "proto",
                                    "size": 5,
                                    "order": "desc",
                                    "orderBy": "1"
                                }
                            }
                        ]
                    }),
                    "uiStateJSON": "{}",
                    "description": "Distribution of network protocols",
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "suricata-*"
                        })
                    }
                }
            }
        ]
        
        success_count = 0
        for viz in visualizations:
            try:
                response = requests.post(
                    f"{self.kibana_url}/api/saved_objects/{viz['type']}/{viz['id']}",
                    headers=self.headers,
                    json={"attributes": viz["attributes"]},
                    auth=self.auth,
                    cookies=getattr(self, 'session_cookies', None)
                )
                
                if response.status_code in [200, 409]:
                    print(f"✅ Created visualization: {viz['attributes']['title']}")
                    success_count += 1
                else:
                    print(f"⚠️  Visualization '{viz['attributes']['title']}' status: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error creating visualization '{viz['attributes']['title']}': {e}")
        
        print(f"✅ Created {success_count}/{len(visualizations)} visualizations")
        return success_count > 0
    
    def create_dashboard(self):
        """Create the main IDS dashboard"""
        print("Creating IDS Dashboard...")
        
        dashboard = {
            "version": "8.19.2",
            "objects": [
                {
                    "attributes": {
                        "title": "🛡️ IDS Security Dashboard",
                        "hits": 0,
                        "description": "Comprehensive dashboard for Suricata IDS monitoring and security analysis",
                        "panelsJSON": json.dumps([
                            {
                                "gridData": {"x": 0, "y": 0, "w": 24, "h": 15},
                                "panelIndex": "1",
                                "embeddableConfig": {},
                                "panelRefName": "panel_1"
                            },
                            {
                                "gridData": {"x": 24, "y": 0, "w": 24, "h": 15},
                                "panelIndex": "2", 
                                "embeddableConfig": {},
                                "panelRefName": "panel_2"
                            },
                            {
                                "gridData": {"x": 0, "y": 15, "w": 48, "h": 15},
                                "panelIndex": "3",
                                "embeddableConfig": {},
                                "panelRefName": "panel_3"
                            },
                            {
                                "gridData": {"x": 0, "y": 30, "w": 24, "h": 15},
                                "panelIndex": "4",
                                "embeddableConfig": {},
                                "panelRefName": "panel_4"
                            },
                            {
                                "gridData": {"x": 24, "y": 30, "w": 12, "h": 15},
                                "panelIndex": "5",
                                "embeddableConfig": {},
                                "panelRefName": "panel_5"
                            },
                            {
                                "gridData": {"x": 36, "y": 30, "w": 12, "h": 15},
                                "panelIndex": "6",
                                "embeddableConfig": {},
                                "panelRefName": "panel_6"
                            }
                        ]),
                        "timeRestore": False,
                        "timeTo": "now",
                        "timeFrom": "now-24h",
                        "refreshInterval": {
                            "pause": False,
                            "value": 60000
                        },
                        "kibanaSavedObjectMeta": {
                            "searchSourceJSON": json.dumps({
                                "query": {"query": "", "language": "kuery"},
                                "filter": []
                            })
                        }
                    },
                    "references": [
                        {
                            "name": "panel_1",
                            "type": "visualization",
                            "id": "ids-alert-severity"
                        },
                        {
                            "name": "panel_2", 
                            "type": "visualization",
                            "id": "ids-protocol-distribution"
                        },
                        {
                            "name": "panel_3",
                            "type": "visualization", 
                            "id": "ids-alerts-timeline"
                        },
                        {
                            "name": "panel_4",
                            "type": "visualization",
                            "id": "ids-top-signatures"
                        },
                        {
                            "name": "panel_5",
                            "type": "visualization",
                            "id": "ids-top-source-ips"
                        },
                        {
                            "name": "panel_6",
                            "type": "visualization",
                            "id": "ids-http-traffic"
                        }
                    ],
                    "migrationVersion": {"dashboard": "8.19.0"},
                    "coreMigrationVersion": "8.19.0"
                }
            ]
        }
        
        try:
            response = requests.post(
                f"{self.kibana_url}/api/saved_objects/_import",
                headers={'kbn-xsrf': 'true'},
                files={'file': ('dashboard.ndjson', json.dumps(dashboard))},
                auth=self.auth,
                cookies=getattr(self, 'session_cookies', None)
            )
            
            if response.status_code in [200, 409]:
                print("✅ IDS Dashboard created successfully!")
                print(f"🌐 Access your dashboard at: {self.kibana_url}/app/kibana#/dashboard/ids-dashboard")
                return True
            else:
                print(f"⚠️  Dashboard creation status: {response.status_code}")
                print(response.text[:300])
                return False
                
        except Exception as e:
            print(f"❌ Error creating dashboard: {e}")
            return False
    
    def create_simple_dashboard(self):
        """Create a simple dashboard using the saved objects API"""
        print("Creating simple IDS Dashboard...")
        
        dashboard_config = {
            "attributes": {
                "title": "🛡️ IDS Security Dashboard",
                "hits": 0,
                "description": "Comprehensive dashboard for Suricata IDS monitoring",
                "panelsJSON": "[]",
                "timeRestore": False,
                "timeTo": "now",
                "timeFrom": "now-24h",
                "refreshInterval": {
                    "pause": False,
                    "value": 60000
                },
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
        
        try:
            response = requests.post(
                f"{self.kibana_url}/api/saved_objects/dashboard/ids-security-dashboard",
                headers=self.headers,
                json=dashboard_config,
                auth=self.auth,
                cookies=getattr(self, 'session_cookies', None)
            )
            
            if response.status_code in [200, 409]:
                print("✅ Simple IDS Dashboard created!")
                return True
            else:
                print(f"⚠️  Simple dashboard status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error creating simple dashboard: {e}")
            return False

def main():
    print("🛡️  Creating Kibana IDS Dashboard")
    print("=" * 50)
    
    creator = KibanaDashboardCreator()
    
    # Step 1: Login to Kibana
    if not creator.login_kibana():
        print("❌ Failed to authenticate with Kibana")
        return False
    
    time.sleep(2)
    
    # Step 2: Create index pattern
    if not creator.create_index_pattern():
        print("❌ Failed to create index pattern")
        return False
    
    time.sleep(2)
    
    # Step 3: Create visualizations
    if not creator.create_visualizations():
        print("❌ Failed to create visualizations")
        return False
    
    time.sleep(2)
    
    # Step 4: Create dashboard
    if not creator.create_simple_dashboard():
        print("❌ Failed to create dashboard")
        return False
    
    print("\n✅ IDS Dashboard setup completed!")
    print(f"🌐 Access Kibana at: http://localhost:5601")
    print("📊 Look for 'IDS Security Dashboard' in your dashboards")
    print("\n📋 Manual Setup Instructions:")
    print("1. Go to http://localhost:5601")
    print("2. Login with: elastic / 6xdx8y-=dLZHdeH4EEm6")
    print("3. Go to Stack Management → Index Patterns")
    print("4. Create 'suricata-*' pattern with @timestamp as time field")
    print("5. Go to Dashboard and create visualizations manually")
    
    return True

if __name__ == "__main__":
    main()