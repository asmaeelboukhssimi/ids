#!/usr/bin/env python3
"""
AI-IDS Manager
Central management script for the AI-powered IDS system
Handles analysis, rule generation, and system management
"""

import subprocess
import sys
import os
import time
import argparse
from datetime import datetime

class AIIDSManager:
    def __init__(self):
        self.base_dir = "/home/asmae/ids"
        self.scripts = {
            'analyze': os.path.join(self.base_dir, 'analyze-traffic.py'),
            'simulate': os.path.join(self.base_dir, 'apt-attack-simulator.py'),
            'start': os.path.join(self.base_dir, 'start-ids.sh'),
            'stop': os.path.join(self.base_dir, 'stop-ids.sh')
        }
        
    def check_dependencies(self):
        """Check if all dependencies are available"""
        print("Checking system dependencies...")
        
        # Check Elasticsearch
        try:
            result = subprocess.run(['curl', '-s', 'http://localhost:9200/_cluster/health'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✅ Elasticsearch is running")
            else:
                print("❌ Elasticsearch not accessible")
                return False
        except:
            print("❌ Elasticsearch not accessible")
            return False
            
        # Check Suricata
        try:
            result = subprocess.run(['systemctl', 'is-active', 'suricata'], 
                                  capture_output=True, text=True)
            if 'active' in result.stdout:
                print("✅ Suricata is running")
            else:
                print("⚠️  Suricata may not be running")
        except:
            print("⚠️  Could not check Suricata status")
            
        # Check Ollama
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=10)
            if 'llama3.2:3b' in result.stdout:
                print("✅ Ollama AI model available")
            else:
                print("⚠️  Ollama AI model not fully available")
        except:
            print("⚠️  Ollama not accessible")
            
        return True

    def analyze_traffic(self, hours=24):
        """Run traffic analysis"""
        print(f"\n🔍 Analyzing traffic from last {hours} hours...")
        try:
            result = subprocess.run([
                'python3', self.scripts['analyze']
            ], capture_output=True, text=True, timeout=300)
            
            print(result.stdout)
            if result.stderr:
                print("Errors:", result.stderr)
                
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("❌ Analysis timed out")
            return False
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
            return False

    def simulate_attacks(self):
        """Run attack simulation"""
        print("\n🎯 Running APT attack simulation...")
        try:
            result = subprocess.run([
                'python3', self.scripts['simulate']
            ], timeout=600)  # 10 minute timeout
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("❌ Simulation timed out")
            return False
        except Exception as e:
            print(f"❌ Simulation failed: {e}")
            return False

    def restart_suricata(self):
        """Restart Suricata to reload rules"""
        print("\n🔄 Restarting Suricata to reload rules...")
        try:
            result = subprocess.run(['sudo', 'systemctl', 'restart', 'suricata'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Suricata restarted successfully")
                return True
            else:
                print("❌ Failed to restart Suricata")
                print(result.stderr)
                return False
        except Exception as e:
            print(f"❌ Error restarting Suricata: {e}")
            return False

    def check_generated_rules(self):
        """Check for generated rules files"""
        print("\n📋 Checking for generated rules...")
        
        rule_files = []
        for file in os.listdir(self.base_dir):
            if file.startswith('generated-rules-') and file.endswith('.rules'):
                rule_files.append(file)
        
        if rule_files:
            rule_files.sort(reverse=True)  # Most recent first
            print(f"Found {len(rule_files)} generated rule files:")
            for i, file in enumerate(rule_files[:5]):  # Show last 5
                file_path = os.path.join(self.base_dir, file)
                mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                print(f"  {i+1}. {file} ({mod_time.strftime('%Y-%m-%d %H:%M:%S')})")
                
            return rule_files[0]  # Return most recent
        else:
            print("No generated rule files found")
            return None

    def apply_rules(self, rule_file):
        """Apply generated rules to custom.rules"""
        if not rule_file:
            print("No rule file specified")
            return False
            
        rule_path = os.path.join(self.base_dir, rule_file)
        custom_rules_path = os.path.join(self.base_dir, 'custom.rules')
        
        print(f"\n📝 Applying rules from {rule_file}...")
        
        # Show preview of rules
        try:
            with open(rule_path, 'r') as f:
                lines = f.readlines()
                rule_count = len([l for l in lines if l.strip() and not l.startswith('#')])
                print(f"This will add {rule_count} new rules to custom.rules")
                
            response = input("Apply these rules? (y/N): ")
            if response.lower() not in ['y', 'yes']:
                print("Rules not applied")
                return False
                
            # Append rules to custom.rules
            with open(rule_path, 'r') as src, open(custom_rules_path, 'a') as dst:
                dst.write(f"\n# Rules added on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                dst.write(src.read())
                
            print("✅ Rules applied successfully")
            return True
            
        except Exception as e:
            print(f"❌ Error applying rules: {e}")
            return False

    def full_analysis_cycle(self):
        """Run a complete analysis cycle"""
        print("🚀 Starting Full AI-IDS Analysis Cycle")
        print("=" * 50)
        
        # Check dependencies
        if not self.check_dependencies():
            print("❌ Dependency check failed. Please fix issues before continuing.")
            return False
        
        # Run traffic analysis
        if not self.analyze_traffic():
            print("❌ Traffic analysis failed")
            return False
        
        # Check for generated rules
        latest_rules = self.check_generated_rules()
        if latest_rules:
            if self.apply_rules(latest_rules):
                if self.restart_suricata():
                    print("\n✅ Full analysis cycle completed successfully!")
                    return True
        
        print("\n⚠️  Analysis cycle completed with some issues")
        return False

    def interactive_mode(self):
        """Run in interactive mode"""
        while True:
            print("\n" + "="*50)
            print("AI-IDS Manager - Interactive Mode")
            print("="*50)
            print("1. Check system status")
            print("2. Analyze traffic and generate rules")
            print("3. Run APT attack simulation")
            print("4. View generated rules")
            print("5. Apply rules and restart Suricata")
            print("6. Full analysis cycle")
            print("7. Exit")
            
            try:
                choice = input("\nEnter your choice (1-7): ").strip()
                
                if choice == '1':
                    self.check_dependencies()
                elif choice == '2':
                    self.analyze_traffic()
                elif choice == '3':
                    self.simulate_attacks()
                elif choice == '4':
                    self.check_generated_rules()
                elif choice == '5':
                    latest_rules = self.check_generated_rules()
                    if latest_rules:
                        if self.apply_rules(latest_rules):
                            self.restart_suricata()
                elif choice == '6':
                    self.full_analysis_cycle()
                elif choice == '7':
                    print("Goodbye!")
                    break
                else:
                    print("Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="AI-IDS Manager")
    parser.add_argument('--analyze', action='store_true', help='Run traffic analysis')
    parser.add_argument('--simulate', action='store_true', help='Run attack simulation')
    parser.add_argument('--full-cycle', action='store_true', help='Run full analysis cycle')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--hours', type=int, default=24, help='Hours of traffic to analyze (default: 24)')
    
    args = parser.parse_args()
    
    manager = AIIDSManager()
    
    if args.analyze:
        manager.analyze_traffic(args.hours)
    elif args.simulate:
        manager.simulate_attacks()
    elif args.full_cycle:
        manager.full_analysis_cycle()
    elif args.interactive:
        manager.interactive_mode()
    else:
        # Default to interactive mode if no arguments provided
        manager.interactive_mode()

if __name__ == "__main__":
    main()