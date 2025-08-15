#!/usr/bin/env python3
"""
DeFi Sentinel Demo

A demonstration script showing the core functionality of DeFi Sentinel
without requiring all external dependencies.
"""

import os
import asyncio
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class DeFiSentinelDemo:
    """Demo version of DeFi Sentinel for testing core concepts"""
    
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.demo_contracts = {
            "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": {
                "name": "Uniswap Token (UNI)",
                "chain": "ethereum",
                "risk_score": 25,
                "risk_level": "LOW"
            },
            "0xa0b86a33e6417a844bf5eff6c7b6cbd3ba9c3b44": {
                "name": "SushiToken (SUSHI)", 
                "chain": "ethereum",
                "risk_score": 45,
                "risk_level": "MEDIUM"
            },
            "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce": {
                "name": "SHIBA INU (SHIB)",
                "chain": "ethereum", 
                "risk_score": 75,
                "risk_level": "HIGH"
            }
        }
    
    def validate_environment(self):
        """Validate environment setup"""
        print("🔧 Validating DeFi Sentinel Environment...")
        print("=" * 50)
        
        # Check API key
        if not self.api_key:
            print("❌ OPENAI_API_KEY not found in environment")
            print("   Please set your OpenRouter API key in .env file")
            return False
        elif not self.api_key.startswith("sk-or-"):
            print("⚠️  API key doesn't appear to be an OpenRouter key")
            print(f"   Found: {self.api_key[:20]}...")
            print("   Expected format: sk-or-v1-...")
        else:
            print("✅ OpenRouter API key found and validated")
            print(f"   Key: {self.api_key[:20]}...{self.api_key[-10:]}")
        
        # Check environment file
        if os.path.exists(".env"):
            print("✅ Environment file (.env) exists")
        else:
            print("⚠️  No .env file found")
        
        print("\n🌐 Network Configuration:")
        networks = {
            "ETHEREUM_RPC_URL": os.getenv("ETHEREUM_RPC_URL", "Not configured"),
            "POLYGON_RPC_URL": os.getenv("POLYGON_RPC_URL", "Not configured"),
            "BSC_RPC_URL": os.getenv("BSC_RPC_URL", "Not configured")
        }
        
        for network, url in networks.items():
            status = "✅" if url != "Not configured" else "⚠️ "
            print(f"   {status} {network}: {url}")
        
        return True
    
    async def analyze_contract_async(self, address: str, chain: str = "ethereum"):
        """Demo contract analysis (async version)"""
        print(f"\n🔍 Analyzing Contract: {address}")
        print("=" * 50)
        
        # Check if it's a known demo contract
        if address in self.demo_contracts:
            contract = self.demo_contracts[address]
            print(f"📋 Contract Name: {contract['name']}")
            print(f"⛓️  Network: {contract['chain'].title()}")
            print(f"📊 Risk Score: {contract['risk_score']}/100")
            print(f"🎯 Risk Level: {contract['risk_level']}")
            
            # Simulate analysis process
            print("\n🔄 Running Analysis Components...")
            analysis_steps = [
                "Web3 Contract Analysis",
                "Security Vulnerability Scan", 
                "Admin Privilege Assessment",
                "Rugpull Pattern Detection",
                "Risk Score Calculation"
            ]
            
            for i, step in enumerate(analysis_steps, 1):
                print(f"   {i}/5 ✓ {step}")
                await asyncio.sleep(0.3)  # Simulate processing time
            
            # Generate detailed analysis
            print(f"\n📈 Detailed Analysis Results:")
            print("-" * 30)
            
            if contract['risk_level'] == "LOW":
                findings = [
                    "✅ No critical vulnerabilities detected",
                    "✅ Standard ERC-20 implementation", 
                    "✅ Limited admin privileges",
                    "✅ Good liquidity distribution"
                ]
                recommendations = [
                    "Safe for general DeFi interactions",
                    "Continue periodic monitoring",
                    "Consider for portfolio inclusion"
                ]
            elif contract['risk_level'] == "MEDIUM":
                findings = [
                    "⚠️  Some admin privileges present",
                    "⚠️  Proxy pattern detected",
                    "✅ No critical security flaws",
                    "⚠️  Moderate centralization"
                ]
                recommendations = [
                    "Proceed with caution",
                    "Monitor admin activities",
                    "Limit exposure amount"
                ]
            else:  # HIGH
                findings = [
                    "🚨 High admin privileges detected",
                    "🚨 Potential rugpull indicators",
                    "⚠️  Centralized control mechanisms",
                    "🚨 Unusual token distribution"
                ]
                recommendations = [
                    "🛑 HIGH RISK - Exercise extreme caution",
                    "Consider avoiding until improvements made",
                    "Monitor for any changes before investing"
                ]
            
            print("🔍 Key Findings:")
            for finding in findings:
                print(f"   {finding}")
            
            print(f"\n💡 Recommendations:")
            for rec in recommendations:
                print(f"   • {rec}")
            
        else:
            print("⚠️  Contract not in demo database")
            print("   In full version, this would perform live analysis")
            print("   Example addresses to try:")
            for addr, info in self.demo_contracts.items():
                print(f"   • {addr} ({info['name']})")
        
        return {
            "address": address,
            "chain": chain,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "status": "completed"
        }
    
    def analyze_contract(self, address: str, chain: str = "ethereum"):
        """Demo contract analysis (sync version)"""
        print(f"\n🔍 Analyzing Contract: {address}")
        print("=" * 50)
        
        # Check if it's a known demo contract
        if address in self.demo_contracts:
            contract = self.demo_contracts[address]
            print(f"📋 Contract Name: {contract['name']}")
            print(f"⛓️  Network: {contract['chain'].title()}")
            print(f"📊 Risk Score: {contract['risk_score']}/100")
            print(f"🎯 Risk Level: {contract['risk_level']}")
            
            # Simulate analysis process
            print("\n🔄 Running Analysis Components...")
            analysis_steps = [
                "Web3 Contract Analysis",
                "Security Vulnerability Scan", 
                "Admin Privilege Assessment",
                "Rugpull Pattern Detection",
                "Risk Score Calculation"
            ]
            
            for i, step in enumerate(analysis_steps, 1):
                print(f"   {i}/5 ✓ {step}")
                import time
                time.sleep(0.2)  # Simulate processing time
            
            # Generate detailed analysis
            print(f"\n📈 Detailed Analysis Results:")
            print("-" * 30)
            
            if contract['risk_level'] == "LOW":
                findings = [
                    "✅ No critical vulnerabilities detected",
                    "✅ Standard ERC-20 implementation", 
                    "✅ Limited admin privileges",
                    "✅ Good liquidity distribution"
                ]
                recommendations = [
                    "Safe for general DeFi interactions",
                    "Continue periodic monitoring",
                    "Consider for portfolio inclusion"
                ]
            elif contract['risk_level'] == "MEDIUM":
                findings = [
                    "⚠️  Some admin privileges present",
                    "⚠️  Proxy pattern detected",
                    "✅ No critical security flaws",
                    "⚠️  Moderate centralization"
                ]
                recommendations = [
                    "Proceed with caution",
                    "Monitor admin activities",
                    "Limit exposure amount"
                ]
            else:  # HIGH
                findings = [
                    "🚨 High admin privileges detected",
                    "🚨 Potential rugpull indicators",
                    "⚠️  Centralized control mechanisms",
                    "🚨 Unusual token distribution"
                ]
                recommendations = [
                    "🛑 HIGH RISK - Exercise extreme caution",
                    "Consider avoiding until improvements made",
                    "Monitor for any changes before investing"
                ]
            
            print("🔍 Key Findings:")
            for finding in findings:
                print(f"   {finding}")
            
            print(f"\n💡 Recommendations:")
            for rec in recommendations:
                print(f"   • {rec}")
            
        else:
            print("⚠️  Contract not in demo database")
            print("   In full version, this would perform live analysis")
            print("   Example addresses to try:")
            for addr, info in self.demo_contracts.items():
                print(f"   • {addr} ({info['name']})")
        
        return {
            "address": address,
            "chain": chain,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "status": "completed"
        }
    
    def generate_risk_report(self, address: str):
        """Generate a comprehensive risk report"""
        if address not in self.demo_contracts:
            print("❌ Contract not found in demo database")
            return
        
        contract = self.demo_contracts[address]
        
        print(f"\n📋 COMPREHENSIVE RISK REPORT")
        print("=" * 60)
        print(f"Contract: {contract['name']}")
        print(f"Address: {address}")
        print(f"Network: {contract['chain'].title()}")
        print(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print("=" * 60)
        
        print(f"\n🎯 EXECUTIVE SUMMARY")
        print(f"Risk Score: {contract['risk_score']}/100 ({contract['risk_level']})")
        
        if contract['risk_level'] == "LOW":
            summary = "This contract presents minimal security risks and follows standard practices."
        elif contract['risk_level'] == "MEDIUM":
            summary = "This contract has moderate risks that require careful consideration."
        else:
            summary = "This contract presents significant security risks and should be approached with extreme caution."
        
        print(f"Assessment: {summary}")
        
        # Risk breakdown
        print(f"\n📊 RISK BREAKDOWN")
        risk_categories = {
            "Security Vulnerabilities": "LOW" if contract['risk_level'] == "LOW" else "MEDIUM" if contract['risk_level'] == "MEDIUM" else "HIGH",
            "Admin Privileges": "LOW" if contract['risk_level'] == "LOW" else "HIGH",
            "Liquidity Risks": "LOW" if contract['risk_level'] == "LOW" else "MEDIUM",
            "Market Manipulation": "LOW" if contract['risk_level'] == "LOW" else "HIGH" if contract['risk_level'] == "HIGH" else "MEDIUM"
        }
        
        for category, level in risk_categories.items():
            emoji = "🟢" if level == "LOW" else "🟡" if level == "MEDIUM" else "🔴"
            print(f"   {emoji} {category}: {level}")
        
        print(f"\n🔍 MONITORING RECOMMENDATIONS")
        monitoring_items = [
            "Set up continuous monitoring alerts",
            "Track admin function usage",
            "Monitor liquidity pool changes",
            "Watch for unusual transaction patterns"
        ]
        
        for item in monitoring_items:
            print(f"   • {item}")
    
    def show_monitoring_dashboard(self):
        """Display monitoring dashboard"""
        print(f"\n📊 DeFi SENTINEL MONITORING DASHBOARD")
        print("=" * 60)
        print(f"Last Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print("=" * 60)
        
        print(f"\n📈 SYSTEM METRICS")
        print(f"   Contracts Monitored: {len(self.demo_contracts)}")
        print(f"   Active Alerts: 2")
        print(f"   Average Risk Score: 48/100")
        print(f"   Scans Today: 127")
        
        print(f"\n🎯 RISK DISTRIBUTION")
        risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for contract in self.demo_contracts.values():
            risk_counts[contract['risk_level']] += 1
        
        for level, count in risk_counts.items():
            emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "⚫"}[level]
            print(f"   {emoji} {level}: {count} contracts")
        
        print(f"\n📋 MONITORED CONTRACTS")
        for address, contract in self.demo_contracts.items():
            emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}[contract['risk_level']]
            short_addr = f"{address[:10]}...{address[-8:]}"
            print(f"   {emoji} {short_addr} | {contract['name']} | {contract['risk_score']}/100")
        
        print(f"\n🚨 RECENT ALERTS")
        alerts = [
            "HIGH: Admin privilege abuse detected - SHIBA INU",
            "MEDIUM: Unusual liquidity movement - SushiToken"
        ]
        
        for alert in alerts:
            print(f"   • {alert}")
    
    def run_demo(self):
        """Run the complete demo"""
        print("🛡️  DEFI SENTINEL - SMART CONTRACT SECURITY MONITOR")
        print("=" * 60)
        print("SpoonOS-Powered Autonomous Security Agent")
        print("=" * 60)
        
        # Validate environment
        if not self.validate_environment():
            return
        
        # Show dashboard
        self.show_monitoring_dashboard()
        
        # Demo interactive analysis
        print(f"\n🎮 INTERACTIVE DEMO")
        print("=" * 30)
        
        while True:
            print(f"\nChoose an action:")
            print("1. Analyze Uniswap Token (LOW risk)")
            print("2. Analyze SushiToken (MEDIUM risk)")  
            print("3. Analyze SHIBA INU (HIGH risk)")
            print("4. Generate Risk Report")
            print("5. Show Monitoring Dashboard")
            print("6. Exit Demo")
            
            try:
                choice = input("\nEnter your choice (1-6): ").strip()
                
                if choice == "1":
                    self.analyze_contract("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
                elif choice == "2":
                    self.analyze_contract("0xa0b86a33e6417a844bf5eff6c7b6cbd3ba9c3b44")
                elif choice == "3":
                    self.analyze_contract("0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce")
                elif choice == "4":
                    print("\nSelect contract for detailed report:")
                    print("1. Uniswap Token")
                    print("2. SushiToken")
                    print("3. SHIBA INU")
                    
                    report_choice = input("Enter choice (1-3): ").strip()
                    addresses = [
                        "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
                        "0xa0b86a33e6417a844bf5eff6c7b6cbd3ba9c3b44", 
                        "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce"
                    ]
                    
                    if report_choice in ["1", "2", "3"]:
                        self.generate_risk_report(addresses[int(report_choice) - 1])
                elif choice == "5":
                    self.show_monitoring_dashboard()
                elif choice == "6":
                    print("\n👋 Thank you for trying DeFi Sentinel!")
                    print("🚀 To run the full version:")
                    print("   pip install -r defi_sentinel/requirements.txt")
                    print("   python run.py agent")
                    break
                else:
                    print("❌ Invalid choice. Please enter 1-6.")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Demo stopped by user. Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")


def main():
    """Main demo entry point"""
    demo = DeFiSentinelDemo()
    demo.run_demo()


if __name__ == "__main__":
    main()
