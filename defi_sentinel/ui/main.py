#!/usr/bin/env python3
"""
DeFi Sentinel Web UI

Interactive web interface for smart contract security monitoring and analysis.
Built with Streamlit for real-time risk assessment and monitoring dashboard.
"""

import os
import asyncio
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

try:
    import streamlit as st
    from streamlit_autorefresh import st_autorefresh
except ImportError:
    st = None
    st_autorefresh = None

import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DeFiSentinelUI:
    """Main UI controller for DeFi Sentinel"""
    
    def __init__(self):
        self.api_base_url = os.getenv("API_BASE_URL", "http://localhost:8000")
        self.demo_data = self._load_demo_data()
    
    def _load_demo_data(self) -> Dict[str, Any]:
        """Load demo data for UI demonstration"""
        return {
            "contracts": [
                {
                    "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
                    "name": "Uniswap Token",
                    "chain": "ethereum",
                    "risk_score": 25,
                    "risk_level": "LOW",
                    "last_updated": "2024-08-16T10:30:00Z"
                },
                {
                    "address": "0xa0b86a33e6417a844bf5eff6c7b6cbd3ba9c3b44",
                    "name": "SushiToken",
                    "chain": "ethereum", 
                    "risk_score": 45,
                    "risk_level": "MEDIUM",
                    "last_updated": "2024-08-16T10:25:00Z"
                },
                {
                    "address": "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce",
                    "name": "SHIBA INU",
                    "chain": "ethereum",
                    "risk_score": 75,
                    "risk_level": "HIGH",
                    "last_updated": "2024-08-16T10:20:00Z"
                }
            ],
            "alerts": [
                {
                    "id": "alert_001",
                    "contract_address": "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce",
                    "contract_name": "SHIBA INU",
                    "alert_type": "HIGH_RISK_DETECTED",
                    "message": "Admin privilege abuse pattern detected",
                    "timestamp": "2024-08-16T10:20:00Z",
                    "severity": "HIGH"
                },
                {
                    "id": "alert_002",
                    "contract_address": "0xa0b86a33e6417a844bf5eff6c7b6cbd3ba9c3b44",
                    "contract_name": "SushiToken",
                    "alert_type": "MEDIUM_RISK_DETECTED",
                    "message": "Unusual admin activity detected",
                    "timestamp": "2024-08-16T09:45:00Z",
                    "severity": "MEDIUM"
                }
            ]
        }
    
    def run(self):
        """Main UI application"""
        if not st:
            print("Streamlit not available. Please install: pip install streamlit")
            return
        
        # Page configuration
        st.set_page_config(
            page_title="DeFi Sentinel - Smart Contract Security Monitor",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Custom CSS
        st.markdown("""
        <style>
        .main-header {
            font-size: 2.5rem;
            font-weight: bold;
            color: #1f77b4;
            text-align: center;
            margin-bottom: 2rem;
        }
        .metric-card {
            background-color: #f0f2f6;
            padding: 1rem;
            border-radius: 0.5rem;
            border-left: 4px solid #1f77b4;
        }
        .risk-high {
            color: #ff4444;
            font-weight: bold;
        }
        .risk-medium {
            color: #ff8800;
            font-weight: bold;
        }
        .risk-low {
            color: #44ff44;
            font-weight: bold;
        }
        .risk-critical {
            color: #cc0000;
            font-weight: bold;
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Header
        st.markdown('<div class="main-header">🛡️ DeFi Sentinel</div>', unsafe_allow_html=True)
        st.markdown("**Advanced Smart Contract Security Monitoring & Risk Assessment**")
        
        # Sidebar navigation
        page = st.sidebar.selectbox(
            "Navigation",
            ["Dashboard", "Analyze Contract", "Monitor Contracts", "Alerts", "API Documentation"]
        )
        
        # Auto-refresh option
        if st.sidebar.checkbox("Auto-refresh (30s)", value=False):
            st_autorefresh(interval=30000, key="auto_refresh")
        
        # Route to appropriate page
        if page == "Dashboard":
            self._render_dashboard()
        elif page == "Analyze Contract":
            self._render_analysis_page()
        elif page == "Monitor Contracts":
            self._render_monitoring_page()
        elif page == "Alerts":
            self._render_alerts_page()
        elif page == "API Documentation":
            self._render_api_docs()
    
    def _render_dashboard(self):
        """Render main dashboard"""
        st.header("📊 Security Dashboard")
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="Contracts Monitored",
                value="3",
                delta="2 new today"
            )
        
        with col2:
            st.metric(
                label="Active Alerts",
                value="2",
                delta="1 high risk"
            )
        
        with col3:
            st.metric(
                label="Average Risk Score",
                value="48/100",
                delta="-5 improved"
            )
        
        with col4:
            st.metric(
                label="Scans Today",
                value="127",
                delta="23 this hour"
            )
        
        # Risk distribution chart
        st.subheader("Risk Level Distribution")
        
        risk_data = pd.DataFrame({
            'Risk Level': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            'Count': [1, 1, 1, 0],
            'Color': ['#44ff44', '#ff8800', '#ff4444', '#cc0000']
        })
        
        fig = px.pie(
            risk_data, 
            values='Count', 
            names='Risk Level',
            color='Risk Level',
            color_discrete_map={
                'LOW': '#44ff44',
                'MEDIUM': '#ff8800', 
                'HIGH': '#ff4444',
                'CRITICAL': '#cc0000'
            }
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Recent contracts table
        st.subheader("Recently Analyzed Contracts")
        
        contracts_df = pd.DataFrame(self.demo_data["contracts"])
        contracts_df['Risk Score'] = contracts_df['risk_score']
        contracts_df['Address'] = contracts_df['address'].apply(lambda x: f"{x[:10]}...{x[-8:]}")
        contracts_df['Chain'] = contracts_df['chain'].str.title()
        contracts_df['Risk Level'] = contracts_df['risk_level']
        
        # Style the dataframe
        def highlight_risk(val):
            if val == 'HIGH':
                return 'background-color: #ffcccc'
            elif val == 'MEDIUM':
                return 'background-color: #fff4cc'
            elif val == 'LOW':
                return 'background-color: #ccffcc'
            return ''
        
        styled_df = contracts_df[['Address', 'name', 'Chain', 'Risk Score', 'Risk Level']].style.applymap(
            highlight_risk, subset=['Risk Level']
        )
        
        st.dataframe(styled_df, use_container_width=True)
        
        # Risk timeline chart
        st.subheader("Risk Score Timeline")
        
        # Generate sample timeline data
        dates = pd.date_range(start='2024-08-10', end='2024-08-16', freq='D')
        timeline_data = pd.DataFrame({
            'Date': dates,
            'Average Risk Score': [45, 42, 48, 51, 47, 45, 48],
            'High Risk Contracts': [2, 1, 2, 3, 2, 1, 1]
        })
        
        fig_timeline = px.line(
            timeline_data, 
            x='Date', 
            y='Average Risk Score',
            title="Average Risk Score Trend"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
    
    def _render_analysis_page(self):
        """Render contract analysis page"""
        st.header("🔍 Smart Contract Analysis")
        
        # Input form
        with st.form("analysis_form"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                contract_address = st.text_input(
                    "Contract Address",
                    placeholder="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"
                )
            
            with col2:
                chain = st.selectbox(
                    "Network",
                    ["ethereum", "polygon", "bsc", "arbitrum"]
                )
            
            analysis_type = st.selectbox(
                "Analysis Type",
                ["Quick Scan", "Comprehensive Analysis", "Rugpull Detection"]
            )
            
            include_market_data = st.checkbox("Include market data analysis")
            
            submit_button = st.form_submit_button("🔍 Analyze Contract")
        
        if submit_button and contract_address:
            # Show loading state
            with st.spinner("Analyzing contract... This may take a few minutes."):
                # Simulate analysis (in real implementation, call API)
                import time
                time.sleep(2)
                
                # Mock analysis results
                self._display_analysis_results(contract_address, chain, analysis_type)
    
    def _display_analysis_results(self, address: str, chain: str, analysis_type: str):
        """Display analysis results"""
        st.success("✅ Analysis completed!")
        
        # Contract info
        st.subheader("📋 Contract Information")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.info(f"**Address:** {address[:10]}...{address[-8:]}")
        with col2:
            st.info(f"**Network:** {chain.title()}")
        with col3:
            st.info(f"**Analysis:** {analysis_type}")
        
        # Risk score display
        st.subheader("⚠️ Risk Assessment")
        
        # Mock risk score based on analysis type
        if analysis_type == "Rugpull Detection":
            risk_score = 85
            risk_level = "CRITICAL"
        elif analysis_type == "Comprehensive Analysis":
            risk_score = 45
            risk_level = "MEDIUM"
        else:
            risk_score = 25
            risk_level = "LOW"
        
        # Risk gauge chart
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=risk_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Risk Score"},
            delta={'reference': 50},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 25], 'color': "lightgreen"},
                    {'range': [25, 50], 'color': "yellow"},
                    {'range': [50, 75], 'color': "orange"},
                    {'range': [75, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        st.plotly_chart(fig_gauge, use_container_width=True)
        
        # Risk level badge
        risk_color = {
            "LOW": "🟢",
            "MEDIUM": "🟡", 
            "HIGH": "🟠",
            "CRITICAL": "🔴"
        }
        
        st.markdown(f"### Risk Level: {risk_color[risk_level]} **{risk_level}**")
        
        # Detailed findings
        st.subheader("🔍 Detailed Findings")
        
        if analysis_type == "Rugpull Detection":
            st.error("🚨 **Critical Rugpull Indicators Detected**")
            findings = [
                "Unlimited minting capability detected",
                "No liquidity lock mechanism found",
                "Owner can pause trading at any time",
                "High concentration of tokens in deployer wallet"
            ]
        elif analysis_type == "Comprehensive Analysis":
            st.warning("⚠️ **Medium Risk Factors Identified**")
            findings = [
                "Admin privileges present but limited",
                "Proxy pattern detected - implementation can change",
                "No timelock on admin functions",
                "Moderate liquidity levels"
            ]
        else:
            st.success("✅ **Low Risk - Basic Issues Only**")
            findings = [
                "Standard ERC-20 implementation",
                "No critical vulnerabilities detected",
                "Owner functions limited in scope",
                "Good liquidity distribution"
            ]
        
        for finding in findings:
            st.write(f"• {finding}")
        
        # Recommendations
        st.subheader("💡 Recommendations")
        
        if risk_level == "CRITICAL":
            recommendations = [
                "🛑 **DO NOT INTERACT** with this contract",
                "High probability of rugpull or scam",
                "Monitor for any changes before considering investment",
                "Wait for independent audit and improvements"
            ]
        elif risk_level == "HIGH":
            recommendations = [
                "⚠️ **Exercise extreme caution**",
                "Only interact with small amounts",
                "Monitor admin activities closely",
                "Consider waiting for improvements"
            ]
        elif risk_level == "MEDIUM":
            recommendations = [
                "✋ **Proceed with caution**",
                "Monitor admin function usage",
                "Set up alerts for unusual activity",
                "Consider diversifying exposure"
            ]
        else:
            recommendations = [
                "✅ **Generally safe to interact**",
                "Standard monitoring recommended",
                "Good candidate for DeFi activities",
                "Continue periodic risk assessment"
            ]
        
        for rec in recommendations:
            st.write(rec)
        
        # Add to monitoring option
        if st.button("📊 Add to Monitoring"):
            st.success("✅ Contract added to continuous monitoring!")
            st.balloons()
    
    def _render_monitoring_page(self):
        """Render monitoring dashboard"""
        st.header("📊 Contract Monitoring")
        
        # Add new contract form
        with st.expander("➕ Add New Contract to Monitor"):
            with st.form("add_monitoring_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    new_address = st.text_input("Contract Address")
                    chain = st.selectbox("Network", ["ethereum", "polygon", "bsc"])
                
                with col2:
                    alert_threshold = st.slider("Alert Threshold", 0, 100, 60)
                    webhook_url = st.text_input("Webhook URL (optional)")
                
                if st.form_submit_button("Add to Monitoring"):
                    st.success(f"✅ Added {new_address[:10]}...{new_address[-8:]} to monitoring!")
        
        # Monitored contracts table
        st.subheader("📋 Monitored Contracts")
        
        # Enhanced contracts data
        contracts_data = []
        for contract in self.demo_data["contracts"]:
            contracts_data.append({
                "Address": f"{contract['address'][:10]}...{contract['address'][-8:]}",
                "Name": contract['name'],
                "Chain": contract['chain'].title(),
                "Risk Score": contract['risk_score'],
                "Risk Level": contract['risk_level'],
                "Status": "🟢 Active",
                "Last Check": "2 minutes ago",
                "Actions": "🔄 ⚙️ 🗑️"
            })
        
        df = pd.DataFrame(contracts_data)
        st.dataframe(df, use_container_width=True)
        
        # Monitoring statistics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.subheader("📈 Risk Trends")
            # Simple trend chart
            trend_data = pd.DataFrame({
                'Time': ['6h ago', '4h ago', '2h ago', 'Now'],
                'Avg Risk': [45, 47, 46, 48]
            })
            fig_trend = px.line(trend_data, x='Time', y='Avg Risk', title="Average Risk Score")
            st.plotly_chart(fig_trend, use_container_width=True)
        
        with col2:
            st.subheader("🚨 Alert Frequency")
            alert_data = pd.DataFrame({
                'Day': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                'Alerts': [2, 1, 3, 1, 2, 0, 2]
            })
            fig_alerts = px.bar(alert_data, x='Day', y='Alerts', title="Alerts This Week")
            st.plotly_chart(fig_alerts, use_container_width=True)
        
        with col3:
            st.subheader("⚡ System Health")
            st.metric("Uptime", "99.9%", "0.1%")
            st.metric("Response Time", "1.2s", "-0.3s")
            st.metric("API Status", "🟢 Healthy")
    
    def _render_alerts_page(self):
        """Render alerts dashboard"""
        st.header("🚨 Security Alerts")
        
        # Alert filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )
        
        with col2:
            time_filter = st.selectbox(
                "Time Range",
                ["Last 24 hours", "Last 7 days", "Last 30 days", "All time"]
            )
        
        with col3:
            contract_filter = st.selectbox(
                "Contract",
                ["All contracts"] + [contract["name"] for contract in self.demo_data["contracts"]]
            )
        
        # Alerts summary
        st.subheader("📊 Alert Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Alerts", "47", "12 today")
        with col2:
            st.metric("Critical", "3", "1 new")
        with col3:
            st.metric("High", "8", "2 new")
        with col4:
            st.metric("Resolved", "36", "5 today")
        
        # Recent alerts
        st.subheader("🔔 Recent Alerts")
        
        for alert in self.demo_data["alerts"]:
            severity_color = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }
            
            with st.expander(f"{severity_color[alert['severity']]} {alert['alert_type']} - {alert['contract_name']}"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.write(f"**Contract:** {alert['contract_address']}")
                    st.write(f"**Message:** {alert['message']}")
                    st.write(f"**Time:** {alert['timestamp']}")
                
                with col2:
                    st.write(f"**Severity:** {alert['severity']}")
                    if st.button(f"Acknowledge", key=f"ack_{alert['id']}"):
                        st.success("Alert acknowledged!")
                    if st.button(f"View Details", key=f"details_{alert['id']}"):
                        st.info("Opening detailed analysis...")
        
        # Alert timeline
        st.subheader("📈 Alert Timeline")
        
        timeline_data = pd.DataFrame({
            'Date': pd.date_range(start='2024-08-10', end='2024-08-16', freq='D'),
            'Critical': [0, 1, 0, 1, 0, 0, 1],
            'High': [1, 2, 1, 1, 2, 0, 1],
            'Medium': [2, 1, 3, 2, 1, 1, 2],
            'Low': [1, 1, 0, 2, 1, 0, 1]
        })
        
        fig_timeline = px.line(
            timeline_data.melt(id_vars=['Date'], var_name='Severity', value_name='Count'),
            x='Date',
            y='Count',
            color='Severity',
            title="Alert Timeline by Severity"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
    
    def _render_api_docs(self):
        """Render API documentation"""
        st.header("📚 API Documentation")
        
        st.markdown("""
        ## DeFi Sentinel API
        
        The DeFi Sentinel API provides programmatic access to our smart contract security analysis and monitoring services.
        
        ### Base URL
        ```
        https://api.defisentinel.com/v1
        ```
        
        ### Authentication
        All requests require an API key in the Authorization header:
        ```
        Authorization: Bearer YOUR_API_KEY
        ```
        
        ### Endpoints
        """)
        
        # API endpoint documentation
        endpoints = [
            {
                "method": "POST",
                "endpoint": "/analyze",
                "description": "Analyze a smart contract for security vulnerabilities",
                "example": {
                    "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
                    "chain": "ethereum",
                    "analysis_type": "comprehensive"
                }
            },
            {
                "method": "GET",
                "endpoint": "/risk-score/{address}",
                "description": "Get risk score for a specific contract",
                "example": "GET /risk-score/0x1f9840a85d5af5bf1d1762f925bdaddc4201f984?chain=ethereum"
            },
            {
                "method": "POST",
                "endpoint": "/monitor",
                "description": "Add a contract to continuous monitoring",
                "example": {
                    "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
                    "chain": "ethereum",
                    "alert_threshold": 60
                }
            },
            {
                "method": "GET",
                "endpoint": "/alerts",
                "description": "Get recent alerts for monitored contracts",
                "example": "GET /alerts?limit=50"
            }
        ]
        
        for endpoint in endpoints:
            with st.expander(f"{endpoint['method']} {endpoint['endpoint']}"):
                st.write(f"**Description:** {endpoint['description']}")
                st.code(json.dumps(endpoint['example'], indent=2), language='json')
        
        # Rate limits and pricing
        st.subheader("💳 Pricing & Rate Limits")
        
        pricing_data = pd.DataFrame({
            'Tier': ['Free', 'Premium', 'Enterprise'],
            'Daily Requests': ['100', '1,000', '10,000'],
            'Features': [
                'Basic analysis',
                'Comprehensive analysis + Monitoring',
                'All features + Priority support'
            ],
            'Price/Month': ['$0', '$49', '$199']
        })
        
        st.dataframe(pricing_data, use_container_width=True)
        
        # Code examples
        st.subheader("💻 Code Examples")
        
        st.write("**Python Example:**")
        st.code("""
import requests

# Analyze a contract
response = requests.post(
    "https://api.defisentinel.com/v1/analyze",
    headers={"Authorization": "Bearer YOUR_API_KEY"},
    json={
        "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
        "chain": "ethereum",
        "analysis_type": "comprehensive"
    }
)

result = response.json()
print(f"Risk Score: {result['data']['risk_score']}")
        """, language='python')
        
        st.write("**JavaScript Example:**")
        st.code("""
const response = await fetch('https://api.defisentinel.com/v1/analyze', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer YOUR_API_KEY',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    address: '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984',
    chain: 'ethereum',
    analysis_type: 'comprehensive'
  })
});

const result = await response.json();
console.log(`Risk Score: ${result.data.risk_score}`);
        """, language='javascript')


def main():
    """Run the Streamlit UI"""
    ui = DeFiSentinelUI()
    ui.run()


if __name__ == "__main__":
    main()
