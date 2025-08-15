#!/usr/bin/env python3
"""
DeFi Sentinel Main Agent

A SpoonOS-powered autonomous agent for continuous smart contract security monitoring.
This agent combines blockchain analysis, AI-powered vulnerability detection, and
real-time risk assessment to protect DeFi protocols.
"""

import os
import sys
import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)

# Add SpoonOS to path (if installed from source)
try:
    from spoon_ai.agents.spoon_react_mcp import SpoonReactMCP
    from spoon_ai.tools.mcp_tool import MCPTool
    from spoon_ai.tools.tool_manager import ToolManager
    from spoon_ai.chat import ChatBot
except ImportError:
    print("SpoonOS not found. Please install spoon-ai-sdk or check your Python path.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeFiSentinelAgent(SpoonReactMCP):
    """
    DeFi Sentinel Agent - Advanced smart contract security monitoring agent
    
    This agent continuously monitors blockchain networks for:
    - Smart contract vulnerabilities
    - Rugpull patterns
    - Admin privilege abuse
    - Suspicious transaction patterns
    - Liquidity manipulation
    """
    
    name: str = "DeFiSentinelAgent"
    
    system_prompt: str = """
    You are DeFi Sentinel, an advanced AI-powered security analyst specializing in smart contract 
    vulnerability detection and DeFi protocol risk assessment.

    Your primary responsibilities:
    1. ANALYZE smart contracts for security vulnerabilities and attack vectors
    2. DETECT patterns indicative of rugpulls, honeypots, and admin abuse
    3. ASSESS risk levels using comprehensive scoring algorithms
    4. GENERATE clear, actionable security reports for stakeholders
    5. MONITOR transaction patterns for suspicious activities
    6. PROVIDE real-time alerts for high-risk scenarios

    Analysis Framework:
    - Contract Security: Analyze bytecode, proxy patterns, access controls
    - Behavioral Analysis: Monitor admin actions, large transfers, liquidity changes
    - Pattern Recognition: Identify known attack vectors and suspicious behaviors
    - Risk Scoring: Generate weighted risk scores (0-100) with confidence levels
    - Market Context: Consider market conditions, protocol maturity, and historical data

    Communication Style:
    - Provide clear, concise risk assessments
    - Use technical accuracy while remaining accessible
    - Include confidence levels and evidence for all claims
    - Prioritize actionable insights over raw data
    - Escalate critical findings immediately

    Security Focus Areas:
    - Reentrancy vulnerabilities
    - Access control bypasses
    - Proxy implementation flaws
    - Oracle manipulation risks
    - MEV attack vectors
    - Liquidity drainage patterns
    - Admin key compromises
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.available_tools = ToolManager([])
        self.monitoring_contracts: Dict[str, Dict] = {}
        self.risk_thresholds = {
            'critical': 80,
            'high': 60,
            'medium': 40,
            'low': 20
        }

    async def initialize(self):
        """Initialize the DeFi Sentinel agent with all required tools"""
        logger.info("Initializing DeFi Sentinel Agent...")
        
        # Validate environment variables
        self._validate_environment()
        
        # Initialize tools
        tools = []
        
        # Web3 Analysis Tool
        web3_tool = MCPTool(
            name="web3_analyzer",
            description="Analyze smart contracts on various blockchain networks",
            mcp_config={
                "command": "python",
                "args": ["-m", "defi_sentinel.tools.web3_analyzer"],
                "env": {
                    "ETHEREUM_RPC_URL": os.getenv("ETHEREUM_RPC_URL", ""),
                    "POLYGON_RPC_URL": os.getenv("POLYGON_RPC_URL", ""),
                    "BSC_RPC_URL": os.getenv("BSC_RPC_URL", "")
                }
            }
        )
        tools.append(web3_tool)
        
        # Contract Security Scanner
        security_tool = MCPTool(
            name="security_scanner",
            description="Perform comprehensive security analysis of smart contracts",
            mcp_config={
                "command": "python",
                "args": ["-m", "defi_sentinel.tools.security_scanner"],
                "env": {"ANALYSIS_TIMEOUT": "300"}
            }
        )
        tools.append(security_tool)
        
        # Risk Assessment Tool
        risk_tool = MCPTool(
            name="risk_assessor", 
            description="Generate risk scores and assessments for DeFi protocols",
            mcp_config={
                "command": "python",
                "args": ["-m", "defi_sentinel.tools.risk_assessor"],
                "env": {"RISK_MODEL_VERSION": "v2.1"}
            }
        )
        tools.append(risk_tool)
        
        # Market Data Tool (optional)
        if os.getenv("COINGECKO_API_KEY"):
            market_tool = MCPTool(
                name="market_data",
                description="Fetch market data and on-chain metrics",
                mcp_config={
                    "command": "python",
                    "args": ["-m", "defi_sentinel.tools.market_data"],
                    "env": {"COINGECKO_API_KEY": os.getenv("COINGECKO_API_KEY")}
                }
            )
            tools.append(market_tool)
        
        # Initialize tool manager
        self.available_tools = ToolManager(tools)
        logger.info(f"Initialized DeFi Sentinel with tools: {list(self.available_tools.tool_map.keys())}")

    def _validate_environment(self):
        """Validate required environment variables"""
        required_vars = ["OPENAI_API_KEY"]
        missing_vars = []
        
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        # Validate OpenRouter API key format
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key.startswith("sk-or-"):
            logger.warning("API key doesn't appear to be an OpenRouter key. Expected format: sk-or-v1-...")

    async def monitor_contract(self, contract_address: str, chain: str = "ethereum") -> Dict[str, Any]:
        """
        Add a contract to continuous monitoring
        
        Args:
            contract_address: The contract address to monitor
            chain: The blockchain network (ethereum, polygon, bsc, etc.)
            
        Returns:
            Initial analysis results and monitoring confirmation
        """
        logger.info(f"Adding contract {contract_address} on {chain} to monitoring")
        
        # Perform initial analysis
        initial_analysis = await self.analyze_contract(contract_address, chain)
        
        # Add to monitoring list
        self.monitoring_contracts[contract_address] = {
            'chain': chain,
            'added_at': datetime.utcnow().isoformat(),
            'last_check': datetime.utcnow().isoformat(),
            'initial_risk_score': initial_analysis.get('risk_score', 0),
            'status': 'active'
        }
        
        return {
            'contract_address': contract_address,
            'chain': chain,
            'monitoring_status': 'active',
            'initial_analysis': initial_analysis
        }

    async def analyze_contract(self, contract_address: str, chain: str = "ethereum") -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a smart contract
        
        Args:
            contract_address: The contract address to analyze
            chain: The blockchain network
            
        Returns:
            Comprehensive analysis results including risk score
        """
        query = f"""
        Perform a comprehensive security analysis of the smart contract at address {contract_address} 
        on the {chain} network. Include:
        
        1. Contract verification status and source code analysis
        2. Security vulnerability assessment (reentrancy, access control, etc.)
        3. Admin privilege analysis and centralization risks
        4. Proxy pattern analysis (if applicable)
        5. Token economics and supply mechanics (if token contract)
        6. Recent transaction pattern analysis
        7. Liquidity and market analysis (if DeFi protocol)
        8. Overall risk score (0-100) with confidence level
        9. Specific recommendations and risk mitigation strategies
        
        Provide a detailed analysis with evidence for all findings.
        """
        
        logger.info(f"Analyzing contract {contract_address} on {chain}")
        analysis_result = await self.run(query)
        
        return {
            'contract_address': contract_address,
            'chain': chain,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'analysis_result': analysis_result,
            'status': 'completed'
        }

    async def generate_risk_report(self, contract_address: str, detailed: bool = True) -> Dict[str, Any]:
        """
        Generate a comprehensive risk report for a contract
        
        Args:
            contract_address: The contract address
            detailed: Whether to include detailed analysis
            
        Returns:
            Formatted risk report
        """
        query = f"""
        Generate a comprehensive risk assessment report for contract {contract_address}.
        
        {'Include detailed technical analysis, code review findings, and specific vulnerabilities.' if detailed else 'Provide a concise executive summary with key risks and recommendations.'}
        
        Report should include:
        - Executive Summary
        - Risk Score and Confidence Level
        - Key Findings and Vulnerabilities
        - Behavioral Red Flags
        - Market and Liquidity Analysis
        - Recommendations and Mitigation Strategies
        - Monitoring Recommendations
        
        Format the output as a professional security assessment report.
        """
        
        logger.info(f"Generating risk report for {contract_address}")
        report = await self.run(query)
        
        return {
            'contract_address': contract_address,
            'report_type': 'detailed' if detailed else 'summary',
            'generated_at': datetime.utcnow().isoformat(),
            'report_content': report
        }

    async def detect_rugpull_patterns(self, contract_address: str) -> Dict[str, Any]:
        """
        Specifically analyze for rugpull indicators
        
        Args:
            contract_address: The contract to analyze
            
        Returns:
            Rugpull risk assessment
        """
        query = f"""
        Analyze contract {contract_address} specifically for rugpull indicators and patterns:
        
        1. Liquidity Lock Analysis:
           - Check if liquidity is locked or can be withdrawn by admin
           - Analyze lock duration and unlock mechanisms
           
        2. Owner Privileges:
           - Assess admin functions and their potential for abuse
           - Check for pause, mint, burn, or transfer override functions
           
        3. Token Distribution:
           - Analyze token holder distribution
           - Check for concentrated ownership by deployer/team
           
        4. Trading Restrictions:
           - Look for hidden fees, blacklist functions, or trading limitations
           - Check for honeypot characteristics
           
        5. Historical Behavior:
           - Analyze past admin actions and pattern changes
           - Check for unusual large transactions or liquidity movements
           
        Provide a specific rugpull risk score (0-100) and detailed evidence.
        """
        
        logger.info(f"Analyzing rugpull patterns for {contract_address}")
        analysis = await self.run(query)
        
        return {
            'contract_address': contract_address,
            'analysis_type': 'rugpull_detection',
            'timestamp': datetime.utcnow().isoformat(),
            'analysis_result': analysis
        }

    async def continuous_monitoring(self, interval_minutes: int = 15):
        """
        Run continuous monitoring loop for all tracked contracts
        
        Args:
            interval_minutes: Monitoring interval in minutes
        """
        logger.info(f"Starting continuous monitoring with {interval_minutes} minute intervals")
        
        while True:
            try:
                for contract_address, contract_info in self.monitoring_contracts.items():
                    if contract_info['status'] == 'active':
                        logger.info(f"Checking contract {contract_address}")
                        
                        # Perform quick risk assessment
                        result = await self.analyze_contract(
                            contract_address, 
                            contract_info['chain']
                        )
                        
                        # Update last check time
                        self.monitoring_contracts[contract_address]['last_check'] = \
                            datetime.utcnow().isoformat()
                        
                        # Check for risk threshold breaches
                        # This would trigger alerts in a production system
                        
                # Wait for next interval
                await asyncio.sleep(interval_minutes * 60)
                
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status and statistics"""
        return {
            'total_contracts': len(self.monitoring_contracts),
            'active_contracts': len([c for c in self.monitoring_contracts.values() 
                                   if c['status'] == 'active']),
            'contracts': self.monitoring_contracts,
            'agent_status': 'active',
            'last_updated': datetime.utcnow().isoformat()
        }


async def main():
    """Main entry point for DeFi Sentinel Agent"""
    print("🛡️  DeFi Sentinel - Smart Contract Security Monitor")
    print("="*60)
    
    try:
        # Initialize agent with OpenRouter
        agent = DeFiSentinelAgent(
            llm=ChatBot(
                model_name="anthropic/claude-3-5-sonnet-20241022",  # Or your preferred model
                llm_provider="openai",  # Required for OpenRouter compatibility
                base_url="https://openrouter.ai/api/v1"
            )
        )
        
        print("🔧 Initializing DeFi Sentinel Agent...")
        await agent.initialize()
        print("✅ Agent initialized successfully!")
        
        # Example usage
        print("\n📋 Example Analysis:")
        print("-" * 40)
        
        # Example contract analysis (you can replace with actual contract)
        example_contract = "0xA0b86a33E6417a844bf5eff6c7b6CBd3ba9c3b44"  # Example address
        
        print(f"Analyzing contract: {example_contract}")
        result = await agent.analyze_contract(example_contract, "ethereum")
        print("Analysis completed!")
        
        print(f"\nResult: {result['analysis_result'][:500]}...")
        
        # Start monitoring (commented out for demo)
        # print("\n🔄 Starting continuous monitoring...")
        # await agent.continuous_monitoring(interval_minutes=30)
        
    except KeyboardInterrupt:
        print("\n⏹️  DeFi Sentinel stopped by user")
    except Exception as e:
        logger.error(f"Error running DeFi Sentinel: {e}")
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())