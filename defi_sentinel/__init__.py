"""
DeFi Sentinel - Smart Contract Security Monitoring Platform

A comprehensive security monitoring and risk assessment platform for DeFi protocols,
built on the SpoonOS Core Developer Framework.

Features:
- Real-time smart contract security monitoring
- AI-powered vulnerability detection
- Risk scoring and assessment
- Rugpull pattern detection
- Multi-chain support
- RESTful API for integration
- Web-based monitoring dashboard

Author: DeFi Sentinel Team
Version: 1.0.0
License: MIT
"""

__version__ = "1.0.0"
__author__ = "DeFi Sentinel Team"
__license__ = "MIT"

# Core components
from .agent.main import DeFiSentinelAgent
from .tools.web3_analyzer import Web3Analyzer
from .tools.security_scanner import SecurityScanner  
from .tools.risk_assessor import RiskAssessor

# API and UI components (optional imports)
try:
    from .api.main import app as api_app
except ImportError:
    api_app = None

try:
    from .ui.main import main as ui_main
except ImportError:
    ui_main = None

__all__ = [
    "DeFiSentinelAgent",
    "Web3Analyzer", 
    "SecurityScanner",
    "RiskAssessor",
    "api_app",
    "ui_main"
]
