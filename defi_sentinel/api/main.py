#!/usr/bin/env python3
"""
DeFi Sentinel FastAPI Server

RESTful API server providing comprehensive smart contract security analysis
and risk assessment services for DeFi protocols.
"""

import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import DeFi Sentinel components (would be available after installing dependencies)
try:
    from ..agent.main import DeFiSentinelAgent
    from ..tools.web3_analyzer import Web3Analyzer
    from ..tools.security_scanner import SecurityScanner
    from ..tools.risk_assessor import RiskAssessor
except ImportError:
    logger.warning("DeFi Sentinel components not available - running in standalone mode")
    DeFiSentinelAgent = None
    Web3Analyzer = None
    SecurityScanner = None
    RiskAssessor = None


# Pydantic models for API requests/responses
class ContractAnalysisRequest(BaseModel):
    """Request model for contract analysis"""
    address: str = Field(..., description="Contract address to analyze")
    chain: str = Field(default="ethereum", description="Blockchain network")
    analysis_type: str = Field(default="comprehensive", description="Type of analysis")
    include_market_data: bool = Field(default=False, description="Include market data")


class RiskScoreRequest(BaseModel):
    """Request model for risk score calculation"""
    address: str = Field(..., description="Contract address")
    chain: str = Field(default="ethereum", description="Blockchain network")


class MonitoringRequest(BaseModel):
    """Request model for adding contract to monitoring"""
    address: str = Field(..., description="Contract address to monitor")
    chain: str = Field(default="ethereum", description="Blockchain network")
    alert_threshold: int = Field(default=60, description="Risk score threshold for alerts")
    webhook_url: Optional[str] = Field(None, description="Webhook URL for alerts")


class AlertConfigRequest(BaseModel):
    """Request model for alert configuration"""
    contract_address: str = Field(..., description="Contract address")
    alert_types: List[str] = Field(..., description="Types of alerts to enable")
    threshold: int = Field(default=60, description="Alert threshold")
    webhook_url: Optional[str] = Field(None, description="Webhook URL")


class APIResponse(BaseModel):
    """Standard API response model"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: str
    request_id: Optional[str] = None


# Global state
app_state = {
    "agent": None,
    "web3_analyzer": None,
    "security_scanner": None,
    "risk_assessor": None,
    "monitoring_contracts": {},
    "rate_limits": {},
    "api_usage": {}
}


# Security and authentication
security = HTTPBearer()

# Mock API key validation (in production, use proper authentication)
VALID_API_KEYS = {
    "demo_key_123": {"tier": "free", "daily_limit": 100, "features": ["basic"]},
    "premium_key_456": {"tier": "premium", "daily_limit": 1000, "features": ["comprehensive", "monitoring", "alerts"]},
    "enterprise_key_789": {"tier": "enterprise", "daily_limit": 10000, "features": ["all"]}
}


async def validate_api_key(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    """Validate API key and return user info"""
    token = credentials.credentials
    
    if token not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    user_info = VALID_API_KEYS[token]
    
    # Check rate limits
    today = datetime.now().strftime("%Y-%m-%d")
    usage_key = f"{token}:{today}"
    
    current_usage = app_state["api_usage"].get(usage_key, 0)
    if current_usage >= user_info["daily_limit"]:
        raise HTTPException(status_code=429, detail="Daily API limit exceeded")
    
    # Increment usage
    app_state["api_usage"][usage_key] = current_usage + 1
    
    return {"api_key": token, **user_info}


# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting DeFi Sentinel API server...")
    
    # Initialize components
    if Web3Analyzer:
        app_state["web3_analyzer"] = Web3Analyzer()
        logger.info("Web3 Analyzer initialized")
    
    if SecurityScanner:
        app_state["security_scanner"] = SecurityScanner()
        logger.info("Security Scanner initialized")
    
    if RiskAssessor:
        app_state["risk_assessor"] = RiskAssessor()
        logger.info("Risk Assessor initialized")
    
    # Initialize DeFi Sentinel Agent (if available)
    if DeFiSentinelAgent:
        try:
            from spoon_ai.chat import ChatBot
            agent = DeFiSentinelAgent(
                llm=ChatBot(
                    model_name="anthropic/claude-3-5-sonnet-20241022",
                    llm_provider="openai",
                    base_url="https://openrouter.ai/api/v1"
                )
            )
            await agent.initialize()
            app_state["agent"] = agent
            logger.info("DeFi Sentinel Agent initialized")
        except Exception as e:
            logger.error(f"Failed to initialize DeFi Sentinel Agent: {e}")
    
    logger.info("DeFi Sentinel API server started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down DeFi Sentinel API server...")


# Create FastAPI app
app = FastAPI(
    title="DeFi Sentinel API",
    description="Comprehensive smart contract security monitoring and risk assessment API",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "agent": app_state["agent"] is not None,
            "web3_analyzer": app_state["web3_analyzer"] is not None,
            "security_scanner": app_state["security_scanner"] is not None,
            "risk_assessor": app_state["risk_assessor"] is not None
        }
    }


# API endpoints
@app.post("/api/v1/analyze", response_model=APIResponse)
async def analyze_contract(
    request: ContractAnalysisRequest,
    user_info: Dict[str, Any] = Depends(validate_api_key)
):
    """Analyze a smart contract for security vulnerabilities and risks"""
    try:
        if not app_state["agent"]:
            raise HTTPException(status_code=503, detail="Analysis service unavailable")
        
        # Check feature access
        if request.analysis_type == "comprehensive" and "comprehensive" not in user_info["features"]:
            raise HTTPException(status_code=403, detail="Comprehensive analysis requires premium subscription")
        
        # Perform analysis using the agent
        result = await app_state["agent"].analyze_contract(request.address, request.chain)
        
        return APIResponse(
            success=True,
            data=result,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error analyzing contract {request.address}: {e}")
        return APIResponse(
            success=False,
            error=str(e),
            timestamp=datetime.utcnow().isoformat()
        )


@app.get("/api/v1/risk-score/{address}")
async def get_risk_score(
    address: str,
    chain: str = "ethereum",
    user_info: Dict[str, Any] = Depends(validate_api_key)
):
    """Get risk score for a specific contract"""
    try:
        if not app_state["web3_analyzer"] or not app_state["risk_assessor"]:
            raise HTTPException(status_code=503, detail="Risk assessment service unavailable")
        
        # Get contract data
        contract_info = await app_state["web3_analyzer"].get_contract_info(address, chain)
        bytecode_analysis = await app_state["web3_analyzer"].analyze_bytecode(contract_info.bytecode)
        admin_analysis = await app_state["web3_analyzer"].check_admin_functions(address, chain)
        
        # Prepare contract data for risk assessment
        contract_data = {
            "address": address,
            "chain": chain,
            "bytecode_analysis": bytecode_analysis,
            "admin_analysis": admin_analysis
        }
        
        # Get security scan if available
        security_report = None
        if app_state["security_scanner"]:
            security_scan = await app_state["security_scanner"].scan_contract_security(contract_info.bytecode, address)
            security_report = {
                "vulnerabilities": [
                    {
                        "severity": vuln.severity,
                        "title": vuln.title,
                        "description": vuln.description
                    }
                    for vuln in security_scan.vulnerabilities
                ]
            }
        
        # Perform risk assessment
        risk_assessment = await app_state["risk_assessor"].assess_contract_risk(
            contract_data, security_report
        )
        
        return APIResponse(
            success=True,
            data={
                "contract_address": address,
                "chain": chain,
                "risk_score": risk_assessment.overall_risk_score,
                "risk_level": risk_assessment.risk_level,
                "confidence": risk_assessment.confidence_score,
                "summary": risk_assessment.summary,
                "assessment_timestamp": risk_assessment.assessment_timestamp
            },
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error getting risk score for {address}: {e}")
        return APIResponse(
            success=False,
            error=str(e),
            timestamp=datetime.utcnow().isoformat()
        )


@app.post("/api/v1/monitor", response_model=APIResponse)
async def add_to_monitoring(
    request: MonitoringRequest,
    background_tasks: BackgroundTasks,
    user_info: Dict[str, Any] = Depends(validate_api_key)
):
    """Add a contract to continuous monitoring"""
    try:
        # Check feature access
        if "monitoring" not in user_info["features"]:
            raise HTTPException(status_code=403, detail="Monitoring requires premium subscription")
        
        if not app_state["agent"]:
            raise HTTPException(status_code=503, detail="Monitoring service unavailable")
        
        # Add contract to monitoring
        result = await app_state["agent"].monitor_contract(request.address, request.chain)
        
        # Store monitoring configuration
        app_state["monitoring_contracts"][request.address] = {
            "chain": request.chain,
            "alert_threshold": request.alert_threshold,
            "webhook_url": request.webhook_url,
            "user_api_key": user_info["api_key"],
            "added_at": datetime.utcnow().isoformat()
        }
        
        return APIResponse(
            success=True,
            data=result,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error adding contract to monitoring: {e}")
        return APIResponse(
            success=False,
            error=str(e),
            timestamp=datetime.utcnow().isoformat()
        )


@app.get("/api/v1/monitoring")
async def get_monitoring_status(
    user_info: Dict[str, Any] = Depends(validate_api_key)
):
    """Get monitoring status for user's contracts"""
    try:
        # Filter contracts by user's API key
        user_contracts = {
            addr: info for addr, info in app_state["monitoring_contracts"].items()
            if info.get("user_api_key") == user_info["api_key"]
        }
        
        return APIResponse(
            success=True,
            data={
                "total_contracts": len(user_contracts),
                "contracts": user_contracts,
                "agent_status": "active" if app_state["agent"] else "inactive"
            },
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return APIResponse(
            success=False,
            error=str(e),
            timestamp=datetime.utcnow().isoformat()
        )


@app.post("/api/v1/detect-rugpull", response_model=APIResponse)
async def detect_rugpull(
    request: ContractAnalysisRequest,
    user_info: Dict[str, Any] = Depends(validate_api_key)
):
    """Specific rugpull detection analysis"""
    try:
        if not app_state["agent"]:
            raise HTTPException(status_code=503, detail="Rugpull detection service unavailable")
        
        # Perform rugpull analysis
        result = await app_state["agent"].detect_rugpull_patterns(request.address)
        
        return APIResponse(
            success=True,
            data=result,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error detecting rugpull patterns: {e}")
        return APIResponse(
            success=False,
            error=str(e),
            timestamp=datetime.utcnow().isoformat()
        )


@app.get("/api/v1/alerts")
async def get_alerts(
    limit: int = 50,
    user_info: Dict[str, Any] = Depends(validate_api_key)
):
    """Get recent alerts for user's monitored contracts"""
    try:
        # In a real implementation, this would fetch from a database
        # For now, return mock data
        
        alerts = [
            {
                "id": "alert_001",
                "contract_address": "0x1234567890123456789012345678901234567890",
                "alert_type": "HIGH_RISK_DETECTED",
                "risk_score": 75,
                "message": "High risk detected: Admin privilege abuse detected",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "HIGH"
            }
        ]
        
        return APIResponse(
            success=True,
            data={
                "alerts": alerts[:limit],
                "total_count": len(alerts)
            },
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return APIResponse(
            success=False,
            error=str(e),
            timestamp=datetime.utcnow().isoformat()
        )


@app.get("/api/v1/usage")
async def get_api_usage(
    user_info: Dict[str, Any] = Depends(validate_api_key)
):
    """Get API usage statistics for the user"""
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        usage_key = f"{user_info['api_key']}:{today}"
        
        current_usage = app_state["api_usage"].get(usage_key, 0)
        
        return APIResponse(
            success=True,
            data={
                "tier": user_info["tier"],
                "daily_limit": user_info["daily_limit"],
                "current_usage": current_usage,
                "remaining": user_info["daily_limit"] - current_usage,
                "features": user_info["features"],
                "date": today
            },
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error getting API usage: {e}")
        return APIResponse(
            success=False,
            error=str(e),
            timestamp=datetime.utcnow().isoformat()
        )


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "timestamp": datetime.utcnow().isoformat()
        }
    )


# Main server runner
async def run_server():
    """Run the API server"""
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(run_server())
