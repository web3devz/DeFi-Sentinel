#!/usr/bin/env python3
"""
Risk Assessor Tool

Advanced risk assessment tool that combines multiple data sources to generate
comprehensive risk scores and assessments for DeFi protocols and smart contracts.
"""

import asyncio
import json
import os
import sys
import math
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RiskFactor:
    """Individual risk factor"""
    category: str
    name: str
    score: float  # 0.0 to 1.0
    weight: float  # Weight in final calculation
    description: str
    evidence: List[str]
    confidence: float = 1.0


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment"""
    contract_address: str
    assessment_timestamp: str
    overall_risk_score: int  # 0-100
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence_score: float  # 0.0-1.0
    risk_factors: List[RiskFactor]
    recommendations: List[str]
    monitoring_suggestions: List[str]
    summary: str


class RiskAssessor:
    """Advanced risk assessor for DeFi protocols"""
    
    def __init__(self):
        self.risk_weights = self._initialize_risk_weights()
        self.risk_thresholds = {
            'CRITICAL': 80,
            'HIGH': 60,
            'MEDIUM': 40,
            'LOW': 20
        }
    
    def _initialize_risk_weights(self) -> Dict[str, float]:
        """Initialize risk factor weights"""
        return {
            # Security risks (40% total weight)
            'critical_vulnerabilities': 0.15,
            'admin_privileges': 0.10,
            'proxy_risks': 0.08,
            'external_dependencies': 0.07,
            
            # Financial risks (30% total weight)
            'liquidity_risks': 0.10,
            'tokenomics': 0.08,
            'market_manipulation': 0.07,
            'oracle_risks': 0.05,
            
            # Operational risks (20% total weight)
            'centralization': 0.08,
            'governance': 0.06,
            'team_reputation': 0.06,
            
            # Technical risks (10% total weight)
            'code_quality': 0.04,
            'audit_status': 0.03,
            'upgrade_mechanisms': 0.03
        }
    
    async def assess_contract_risk(
        self, 
        contract_data: Dict[str, Any],
        security_report: Optional[Dict[str, Any]] = None,
        market_data: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        """Perform comprehensive risk assessment"""
        
        risk_factors = []
        
        # Security risk assessment
        security_factors = await self._assess_security_risks(contract_data, security_report)
        risk_factors.extend(security_factors)
        
        # Financial risk assessment
        financial_factors = await self._assess_financial_risks(contract_data, market_data)
        risk_factors.extend(financial_factors)
        
        # Operational risk assessment
        operational_factors = await self._assess_operational_risks(contract_data)
        risk_factors.extend(operational_factors)
        
        # Technical risk assessment
        technical_factors = await self._assess_technical_risks(contract_data, security_report)
        risk_factors.extend(technical_factors)
        
        # Calculate overall risk score
        overall_score = self._calculate_overall_risk_score(risk_factors)
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(risk_factors)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_factors)
        
        # Generate monitoring suggestions
        monitoring_suggestions = self._generate_monitoring_suggestions(risk_factors)
        
        # Generate summary
        summary = self._generate_risk_summary(risk_factors, overall_score, risk_level)
        
        return RiskAssessment(
            contract_address=contract_data.get('address', ''),
            assessment_timestamp=datetime.utcnow().isoformat(),
            overall_risk_score=overall_score,
            risk_level=risk_level,
            confidence_score=confidence_score,
            risk_factors=risk_factors,
            recommendations=recommendations,
            monitoring_suggestions=monitoring_suggestions,
            summary=summary
        )
    
    async def _assess_security_risks(
        self, 
        contract_data: Dict[str, Any],
        security_report: Optional[Dict[str, Any]]
    ) -> List[RiskFactor]:
        """Assess security-related risks"""
        factors = []
        
        # Critical vulnerabilities
        if security_report:
            vulns = security_report.get('vulnerabilities', [])
            critical_vulns = [v for v in vulns if v.get('severity') == 'CRITICAL']
            high_vulns = [v for v in vulns if v.get('severity') == 'HIGH']
            
            if critical_vulns:
                score = min(1.0, len(critical_vulns) * 0.4)
                factors.append(RiskFactor(
                    category="Security",
                    name="Critical Vulnerabilities",
                    score=score,
                    weight=self.risk_weights['critical_vulnerabilities'],
                    description=f"Found {len(critical_vulns)} critical vulnerabilities",
                    evidence=[v.get('title', '') for v in critical_vulns],
                    confidence=0.9
                ))
            elif high_vulns:
                score = min(0.7, len(high_vulns) * 0.2)
                factors.append(RiskFactor(
                    category="Security",
                    name="High Severity Vulnerabilities",
                    score=score,
                    weight=self.risk_weights['critical_vulnerabilities'],
                    description=f"Found {len(high_vulns)} high severity vulnerabilities",
                    evidence=[v.get('title', '') for v in high_vulns],
                    confidence=0.8
                ))
        
        # Admin privileges assessment
        admin_analysis = contract_data.get('admin_analysis', {})
        admin_functions = admin_analysis.get('detected_admin_functions', [])
        
        if admin_functions:
            dangerous_functions = ['mint', 'burn', 'withdraw', 'emergencyWithdraw', 'pause']
            dangerous_count = len([f for f in admin_functions if f in dangerous_functions])
            
            score = min(1.0, dangerous_count * 0.3)
            factors.append(RiskFactor(
                category="Security",
                name="Admin Privileges",
                score=score,
                weight=self.risk_weights['admin_privileges'],
                description=f"Contract has {len(admin_functions)} admin functions",
                evidence=admin_functions,
                confidence=0.8
            ))
        
        # Proxy risks
        bytecode_analysis = contract_data.get('bytecode_analysis', {})
        if bytecode_analysis.get('has_proxy_pattern'):
            factors.append(RiskFactor(
                category="Security",
                name="Proxy Pattern Risk",
                score=0.6,
                weight=self.risk_weights['proxy_risks'],
                description="Contract uses proxy pattern - implementation can change",
                evidence=["Proxy pattern detected in bytecode"],
                confidence=0.9
            ))
        
        # External dependencies
        if bytecode_analysis.get('has_delegatecall'):
            factors.append(RiskFactor(
                category="Security",
                name="External Dependencies",
                score=0.5,
                weight=self.risk_weights['external_dependencies'],
                description="Contract uses delegatecall - depends on external code",
                evidence=["Delegatecall usage detected"],
                confidence=0.7
            ))
        
        return factors
    
    async def _assess_financial_risks(
        self,
        contract_data: Dict[str, Any],
        market_data: Optional[Dict[str, Any]]
    ) -> List[RiskFactor]:
        """Assess financial and economic risks"""
        factors = []
        
        # Liquidity risks
        if market_data:
            liquidity = market_data.get('liquidity', {})
            total_liquidity = liquidity.get('total_usd', 0)
            
            if total_liquidity < 100000:  # Less than $100k liquidity
                score = 0.8
                factors.append(RiskFactor(
                    category="Financial",
                    name="Low Liquidity Risk",
                    score=score,
                    weight=self.risk_weights['liquidity_risks'],
                    description=f"Low liquidity: ${total_liquidity:,.2f}",
                    evidence=[f"Total liquidity: ${total_liquidity:,.2f}"],
                    confidence=0.9
                ))
            elif total_liquidity < 1000000:  # Less than $1M liquidity
                score = 0.4
                factors.append(RiskFactor(
                    category="Financial",
                    name="Medium Liquidity Risk",
                    score=score,
                    weight=self.risk_weights['liquidity_risks'],
                    description=f"Medium liquidity: ${total_liquidity:,.2f}",
                    evidence=[f"Total liquidity: ${total_liquidity:,.2f}"],
                    confidence=0.8
                ))
        
        # Tokenomics assessment
        token_info = contract_data.get('token_info', {})
        supply_info = token_info.get('supply', {})
        
        if supply_info:
            total_supply = supply_info.get('total', 0)
            max_supply = supply_info.get('max', 0)
            
            # Check for unlimited supply
            if max_supply == 0 or max_supply > total_supply * 10:
                factors.append(RiskFactor(
                    category="Financial",
                    name="Unlimited Supply Risk",
                    score=0.6,
                    weight=self.risk_weights['tokenomics'],
                    description="Token has unlimited or very high max supply",
                    evidence=[f"Max supply: {max_supply}", f"Current supply: {total_supply}"],
                    confidence=0.8
                ))
        
        # Market manipulation risks
        admin_analysis = contract_data.get('admin_analysis', {})
        admin_functions = admin_analysis.get('detected_admin_functions', [])
        
        manipulation_functions = ['setFeeRate', 'pause', 'mint', 'burn']
        manipulation_count = len([f for f in admin_functions if f in manipulation_functions])
        
        if manipulation_count > 0:
            score = min(0.8, manipulation_count * 0.3)
            factors.append(RiskFactor(
                category="Financial",
                name="Market Manipulation Risk",
                score=score,
                weight=self.risk_weights['market_manipulation'],
                description=f"Admin can manipulate market via {manipulation_count} functions",
                evidence=[f for f in admin_functions if f in manipulation_functions],
                confidence=0.7
            ))
        
        return factors
    
    async def _assess_operational_risks(self, contract_data: Dict[str, Any]) -> List[RiskFactor]:
        """Assess operational and governance risks"""
        factors = []
        
        # Centralization risks
        admin_analysis = contract_data.get('admin_analysis', {})
        admin_functions = admin_analysis.get('detected_admin_functions', [])
        
        if len(admin_functions) > 3:
            score = min(1.0, len(admin_functions) * 0.15)
            factors.append(RiskFactor(
                category="Operational",
                name="High Centralization",
                score=score,
                weight=self.risk_weights['centralization'],
                description=f"High degree of centralization with {len(admin_functions)} admin functions",
                evidence=admin_functions,
                confidence=0.8
            ))
        
        # Governance assessment
        governance_functions = ['vote', 'propose', 'delegate', 'timelock']
        has_governance = any(func in str(admin_functions).lower() for func in governance_functions)
        
        if not has_governance and admin_functions:
            factors.append(RiskFactor(
                category="Operational", 
                name="No Governance Mechanism",
                score=0.6,
                weight=self.risk_weights['governance'],
                description="Admin functions without governance controls",
                evidence=["No governance functions detected"],
                confidence=0.7
            ))
        
        return factors
    
    async def _assess_technical_risks(
        self,
        contract_data: Dict[str, Any],
        security_report: Optional[Dict[str, Any]]
    ) -> List[RiskFactor]:
        """Assess technical and code quality risks"""
        factors = []
        
        # Code quality assessment
        bytecode_analysis = contract_data.get('bytecode_analysis', {})
        contract_size = bytecode_analysis.get('size', 0)
        
        if contract_size > 20000:  # Large contract
            factors.append(RiskFactor(
                category="Technical",
                name="Complex Contract",
                score=0.4,
                weight=self.risk_weights['code_quality'],
                description=f"Large contract size: {contract_size} bytes",
                evidence=[f"Contract size: {contract_size} bytes"],
                confidence=0.6
            ))
        
        # Audit status (would require external data)
        # For now, we'll assume no audit if no security report provided
        if not security_report:
            factors.append(RiskFactor(
                category="Technical",
                name="No Security Audit",
                score=0.5,
                weight=self.risk_weights['audit_status'],
                description="No evidence of security audit",
                evidence=["No audit report provided"],
                confidence=0.6
            ))
        
        # Upgrade mechanisms
        if bytecode_analysis.get('has_proxy_pattern'):
            factors.append(RiskFactor(
                category="Technical",
                name="Upgradeable Contract",
                score=0.5,
                weight=self.risk_weights['upgrade_mechanisms'],
                description="Contract is upgradeable - implementation can change",
                evidence=["Proxy pattern detected"],
                confidence=0.8
            ))
        
        return factors
    
    def _calculate_overall_risk_score(self, risk_factors: List[RiskFactor]) -> int:
        """Calculate weighted overall risk score"""
        if not risk_factors:
            return 0
        
        weighted_score = 0.0
        total_weight = 0.0
        
        for factor in risk_factors:
            weighted_score += factor.score * factor.weight * factor.confidence
            total_weight += factor.weight
        
        # Normalize to 0-100 scale
        if total_weight > 0:
            normalized_score = (weighted_score / total_weight) * 100
        else:
            normalized_score = 0
        
        return min(100, int(normalized_score))
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level based on score"""
        for level, threshold in sorted(self.risk_thresholds.items(), 
                                     key=lambda x: x[1], reverse=True):
            if score >= threshold:
                return level
        return "LOW"
    
    def _calculate_confidence_score(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate overall confidence in the assessment"""
        if not risk_factors:
            return 1.0
        
        confidence_sum = sum(factor.confidence for factor in risk_factors)
        return confidence_sum / len(risk_factors)
    
    def _generate_recommendations(self, risk_factors: List[RiskFactor]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Group factors by category
        security_factors = [f for f in risk_factors if f.category == "Security"]
        financial_factors = [f for f in risk_factors if f.category == "Financial"]
        operational_factors = [f for f in risk_factors if f.category == "Operational"]
        technical_factors = [f for f in risk_factors if f.category == "Technical"]
        
        # Security recommendations
        if any(f.score > 0.7 for f in security_factors):
            recommendations.append("🔒 Conduct immediate security audit focusing on critical vulnerabilities")
        
        if any("admin" in f.name.lower() for f in security_factors):
            recommendations.append("👥 Implement multi-signature wallet for admin functions")
            recommendations.append("⏰ Add timelock mechanisms for sensitive operations")
        
        # Financial recommendations
        if any(f.score > 0.6 for f in financial_factors):
            recommendations.append("💰 Increase liquidity or implement liquidity protection mechanisms")
        
        if any("supply" in f.name.lower() for f in financial_factors):
            recommendations.append("📊 Implement supply cap or governance-controlled minting")
        
        # Operational recommendations
        if any(f.score > 0.5 for f in operational_factors):
            recommendations.append("🏛️ Implement decentralized governance mechanism")
            recommendations.append("📋 Establish clear governance procedures and documentation")
        
        # Technical recommendations
        if any(f.score > 0.4 for f in technical_factors):
            recommendations.append("🔍 Complete comprehensive code audit")
            recommendations.append("📚 Publish detailed technical documentation")
        
        return recommendations
    
    def _generate_monitoring_suggestions(self, risk_factors: List[RiskFactor]) -> List[str]:
        """Generate monitoring suggestions"""
        suggestions = []
        
        high_risk_factors = [f for f in risk_factors if f.score > 0.6]
        
        if high_risk_factors:
            suggestions.append("🔄 Implement continuous monitoring with alerting")
            suggestions.append("📊 Monitor admin function usage and governance actions")
            suggestions.append("💧 Track liquidity changes and large transactions")
            suggestions.append("⚡ Set up real-time risk score updates")
        
        if any("admin" in f.name.lower() for f in risk_factors):
            suggestions.append("👀 Monitor admin wallet activities")
            suggestions.append("🚨 Alert on admin function calls")
        
        if any("liquidity" in f.name.lower() for f in risk_factors):
            suggestions.append("💹 Monitor liquidity pool health")
            suggestions.append("📈 Track token price volatility")
        
        return suggestions
    
    def _generate_risk_summary(
        self, 
        risk_factors: List[RiskFactor], 
        overall_score: int, 
        risk_level: str
    ) -> str:
        """Generate comprehensive risk summary"""
        if not risk_factors:
            return "No significant risks identified in the analysis."
        
        # Categorize factors
        categories = {}
        for factor in risk_factors:
            if factor.category not in categories:
                categories[factor.category] = []
            categories[factor.category].append(factor)
        
        # Count high-risk factors
        high_risk_count = len([f for f in risk_factors if f.score > 0.7])
        medium_risk_count = len([f for f in risk_factors if 0.4 <= f.score <= 0.7])
        
        summary_parts = [
            f"Overall Risk: {risk_level} ({overall_score}/100)",
            f"Risk Factors: {len(risk_factors)} identified"
        ]
        
        if high_risk_count > 0:
            summary_parts.append(f"High Risk: {high_risk_count} factors")
        if medium_risk_count > 0:
            summary_parts.append(f"Medium Risk: {medium_risk_count} factors")
        
        # Add category breakdown
        for category, factors in categories.items():
            avg_score = sum(f.score for f in factors) / len(factors)
            summary_parts.append(f"{category}: {avg_score:.1f}/1.0")
        
        return " | ".join(summary_parts)


# MCP Tool Interface
class MCPRiskAssessor:
    """MCP interface for risk assessor"""
    
    def __init__(self):
        self.assessor = RiskAssessor()
    
    async def handle_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP requests"""
        try:
            if method == "assess_risk":
                contract_data = params.get('contract_data', {})
                security_report = params.get('security_report')
                market_data = params.get('market_data')
                
                if not contract_data:
                    return {"error": "Contract data parameter required"}
                
                assessment = await self.assessor.assess_contract_risk(
                    contract_data, security_report, market_data
                )
                
                return {
                    "risk_assessment": {
                        "contract_address": assessment.contract_address,
                        "assessment_timestamp": assessment.assessment_timestamp,
                        "overall_risk_score": assessment.overall_risk_score,
                        "risk_level": assessment.risk_level,
                        "confidence_score": assessment.confidence_score,
                        "risk_factors": [
                            {
                                "category": factor.category,
                                "name": factor.name,
                                "score": factor.score,
                                "weight": factor.weight,
                                "description": factor.description,
                                "evidence": factor.evidence,
                                "confidence": factor.confidence
                            }
                            for factor in assessment.risk_factors
                        ],
                        "recommendations": assessment.recommendations,
                        "monitoring_suggestions": assessment.monitoring_suggestions,
                        "summary": assessment.summary
                    },
                    "status": "success"
                }
            
            elif method == "quick_risk_score":
                contract_data = params.get('contract_data', {})
                
                # Quick risk score based on basic factors
                admin_functions = contract_data.get('admin_analysis', {}).get('detected_admin_functions', [])
                bytecode_analysis = contract_data.get('bytecode_analysis', {})
                
                risk_score = 0
                
                # Admin privileges (0-40 points)
                dangerous_functions = ['mint', 'burn', 'withdraw', 'emergencyWithdraw', 'pause']
                dangerous_count = len([f for f in admin_functions if f in dangerous_functions])
                risk_score += min(40, dangerous_count * 15)
                
                # Security flags (0-30 points)
                security_flags = bytecode_analysis.get('security_flags', [])
                risk_score += min(30, len(security_flags) * 10)
                
                # Proxy pattern (0-20 points)
                if bytecode_analysis.get('has_proxy_pattern'):
                    risk_score += 20
                
                # Contract size (0-10 points)
                size = bytecode_analysis.get('size', 0)
                if size > 20000:
                    risk_score += 10
                
                return {
                    "quick_risk_assessment": {
                        "risk_score": min(100, risk_score),
                        "risk_level": "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW",
                        "factors_considered": [
                            f"Admin functions: {len(admin_functions)}",
                            f"Security flags: {len(security_flags)}",
                            f"Proxy pattern: {bytecode_analysis.get('has_proxy_pattern', False)}",
                            f"Contract size: {size} bytes"
                        ]
                    },
                    "status": "success"
                }
            
            else:
                return {"error": f"Unknown method: {method}"}
                
        except Exception as e:
            logger.error(f"Error handling request {method}: {e}")
            return {"error": str(e), "status": "error"}


async def main():
    """Main function for running as MCP tool"""
    mcp_assessor = MCPRiskAssessor()
    
    # Simple CLI interface for testing
    if len(sys.argv) > 1:
        if sys.argv[1] == "assess":
            # Sample contract data for testing
            contract_data = {
                "address": "0x1234567890123456789012345678901234567890",
                "admin_analysis": {
                    "detected_admin_functions": ["owner", "mint", "pause", "withdraw"]
                },
                "bytecode_analysis": {
                    "size": 15000,
                    "has_proxy_pattern": True,
                    "security_flags": ["DELEGATECALL_PRESENT"]
                }
            }
            
            result = await mcp_assessor.handle_request("assess_risk", {
                "contract_data": contract_data
            })
            
            print(json.dumps(result, indent=2))
    else:
        print("Risk Assessor Tool - MCP Mode")
        print("Usage: python risk_assessor.py assess")


if __name__ == "__main__":
    asyncio.run(main())
