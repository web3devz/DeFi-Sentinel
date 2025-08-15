#!/usr/bin/env python3
"""
Security Scanner Tool

Advanced security analysis tool for smart contracts using static analysis,
pattern recognition, and heuristic checks for common vulnerabilities.
"""

import asyncio
import json
import os
import sys
import re
import hashlib
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Vulnerability finding structure"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    location: Optional[str] = None
    recommendation: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0


@dataclass
class SecurityReport:
    """Security analysis report"""
    contract_address: str
    scan_timestamp: str
    vulnerabilities: List[Vulnerability]
    risk_score: int  # 0-100
    confidence_score: float  # 0.0-1.0
    summary: str


class SecurityScanner:
    """Advanced security scanner for smart contracts"""
    
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.admin_abuse_patterns = self._load_admin_patterns()
        self.rugpull_indicators = self._load_rugpull_patterns()
    
    def _load_vulnerability_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load common vulnerability patterns"""
        return {
            'reentrancy': {
                'bytecode_patterns': [
                    '3d602d80600a3d3981f3363d3d373d3d3d363d73',  # Proxy pattern
                    'f1',  # CALL opcode
                    'fa',  # STATICCALL
                ],
                'severity': 'HIGH',
                'description': 'Potential reentrancy vulnerability detected',
                'confidence': 0.7
            },
            'selfdestruct': {
                'bytecode_patterns': ['ff'],  # SELFDESTRUCT opcode
                'severity': 'HIGH',
                'description': 'Contract contains selfdestruct functionality',
                'confidence': 0.9
            },
            'delegatecall': {
                'bytecode_patterns': ['f4'],  # DELEGATECALL opcode
                'severity': 'MEDIUM',
                'description': 'Contract uses delegatecall - potential proxy vulnerability',
                'confidence': 0.8
            },
            'unchecked_external_call': {
                'bytecode_patterns': ['f1', 'f2', 'f4'],  # CALL, CALLCODE, DELEGATECALL
                'severity': 'MEDIUM',
                'description': 'External calls without proper checks detected',
                'confidence': 0.6
            },
            'integer_overflow': {
                'bytecode_patterns': ['01', '02', '03', '04'],  # ADD, MUL, SUB, DIV
                'severity': 'MEDIUM',
                'description': 'Potential integer overflow/underflow vulnerability',
                'confidence': 0.5
            }
        }
    
    def _load_admin_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load admin abuse patterns"""
        return {
            'centralized_control': {
                'function_signatures': [
                    '8da5cb5b',  # owner()
                    'f2fde38b',  # transferOwnership(address)
                    'ab2f7269',  # setFeeRate(uint256)
                    '8456cb59',  # pause()
                    '3f4ba83a',  # unpause()
                ],
                'severity': 'HIGH',
                'description': 'High degree of centralized control detected'
            },
            'dangerous_admin_functions': {
                'function_signatures': [
                    '40c10f19',  # mint(address,uint256)
                    '42966c68',  # burn(uint256)
                    '3ccfd60b',  # withdraw()
                    '5312ea8e',  # emergencyWithdraw()
                    'a9059cbb',  # transfer(address,uint256)
                ],
                'severity': 'HIGH',
                'description': 'Dangerous admin functions that could be abused'
            },
            'no_timelock': {
                'function_signatures': ['8da5cb5b'],  # Check if owner exists
                'severity': 'MEDIUM',
                'description': 'Admin functions without timelock protection'
            }
        }
    
    def _load_rugpull_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load rugpull indicator patterns"""
        return {
            'liquidity_drain': {
                'function_signatures': [
                    '3ccfd60b',  # withdraw()
                    '5312ea8e',  # emergencyWithdraw()
                    'e941fa78',  # withdrawEth()
                ],
                'severity': 'CRITICAL',
                'description': 'Functions that can drain liquidity'
            },
            'unlimited_minting': {
                'function_signatures': ['40c10f19'],  # mint(address,uint256)
                'severity': 'CRITICAL',
                'description': 'Unlimited token minting capability'
            },
            'trading_restrictions': {
                'function_signatures': [
                    '8456cb59',  # pause()
                    '9f5f7f1e',  # setMaxTx(uint256)
                    'dd62ed3e',  # allowance(address,address)
                ],
                'severity': 'HIGH',
                'description': 'Functions that can restrict trading'
            },
            'hidden_fees': {
                'function_signatures': [
                    'ab2f7269',  # setFeeRate(uint256)
                    '30ff2243',  # setTaxFee(uint256)
                    '2d838119',  # setLiquidityFee(uint256)
                ],
                'severity': 'HIGH',
                'description': 'Hidden or adjustable fee mechanisms'
            }
        }
    
    async def scan_contract_security(self, bytecode: str, address: str = "") -> SecurityReport:
        """Perform comprehensive security scan"""
        vulnerabilities = []
        
        # Basic bytecode validation
        if not bytecode or bytecode == '0x':
            return SecurityReport(
                contract_address=address,
                scan_timestamp=datetime.utcnow().isoformat(),
                vulnerabilities=[Vulnerability(
                    severity="INFO",
                    title="No Bytecode",
                    description="Contract has no bytecode - likely an EOA or destroyed contract"
                )],
                risk_score=0,
                confidence_score=1.0,
                summary="No bytecode found for analysis"
            )
        
        # Scan for vulnerability patterns
        vulnerabilities.extend(await self._scan_vulnerability_patterns(bytecode))
        
        # Scan for admin abuse patterns
        vulnerabilities.extend(await self._scan_admin_patterns(bytecode))
        
        # Scan for rugpull indicators
        vulnerabilities.extend(await self._scan_rugpull_patterns(bytecode))
        
        # Analyze contract structure
        vulnerabilities.extend(await self._analyze_contract_structure(bytecode))
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Calculate overall confidence
        confidence_score = self._calculate_confidence_score(vulnerabilities)
        
        # Generate summary
        summary = self._generate_summary(vulnerabilities, risk_score)
        
        return SecurityReport(
            contract_address=address,
            scan_timestamp=datetime.utcnow().isoformat(),
            vulnerabilities=vulnerabilities,
            risk_score=risk_score,
            confidence_score=confidence_score,
            summary=summary
        )
    
    async def _scan_vulnerability_patterns(self, bytecode: str) -> List[Vulnerability]:
        """Scan for common vulnerability patterns"""
        vulnerabilities = []
        bytecode_lower = bytecode.lower()
        
        for vuln_name, pattern_info in self.vulnerability_patterns.items():
            patterns = pattern_info['bytecode_patterns']
            found_patterns = []
            
            for pattern in patterns:
                if pattern in bytecode_lower:
                    found_patterns.append(pattern)
            
            if found_patterns:
                vuln = Vulnerability(
                    severity=pattern_info['severity'],
                    title=f"{vuln_name.replace('_', ' ').title()} Detected",
                    description=pattern_info['description'],
                    location=f"Bytecode patterns: {found_patterns}",
                    confidence=pattern_info['confidence'],
                    recommendation=self._get_vulnerability_recommendation(vuln_name)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _scan_admin_patterns(self, bytecode: str) -> List[Vulnerability]:
        """Scan for admin abuse patterns"""
        vulnerabilities = []
        bytecode_lower = bytecode.lower()
        
        # Extract function signatures
        function_signatures = self._extract_function_signatures(bytecode_lower)
        
        for pattern_name, pattern_info in self.admin_abuse_patterns.items():
            matching_functions = []
            
            for sig in pattern_info['function_signatures']:
                if sig in function_signatures:
                    matching_functions.append(sig)
            
            if matching_functions:
                vuln = Vulnerability(
                    severity=pattern_info['severity'],
                    title=f"Admin Pattern: {pattern_name.replace('_', ' ').title()}",
                    description=pattern_info['description'],
                    location=f"Function signatures: {matching_functions}",
                    confidence=0.8,
                    recommendation=self._get_admin_recommendation(pattern_name)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _scan_rugpull_patterns(self, bytecode: str) -> List[Vulnerability]:
        """Scan for rugpull indicators"""
        vulnerabilities = []
        bytecode_lower = bytecode.lower()
        
        # Extract function signatures
        function_signatures = self._extract_function_signatures(bytecode_lower)
        
        for pattern_name, pattern_info in self.rugpull_indicators.items():
            matching_functions = []
            
            for sig in pattern_info['function_signatures']:
                if sig in function_signatures:
                    matching_functions.append(sig)
            
            if matching_functions:
                vuln = Vulnerability(
                    severity=pattern_info['severity'],
                    title=f"Rugpull Risk: {pattern_name.replace('_', ' ').title()}",
                    description=pattern_info['description'],
                    location=f"Function signatures: {matching_functions}",
                    confidence=0.9,
                    recommendation=self._get_rugpull_recommendation(pattern_name)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _analyze_contract_structure(self, bytecode: str) -> List[Vulnerability]:
        """Analyze contract structure for additional risks"""
        vulnerabilities = []
        bytecode_lower = bytecode.lower()
        
        # Check contract size
        size = len(bytecode) // 2 - 1  # Remove '0x' and convert to bytes
        if size > 24576:  # Ethereum contract size limit
            vulnerabilities.append(Vulnerability(
                severity="HIGH",
                title="Contract Size Exceeds Limit",
                description=f"Contract size ({size} bytes) exceeds Ethereum limit",
                confidence=1.0
            ))
        elif size > 20000:
            vulnerabilities.append(Vulnerability(
                severity="MEDIUM",
                title="Large Contract Size",
                description=f"Contract is unusually large ({size} bytes)",
                confidence=0.8
            ))
        
        # Check for proxy patterns
        proxy_patterns = [
            '3d602d80600a3d3981f3363d3d373d3d3d363d73',  # EIP-1167 minimal proxy
            '363d3d373d3d3d363d73',  # Another proxy pattern
        ]
        
        for pattern in proxy_patterns:
            if pattern in bytecode_lower:
                vulnerabilities.append(Vulnerability(
                    severity="MEDIUM",
                    title="Proxy Contract Detected",
                    description="Contract appears to be a proxy - implementation may change",
                    confidence=0.9,
                    recommendation="Verify proxy implementation and upgrade mechanisms"
                ))
                break
        
        # Check for unusual opcode patterns
        if 'invalid' in bytecode_lower or 'fe' in bytecode_lower:
            vulnerabilities.append(Vulnerability(
                severity="LOW",
                title="Invalid Opcode Present",
                description="Contract contains INVALID opcode - may be intentional",
                confidence=0.6
            ))
        
        return vulnerabilities
    
    def _extract_function_signatures(self, bytecode: str) -> List[str]:
        """Extract function signatures from bytecode"""
        signatures = set()
        
        # Look for PUSH4 operations (0x63) followed by 4-byte signatures
        i = 0
        while i < len(bytecode) - 10:
            if bytecode[i:i+2] == '63':  # PUSH4 opcode
                sig = bytecode[i+2:i+10]
                if len(sig) == 8 and all(c in '0123456789abcdef' for c in sig):
                    signatures.add(sig)
            i += 2
        
        return list(signatures)
    
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """Calculate overall risk score (0-100)"""
        if not vulnerabilities:
            return 0
        
        severity_weights = {
            'CRITICAL': 40,
            'HIGH': 25,
            'MEDIUM': 15,
            'LOW': 5,
            'INFO': 1
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            weight = severity_weights.get(vuln.severity, 1)
            confidence_multiplier = vuln.confidence
            total_score += weight * confidence_multiplier
        
        # Normalize to 0-100 scale
        max_possible_score = len(vulnerabilities) * 40  # All CRITICAL
        normalized_score = min(100, int((total_score / max_possible_score) * 100)) if max_possible_score > 0 else 0
        
        return normalized_score
    
    def _calculate_confidence_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall confidence score"""
        if not vulnerabilities:
            return 1.0
        
        confidence_sum = sum(vuln.confidence for vuln in vulnerabilities)
        return confidence_sum / len(vulnerabilities)
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability], risk_score: int) -> str:
        """Generate security analysis summary"""
        if not vulnerabilities:
            return "No security issues detected in the analysis."
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        risk_level = "LOW"
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        
        summary_parts = [
            f"Risk Level: {risk_level} (Score: {risk_score}/100)",
            f"Total Issues: {len(vulnerabilities)}"
        ]
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                summary_parts.append(f"{severity}: {count}")
        
        return " | ".join(summary_parts)
    
    def _get_vulnerability_recommendation(self, vuln_name: str) -> str:
        """Get recommendation for vulnerability"""
        recommendations = {
            'reentrancy': "Use checks-effects-interactions pattern and reentrancy guards",
            'selfdestruct': "Remove selfdestruct or add proper access controls",
            'delegatecall': "Validate delegatecall targets and implement proper proxy patterns",
            'unchecked_external_call': "Check return values of external calls",
            'integer_overflow': "Use SafeMath library or Solidity 0.8+ overflow protection"
        }
        return recommendations.get(vuln_name, "Review and test this functionality thoroughly")
    
    def _get_admin_recommendation(self, pattern_name: str) -> str:
        """Get recommendation for admin pattern"""
        recommendations = {
            'centralized_control': "Consider decentralizing control or implementing multisig",
            'dangerous_admin_functions': "Implement timelock and governance mechanisms",
            'no_timelock': "Add timelock delays for sensitive admin functions"
        }
        return recommendations.get(pattern_name, "Review admin privileges and add appropriate safeguards")
    
    def _get_rugpull_recommendation(self, pattern_name: str) -> str:
        """Get recommendation for rugpull pattern"""
        recommendations = {
            'liquidity_drain': "Lock liquidity or implement withdrawal limits",
            'unlimited_minting': "Set mint caps or implement governance-controlled minting",
            'trading_restrictions': "Make trading controls transparent and time-limited",
            'hidden_fees': "Make all fees transparent and limit admin control over fees"
        }
        return recommendations.get(pattern_name, "Increase transparency and reduce admin control")


# MCP Tool Interface
class MCPSecurityScanner:
    """MCP interface for security scanner"""
    
    def __init__(self):
        self.scanner = SecurityScanner()
    
    async def handle_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP requests"""
        try:
            if method == "scan_security":
                bytecode = params.get('bytecode')
                address = params.get('address', '')
                
                if not bytecode:
                    return {"error": "Bytecode parameter required"}
                
                report = await self.scanner.scan_contract_security(bytecode, address)
                
                return {
                    "scan_report": {
                        "contract_address": report.contract_address,
                        "scan_timestamp": report.scan_timestamp,
                        "risk_score": report.risk_score,
                        "confidence_score": report.confidence_score,
                        "summary": report.summary,
                        "vulnerabilities": [
                            {
                                "severity": vuln.severity,
                                "title": vuln.title,
                                "description": vuln.description,
                                "location": vuln.location,
                                "recommendation": vuln.recommendation,
                                "confidence": vuln.confidence
                            }
                            for vuln in report.vulnerabilities
                        ]
                    },
                    "status": "success"
                }
            
            elif method == "quick_risk_assessment":
                bytecode = params.get('bytecode')
                
                if not bytecode:
                    return {"error": "Bytecode parameter required"}
                
                # Quick assessment focusing on critical issues
                critical_patterns = ['ff', 'f4', '40c10f19', '3ccfd60b']
                found_critical = []
                
                for pattern in critical_patterns:
                    if pattern in bytecode.lower():
                        found_critical.append(pattern)
                
                risk_level = "HIGH" if found_critical else "LOW"
                
                return {
                    "quick_assessment": {
                        "risk_level": risk_level,
                        "critical_patterns_found": found_critical,
                        "requires_full_scan": bool(found_critical)
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
    mcp_scanner = MCPSecurityScanner()
    
    # Simple CLI interface for testing
    if len(sys.argv) > 1:
        if sys.argv[1] == "scan":
            bytecode = sys.argv[2] if len(sys.argv) > 2 else "0x"
            address = sys.argv[3] if len(sys.argv) > 3 else "0x0000000000000000000000000000000000000000"
            
            result = await mcp_scanner.handle_request("scan_security", {
                "bytecode": bytecode,
                "address": address
            })
            
            print(json.dumps(result, indent=2))
    else:
        print("Security Scanner Tool - MCP Mode")
        print("Usage: python security_scanner.py scan <bytecode> [address]")


if __name__ == "__main__":
    asyncio.run(main())
