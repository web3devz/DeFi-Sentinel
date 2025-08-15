#!/usr/bin/env python3
"""
Web3 Analyzer Tool

MCP tool for analyzing smart contracts on various blockchain networks.
Provides contract information, bytecode analysis, and transaction monitoring.
"""

import asyncio
import json
import os
import sys
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from web3 import Web3
from eth_utils import is_address, to_checksum_address
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ContractInfo:
    """Contract information structure"""
    address: str
    chain: str
    bytecode: str
    is_verified: bool
    creation_block: Optional[int] = None
    creation_tx: Optional[str] = None
    balance: Optional[str] = None
    transaction_count: Optional[int] = None


class Web3Analyzer:
    """Web3 analyzer for smart contract analysis"""
    
    def __init__(self):
        self.networks = {
            'ethereum': os.getenv('ETHEREUM_RPC_URL', 'https://mainnet.infura.io/v3/'),
            'polygon': os.getenv('POLYGON_RPC_URL', 'https://polygon-rpc.com'),
            'bsc': os.getenv('BSC_RPC_URL', 'https://bsc-dataseed.binance.org')
        }
        self.web3_instances = {}
        self._initialize_connections()
    
    def _initialize_connections(self):
        """Initialize Web3 connections for all networks"""
        for network, rpc_url in self.networks.items():
            if rpc_url and not rpc_url.endswith('/'):
                try:
                    w3 = Web3(Web3.HTTPProvider(rpc_url))
                    if w3.is_connected():
                        self.web3_instances[network] = w3
                        logger.info(f"Connected to {network} network")
                    else:
                        logger.warning(f"Failed to connect to {network}")
                except Exception as e:
                    logger.error(f"Error connecting to {network}: {e}")
    
    async def get_contract_info(self, address: str, chain: str = 'ethereum') -> ContractInfo:
        """Get basic contract information"""
        if chain not in self.web3_instances:
            raise ValueError(f"Network {chain} not available")
        
        w3 = self.web3_instances[chain]
        
        if not is_address(address):
            raise ValueError(f"Invalid address: {address}")
        
        address = to_checksum_address(address)
        
        # Get bytecode
        bytecode = w3.eth.get_code(address).hex()
        
        # Get balance
        balance = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance, 'ether')
        
        # Get transaction count
        tx_count = w3.eth.get_transaction_count(address)
        
        # Check if contract exists
        is_contract = len(bytecode) > 2  # More than '0x'
        
        return ContractInfo(
            address=address,
            chain=chain,
            bytecode=bytecode,
            is_verified=False,  # Would need additional API calls to check
            balance=str(balance_eth),
            transaction_count=tx_count
        )
    
    async def analyze_bytecode(self, bytecode: str) -> Dict[str, Any]:
        """Analyze contract bytecode for security patterns"""
        analysis = {
            'size': len(bytecode) // 2 - 1,  # Remove '0x' and convert to bytes
            'has_selfdestruct': False,
            'has_delegatecall': False,
            'has_proxy_pattern': False,
            'function_signatures': [],
            'security_flags': []
        }
        
        if not bytecode or bytecode == '0x':
            return analysis
        
        bytecode_lower = bytecode.lower()
        
        # Check for dangerous opcodes
        if 'ff' in bytecode_lower:  # SELFDESTRUCT
            analysis['has_selfdestruct'] = True
            analysis['security_flags'].append('SELFDESTRUCT_PRESENT')
        
        if 'f4' in bytecode_lower:  # DELEGATECALL
            analysis['has_delegatecall'] = True
            analysis['security_flags'].append('DELEGATECALL_PRESENT')
        
        # Check for proxy patterns
        proxy_indicators = ['3d602d80600a3d3981f3363d3d373d3d3d363d73', '363d3d373d3d3d363d73']
        for indicator in proxy_indicators:
            if indicator in bytecode_lower:
                analysis['has_proxy_pattern'] = True
                analysis['security_flags'].append('PROXY_PATTERN_DETECTED')
                break
        
        # Extract function signatures (first 4 bytes of function calls)
        # This is a simplified extraction
        function_sigs = set()
        for i in range(0, len(bytecode_lower), 2):
            if i + 8 <= len(bytecode_lower):
                potential_sig = bytecode_lower[i:i+8]
                if potential_sig.startswith('63'):  # PUSH4 opcode
                    function_sigs.add(potential_sig[2:])
        
        analysis['function_signatures'] = list(function_sigs)[:20]  # Limit output
        
        return analysis
    
    async def get_recent_transactions(self, address: str, chain: str = 'ethereum', limit: int = 10) -> List[Dict]:
        """Get recent transactions for an address"""
        if chain not in self.web3_instances:
            raise ValueError(f"Network {chain} not available")
        
        w3 = self.web3_instances[chain]
        address = to_checksum_address(address)
        
        # Get current block number
        current_block = w3.eth.block_number
        
        transactions = []
        blocks_to_check = min(1000, current_block)  # Check last 1000 blocks max
        
        for block_num in range(current_block, current_block - blocks_to_check, -1):
            try:
                block = w3.eth.get_block(block_num, full_transactions=True)
                for tx in block.transactions:
                    if tx['to'] == address or tx['from'] == address:
                        transactions.append({
                            'hash': tx['hash'].hex(),
                            'from': tx['from'],
                            'to': tx['to'],
                            'value': str(w3.from_wei(tx['value'], 'ether')),
                            'gas': tx['gas'],
                            'gas_price': str(w3.from_wei(tx['gasPrice'], 'gwei')),
                            'block_number': block_num,
                            'timestamp': block['timestamp']
                        })
                        
                        if len(transactions) >= limit:
                            return transactions
            except Exception as e:
                logger.warning(f"Error fetching block {block_num}: {e}")
                continue
        
        return transactions
    
    async def check_admin_functions(self, address: str, chain: str = 'ethereum') -> Dict[str, Any]:
        """Check for common admin/owner functions"""
        admin_functions = {
            'owner': '8da5cb5b',
            'transferOwnership': 'f2fde38b', 
            'pause': '8456cb59',
            'unpause': '3f4ba83a',
            'mint': '40c10f19',
            'burn': '42966c68',
            'setFeeRate': 'ab2f7269',
            'withdraw': '3ccfd60b',
            'emergencyWithdraw': '5312ea8e'
        }
        
        contract_info = await self.get_contract_info(address, chain)
        bytecode_analysis = await self.analyze_bytecode(contract_info.bytecode)
        
        detected_functions = []
        for func_name, signature in admin_functions.items():
            if signature in bytecode_analysis['function_signatures']:
                detected_functions.append(func_name)
        
        return {
            'detected_admin_functions': detected_functions,
            'risk_level': self._assess_admin_risk(detected_functions),
            'total_functions': len(bytecode_analysis['function_signatures'])
        }
    
    def _assess_admin_risk(self, functions: List[str]) -> str:
        """Assess risk level based on admin functions"""
        high_risk_functions = {'transferOwnership', 'pause', 'mint', 'burn', 'emergencyWithdraw'}
        medium_risk_functions = {'setFeeRate', 'withdraw'}
        
        high_risk_count = len(set(functions) & high_risk_functions)
        medium_risk_count = len(set(functions) & medium_risk_functions)
        
        if high_risk_count >= 2:
            return 'HIGH'
        elif high_risk_count >= 1 or medium_risk_count >= 2:
            return 'MEDIUM'
        elif medium_risk_count >= 1:
            return 'LOW'
        else:
            return 'MINIMAL'


# MCP Tool Interface
class MCPWeb3Analyzer:
    """MCP interface for Web3 analyzer"""
    
    def __init__(self):
        self.analyzer = Web3Analyzer()
    
    async def handle_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP requests"""
        try:
            if method == "analyze_contract":
                address = params.get('address')
                chain = params.get('chain', 'ethereum')
                
                if not address:
                    return {"error": "Address parameter required"}
                
                # Get contract info
                contract_info = await self.analyzer.get_contract_info(address, chain)
                
                # Analyze bytecode
                bytecode_analysis = await self.analyzer.analyze_bytecode(contract_info.bytecode)
                
                # Check admin functions
                admin_analysis = await self.analyzer.check_admin_functions(address, chain)
                
                # Get recent transactions
                recent_txs = await self.analyzer.get_recent_transactions(address, chain, limit=5)
                
                return {
                    "contract_info": {
                        "address": contract_info.address,
                        "chain": contract_info.chain,
                        "balance": contract_info.balance,
                        "transaction_count": contract_info.transaction_count,
                        "is_contract": len(contract_info.bytecode) > 2
                    },
                    "bytecode_analysis": bytecode_analysis,
                    "admin_analysis": admin_analysis,
                    "recent_transactions": recent_txs,
                    "status": "success"
                }
            
            elif method == "get_contract_bytecode":
                address = params.get('address')
                chain = params.get('chain', 'ethereum')
                
                contract_info = await self.analyzer.get_contract_info(address, chain)
                bytecode_analysis = await self.analyzer.analyze_bytecode(contract_info.bytecode)
                
                return {
                    "address": address,
                    "chain": chain,
                    "bytecode": contract_info.bytecode,
                    "analysis": bytecode_analysis,
                    "status": "success"
                }
            
            elif method == "check_admin_privileges":
                address = params.get('address')
                chain = params.get('chain', 'ethereum')
                
                admin_analysis = await self.analyzer.check_admin_functions(address, chain)
                
                return {
                    "address": address,
                    "chain": chain,
                    "admin_analysis": admin_analysis,
                    "status": "success"
                }
            
            else:
                return {"error": f"Unknown method: {method}"}
                
        except Exception as e:
            logger.error(f"Error handling request {method}: {e}")
            return {"error": str(e), "status": "error"}


async def main():
    """Main function for running as MCP tool"""
    mcp_analyzer = MCPWeb3Analyzer()
    
    # Simple CLI interface for testing
    if len(sys.argv) > 1:
        if sys.argv[1] == "analyze":
            address = sys.argv[2] if len(sys.argv) > 2 else "0xA0b86a33E6417a844bf5eff6c7b6CBd3ba9c3b44"
            chain = sys.argv[3] if len(sys.argv) > 3 else "ethereum"
            
            result = await mcp_analyzer.handle_request("analyze_contract", {
                "address": address,
                "chain": chain
            })
            
            print(json.dumps(result, indent=2))
    else:
        print("Web3 Analyzer Tool - MCP Mode")
        print("Usage: python web3_analyzer.py analyze <address> [chain]")


if __name__ == "__main__":
    asyncio.run(main())
