#!/usr/bin/env python3
"""
DeFi Sentinel CLI Runner

Command-line interface for running different components of DeFi Sentinel.
"""

import os
import sys
import asyncio
import argparse
import logging
from pathlib import Path

# Add the parent directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import components
try:
    from defi_sentinel.agent.main import DeFiSentinelAgent, main as agent_main
    from defi_sentinel.tools.web3_analyzer import main as web3_main
    from defi_sentinel.tools.security_scanner import main as scanner_main
    from defi_sentinel.tools.risk_assessor import main as assessor_main
except ImportError as e:
    print(f"Import error: {e}")
    print("Please install required dependencies first:")
    print("pip install -r requirements.txt")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_agent():
    """Run the main DeFi Sentinel agent"""
    print("Starting DeFi Sentinel Agent...")
    asyncio.run(agent_main())


def run_api():
    """Run the API server"""
    try:
        from defi_sentinel.api.main import run_server
        print("Starting DeFi Sentinel API server...")
        asyncio.run(run_server())
    except ImportError:
        print("API dependencies not available. Please install:")
        print("pip install fastapi uvicorn")
        sys.exit(1)


def run_ui():
    """Run the web UI"""
    try:
        import streamlit.web.cli as stcli
        import sys
        
        # Get the path to the UI main file
        ui_file = Path(__file__).parent / "defi_sentinel" / "ui" / "main.py"
        
        print("Starting DeFi Sentinel Web UI...")
        print("Web interface will be available at: http://localhost:8501")
        
        # Run Streamlit
        sys.argv = ["streamlit", "run", str(ui_file)]
        stcli.main()
        
    except ImportError:
        print("UI dependencies not available. Please install:")
        print("pip install streamlit plotly")
        sys.exit(1)


def run_web3_analyzer():
    """Run Web3 analyzer tool"""
    print("Running Web3 Analyzer...")
    asyncio.run(web3_main())


def run_security_scanner():
    """Run security scanner tool"""
    print("Running Security Scanner...")
    asyncio.run(scanner_main())


def run_risk_assessor():
    """Run risk assessor tool"""
    print("Running Risk Assessor...")
    asyncio.run(assessor_main())


def setup_environment():
    """Set up the environment and check dependencies"""
    print("Setting up DeFi Sentinel environment...")
    
    # Check if .env file exists
    env_file = Path(".env")
    if not env_file.exists():
        env_example = Path(".env.example")
        if env_example.exists():
            print("Creating .env file from template...")
            import shutil
            shutil.copy(env_example, env_file)
            print("✅ .env file created. Please update it with your API keys.")
        else:
            print("❌ No .env.example file found.")
    else:
        print("✅ .env file exists.")
    
    # Check API key
    from dotenv import load_dotenv
    load_dotenv()
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ OPENAI_API_KEY not found in .env file.")
        print("Please add your OpenRouter API key to the .env file.")
        return False
    elif not api_key.startswith("sk-or-"):
        print("⚠️  API key doesn't appear to be an OpenRouter key.")
        print("Expected format: sk-or-v1-...")
    else:
        print("✅ OpenRouter API key found.")
    
    print("✅ Environment setup complete!")
    return True


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="DeFi Sentinel - Smart Contract Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py agent                    # Run the main DeFi Sentinel agent
  python run.py api                      # Start the API server
  python run.py ui                       # Launch the web interface
  python run.py setup                    # Set up environment
  python run.py analyze <address>        # Quick contract analysis
        """
    )
    
    parser.add_argument(
        "command",
        choices=["agent", "api", "ui", "web3", "scanner", "assessor", "setup", "analyze"],
        help="Component to run"
    )
    
    parser.add_argument(
        "address",
        nargs="?",
        help="Contract address (for analyze command)"
    )
    
    parser.add_argument(
        "--chain",
        default="ethereum",
        help="Blockchain network (default: ethereum)"
    )
    
    args = parser.parse_args()
    
    # Handle setup command first
    if args.command == "setup":
        setup_environment()
        return
    
    # Handle analyze command
    if args.command == "analyze":
        if not args.address:
            print("Error: Contract address required for analyze command")
            parser.print_help()
            return
        
        # Quick analysis using web3 analyzer
        print(f"Analyzing contract {args.address} on {args.chain}...")
        sys.argv = ["web3_analyzer.py", "analyze", args.address, args.chain]
        run_web3_analyzer()
        return
    
    # Route to appropriate component
    commands = {
        "agent": run_agent,
        "api": run_api,
        "ui": run_ui,
        "web3": run_web3_analyzer,
        "scanner": run_security_scanner,
        "assessor": run_risk_assessor
    }
    
    command_func = commands.get(args.command)
    if command_func:
        try:
            command_func()
        except KeyboardInterrupt:
            print("\n👋 DeFi Sentinel stopped by user")
        except Exception as e:
            logger.error(f"Error running {args.command}: {e}")
            print(f"❌ Error: {e}")
    else:
        print(f"Unknown command: {args.command}")
        parser.print_help()


if __name__ == "__main__":
    main()
