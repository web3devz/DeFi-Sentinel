# DeFi Sentinel Installation & Setup Guide

## 🚀 Quick Start

### 1. **Environment Setup**
```bash
# Clone the repository
git clone https://github.com/web3devz/DeFi-Sentinel
cd DeFi-Sentinel

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 2. **Install Core Dependencies**
```bash
# Install Python packages
pip install -r requirements.txt
```

### 3. **Configure Environment**
```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your API keys
# Required: OPENAI_API_KEY (OpenRouter API key)
```

### 4. **Run Demo**
```bash
# Test basic functionality
python demo.py
```

## 🔧 Full Installation

### SpoonOS Framework
```bash
# Install SpoonOS Core Developer Framework
pip install spoon-ai-sdk

# Or install from source
git clone https://github.com/XSpoonAi/spoon-core.git
cd spoon-core
pip install -e .
```

### Additional Dependencies
```bash
# Web3 and blockchain analysis
pip install web3 eth-abi eth-utils

# Security analysis tools
pip install slither-analyzer mythril

# API server
pip install fastapi uvicorn

# Web UI
pip install streamlit plotly

# Discord integration
pip install discord.py

# Database support
pip install sqlalchemy psycopg2-binary

# Data processing
pip install pandas numpy
```

## 🎯 Usage Examples

### CLI Interface
```bash
# Run main agent
python run.py agent

# Start API server
python run.py api

# Launch web UI
python run.py ui

# Quick contract analysis
python run.py analyze 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984

# Setup environment
python run.py setup
```

### Python API
```python
from defi_sentinel import DeFiSentinelAgent
from spoon_ai.chat import ChatBot

# Initialize agent
agent = DeFiSentinelAgent(
    llm=ChatBot(
        model_name="anthropic/claude-3-5-sonnet-20241022",
        llm_provider="openai",
        base_url="https://openrouter.ai/api/v1"
    )
)

# Initialize and analyze
await agent.initialize()
result = await agent.analyze_contract(
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
    "ethereum"
)
print(result)
```

### REST API
```bash
# Start API server
python run.py api

# Test endpoint
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -H "Authorization: Bearer demo_key_123" \
  -H "Content-Type: application/json" \
  -d '{
    "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
    "chain": "ethereum",
    "analysis_type": "comprehensive"
  }'
```

## 🌐 Web Interface

```bash
# Start web UI
python run.py ui

# Open browser to:
http://localhost:8501
```

Features:
- **Dashboard**: Real-time monitoring overview
- **Analysis**: Interactive contract analysis
- **Monitoring**: Continuous monitoring setup
- **Alerts**: Security alert management
- **API Docs**: Interactive API documentation

## ⚙️ Configuration

### Environment Variables (.env)
```bash
# Required
OPENAI_API_KEY=sk-or-v1-your-openrouter-key

# Blockchain RPCs
ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/your-key
POLYGON_RPC_URL=https://polygon-rpc.com
BSC_RPC_URL=https://bsc-dataseed.binance.org

# Optional
COINGECKO_API_KEY=your-coingecko-key
DISCORD_BOT_TOKEN=your-discord-token
DATABASE_URL=postgresql://user:pass@localhost/defi_sentinel
```

### SpoonOS Configuration (config.json)
```json
{
  "api_keys": {
    "openai": "sk-or-v1-your-openrouter-key"
  },
  "providers": {
    "openai": {
      "model": "anthropic/claude-3-5-sonnet-20241022",
      "base_url": "https://openrouter.ai/api/v1"
    }
  },
  "agents": {
    "defi_sentinel": {
      "class": "SpoonReactMCP",
      "tools": ["web3_analyzer", "security_scanner", "risk_assessor"]
    }
  }
}
```

## 🔍 Component Details

### Core Agent (`defi_sentinel/agent/main.py`)
- SpoonOS-powered autonomous agent
- Multi-LLM reasoning capabilities
- Continuous monitoring orchestration

### Analysis Tools (`defi_sentinel/tools/`)
- **Web3 Analyzer**: Blockchain interaction and contract analysis
- **Security Scanner**: Vulnerability detection and pattern matching
- **Risk Assessor**: Multi-factor risk scoring

### API Server (`defi_sentinel/api/main.py`)
- FastAPI-based REST API
- Authentication and rate limiting
- Comprehensive endpoint coverage

### Web UI (`defi_sentinel/ui/main.py`)
- Streamlit-based interactive dashboard
- Real-time monitoring and analysis
- Professional reporting interface

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Install missing dependencies
   pip install -r defi_sentinel/requirements.txt
   ```

2. **API Key Issues**
   ```bash
   # Check .env file
   cat .env | grep OPENAI_API_KEY
   
   # Ensure OpenRouter format
   # Should start with: sk-or-v1-
   ```

3. **RPC Connection Issues**
   ```bash
   # Test RPC connectivity
   curl -X POST "https://mainnet.infura.io/v3/your-key" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
   ```

4. **SpoonOS Integration**
   ```bash
   # Verify SpoonOS installation
   python -c "from spoon_ai.agents.spoon_react_mcp import SpoonReactMCP; print('OK')"
   ```

### Debug Mode
```bash
# Enable debug logging
export DEBUG_MODE=true
export LOG_LEVEL=DEBUG

# Run with verbose output
python run.py agent
```

## 📊 Performance Optimization

### Production Settings
```bash
# Environment optimizations
export MAX_CONCURRENT_ANALYSIS=10
export ENABLE_CACHING=true
export CACHE_TTL=3600

# Database connection pooling
export DB_POOL_SIZE=20
export DB_MAX_OVERFLOW=30
```

### Monitoring Setup
```bash
# Start monitoring services
docker-compose up -d redis postgresql

# Configure monitoring
export REDIS_URL=redis://localhost:6379
export DATABASE_URL=postgresql://user:pass@localhost/defi_sentinel
```

## 🚀 Deployment

### Docker Setup
```bash
# Build Docker image
docker build -t defi-sentinel .

# Run container
docker run -d \
  --name defi-sentinel \
  -p 8000:8000 \
  -p 8501:8501 \
  -e OPENAI_API_KEY=sk-or-v1-your-key \
  defi-sentinel
```

### Production Deployment
```bash
# Install production dependencies
pip install gunicorn supervisor

# Start services
supervisord -c supervisord.conf

# Configure reverse proxy (nginx)
# See nginx.conf.example
```

## 🔒 Security Considerations

1. **API Key Security**
   - Never commit API keys to version control
   - Use environment variables or secure key management
   - Rotate keys regularly

2. **RPC Endpoint Security**
   - Use authenticated RPC endpoints
   - Implement rate limiting
   - Monitor for unusual usage patterns

3. **Database Security**
   - Use strong passwords
   - Enable SSL/TLS connections
   - Regular security updates

## 📞 Support

- **Documentation**: Project Wiki
- **Issues**: GitHub Issues
- **Community**: Discord Server
- **Email**: support@defisentinel.com

## 🎯 Next Steps

1. **Try the Demo**: `python demo.py`
2. **Full Installation**: Install all dependencies
3. **Run Agent**: `python run.py agent`
4. **Explore API**: `python run.py api`
5. **Web Interface**: `python run.py ui`
6. **Customize**: Modify configurations for your needs
