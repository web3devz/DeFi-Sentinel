# DeFi Sentinel

**🛡️ Autonomous Smart Contract Security Monitoring Platform**

DeFi Sentinel is a comprehensive security monitoring and risk assessment platform for DeFi protocols, built on the SpoonOS Core Developer Framework. It provides real-time monitoring, AI-powered analysis, and automated risk assessment for smart contracts across multiple blockchain networks.

![DeFi Sentinel Dashboard](docs/images/dashboard-preview.png)

## 🌟 Key Features

### 🔍 **Comprehensive Security Analysis**
- **Static Analysis**: Bytecode-level vulnerability detection
- **Pattern Recognition**: Rugpull and honeypot detection
- **Admin Privilege Assessment**: Centralization risk analysis
- **Proxy Pattern Analysis**: Implementation change risks

### 🤖 **AI-Powered Risk Assessment**
- **Multi-LLM Support**: Powered by OpenRouter API (Claude, GPT-4, etc.)
- **Contextual Analysis**: Natural language risk explanations
- **Confidence Scoring**: Reliability metrics for all assessments
- **Continuous Learning**: Pattern recognition improvement over time

### 📊 **Real-Time Monitoring**
- **Continuous Scanning**: 24/7 automated monitoring
- **Multi-Chain Support**: Ethereum, Polygon, BSC, Arbitrum
- **Threshold Alerts**: Customizable risk-based notifications
- **Historical Tracking**: Risk score trends and analysis

### 🚨 **Advanced Alert System**
- **Real-Time Notifications**: Discord, webhooks, email
- **Risk-Based Triggers**: Configurable alert thresholds
- **Detailed Reports**: Forensic analysis for security events
- **Multi-Channel Delivery**: Flexible notification options

### 🌐 **Professional API & UI**
- **RESTful API**: Enterprise-grade integration
- **Subscription Tiers**: Free, Premium, Enterprise plans
- **Interactive Dashboard**: Web-based monitoring interface
- **Rate Limiting**: Fair usage and scalability

## 🚀 Quick Start

### Prerequisites
- Python ≥ 3.10
- OpenRouter API key
- Blockchain RPC access (optional for full functionality)

### Installation

1. **Clone the Repository**
```bash
git clone https://github.com/your-username/DeFi-Sentinel.git
cd DeFi-Sentinel
```

2. **Set Up Virtual Environment**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install Dependencies**
```bash
pip install -r defi_sentinel/requirements.txt
```

4. **Configure Environment**
```bash
cp .env.example .env
# Edit .env with your OpenRouter API key
```

5. **Run Setup**
```bash
python run.py setup
```

### Usage

#### 🤖 **Run the Main Agent**
```bash
python run.py agent
```

#### 🌐 **Start Web Interface**
```bash
python run.py ui
# Open http://localhost:8501 in your browser
```

#### 🔌 **Launch API Server**
```bash
python run.py api
# API available at http://localhost:8000
```

#### ⚡ **Quick Contract Analysis**
```bash
python run.py analyze 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984
```

## 🏗️ Architecture

DeFi Sentinel is built on the SpoonOS Core Developer Framework, providing:

```
┌─────────────────────────────────────────────────────────────┐
│                    DeFi Sentinel Platform                   │
├─────────────────────────────────────────────────────────────┤
│  🤖 SpoonOS Agent    📊 Web UI    🔌 REST API    🤖 Discord  │
├─────────────────────────────────────────────────────────────┤
│  🔍 Web3 Analyzer   🛡️ Security    📈 Risk        🔄 Monitor │
│                      Scanner       Assessor                 │
├─────────────────────────────────────────────────────────────┤
│              🧠 OpenRouter Multi-LLM Engine                 │
├─────────────────────────────────────────────────────────────┤
│  🔗 Ethereum   🟣 Polygon   🟡 BSC   🔵 Arbitrum   🌐 More   │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

- **🤖 SpoonReactMCP Agent**: Main autonomous agent with reasoning capabilities
- **🔍 Web3 Analyzer**: Blockchain interaction and contract analysis
- **🛡️ Security Scanner**: Vulnerability detection and pattern matching
- **📈 Risk Assessor**: Multi-factor risk scoring and assessment
- **📊 Web UI**: Streamlit-based interactive dashboard
- **🔌 REST API**: FastAPI-powered enterprise integration

## 📋 Configuration

### Environment Variables

```bash
# OpenRouter LLM API (Required)
OPENAI_API_KEY=sk-or-v1-your-openrouter-key

# Blockchain RPC URLs
ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/your-key
POLYGON_RPC_URL=https://polygon-rpc.com
BSC_RPC_URL=https://bsc-dataseed.binance.org

# Optional: Enhanced Features
COINGECKO_API_KEY=your-coingecko-api-key
DISCORD_BOT_TOKEN=your-discord-bot-token
```

### SpoonOS Configuration

Create `config.json` for advanced SpoonOS features:

```json
{
  "api_keys": {
    "openai": "sk-or-v1-your-openrouter-key"
  },
  "providers": {
    "openai": {
      "api_key": "sk-or-v1-your-openrouter-key",
      "model": "anthropic/claude-3-5-sonnet-20241022",
      "base_url": "https://openrouter.ai/api/v1"
    }
  },
  "agents": {
    "defi_sentinel": {
      "class": "SpoonReactMCP",
      "description": "DeFi security monitoring agent",
      "tools": ["web3_analyzer", "security_scanner", "risk_assessor"]
    }
  }
}
```

## 🔌 API Reference

### Authentication
```bash
Authorization: Bearer YOUR_API_KEY
```

### Key Endpoints

#### Analyze Contract
```bash
POST /api/v1/analyze
{
  "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
  "chain": "ethereum",
  "analysis_type": "comprehensive"
}
```

#### Get Risk Score
```bash
GET /api/v1/risk-score/0x1f9840a85d5af5bf1d1762f925bdaddc4201f984?chain=ethereum
```

#### Monitor Contract
```bash
POST /api/v1/monitor
{
  "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
  "chain": "ethereum",
  "alert_threshold": 60
}
```

#### Get Alerts
```bash
GET /api/v1/alerts?limit=50
```

### Rate Limits & Pricing

| Tier | Daily Requests | Features | Price/Month |
|------|----------------|----------|-------------|
| **Free** | 100 | Basic analysis | $0 |
| **Premium** | 1,000 | Full analysis + Monitoring | $49 |
| **Enterprise** | 10,000 | All features + Priority support | $199 |

## 🔒 Security Features

### Vulnerability Detection
- ✅ Reentrancy attacks
- ✅ Integer overflow/underflow
- ✅ Access control issues
- ✅ Proxy implementation flaws
- ✅ Upgrade mechanism abuse

### Behavioral Analysis
- ✅ Admin privilege monitoring
- ✅ Large transaction detection
- ✅ Liquidity manipulation alerts
- ✅ Price oracle manipulation
- ✅ MEV attack patterns

### Rugpull Detection
- ✅ Unlimited minting capabilities
- ✅ Liquidity drainage functions
- ✅ Trading restriction mechanisms
- ✅ Hidden fee structures
- ✅ Ownership concentration analysis

## 📊 Risk Scoring

DeFi Sentinel uses a comprehensive 100-point risk scoring system:

### Risk Categories
- **🔒 Security (40%)**: Vulnerabilities, admin privileges, proxy risks
- **💰 Financial (30%)**: Liquidity, tokenomics, market manipulation
- **🏛️ Operational (20%)**: Centralization, governance, team reputation
- **🔧 Technical (10%)**: Code quality, audit status, upgrade mechanisms

### Risk Levels
- **🟢 LOW (0-25)**: Minimal risk, safe for interaction
- **🟡 MEDIUM (26-50)**: Moderate risk, proceed with caution
- **🟠 HIGH (51-75)**: High risk, extreme caution advised
- **🔴 CRITICAL (76-100)**: Extreme risk, avoid interaction

## 🛠️ Development

### Project Structure
```
defi_sentinel/
├── agent/           # Core SpoonOS agents
│   └── main.py      # Main DeFi Sentinel agent
├── tools/           # Custom MCP tools
│   ├── web3_analyzer.py      # Blockchain analysis
│   ├── security_scanner.py   # Vulnerability detection
│   └── risk_assessor.py      # Risk scoring
├── api/             # REST API server
│   └── main.py      # FastAPI application
├── ui/              # Web interface
│   └── main.py      # Streamlit dashboard
├── discord_bot/     # Discord integration
├── monitor/         # Monitoring services
└── tests/           # Test suites
```

### Running Tests
```bash
python -m pytest tests/
```

### Code Quality
```bash
black defi_sentinel/        # Format code
flake8 defi_sentinel/       # Lint code
mypy defi_sentinel/         # Type checking
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Install development dependencies: `pip install -r requirements-dev.txt`
4. Make your changes
5. Run tests and linting
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[SpoonOS](https://github.com/XSpoonAi/spoon-core)**: Core framework powering the autonomous agent
- **[OpenRouter](https://openrouter.ai)**: Multi-LLM API access
- **DeFi Security Community**: Inspiration and vulnerability research

## 📞 Support

- 📖 **Documentation**: [Project Wiki](https://github.com/your-username/DeFi-Sentinel/wiki)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/your-username/DeFi-Sentinel/issues)
- 💬 **Community**: [Discord Server](https://discord.gg/defi-sentinel)
- 📧 **Email**: support@defisentinel.com

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=your-username/DeFi-Sentinel&type=Date)](https://star-history.com/#your-username/DeFi-Sentinel&Date)

---

**⚠️ Disclaimer**: DeFi Sentinel is a security analysis tool and should not be considered as financial advice. Always conduct your own research and due diligence before interacting with any smart contracts or DeFi protocols.