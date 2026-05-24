# Decepticon

> Fork of [PurpleAILAB/Decepticon](https://github.com/PurpleAILAB/Decepticon)

Decepticon is an advanced AI-powered red teaming and adversarial testing framework designed to evaluate the robustness of large language models (LLMs) against prompt injection, jailbreaking, and other adversarial attacks.

## Features

- 🔴 **Automated Red Teaming** — Generate and execute adversarial prompts against target LLMs
- 🛡️ **Defense Evaluation** — Measure how well safety guardrails hold up under attack
- 📊 **Reporting & Metrics** — Detailed reports on model vulnerabilities and attack success rates
- 🔌 **Multi-Provider Support** — Works with OpenAI, Anthropic, Mistral, and more
- 🐳 **Docker Ready** — Fully containerized for easy deployment

## Quick Start

### Prerequisites

- Python 3.10+
- Docker & Docker Compose (optional)
- API keys for your target LLM provider(s)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/Decepticon.git
cd Decepticon

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your API keys and settings
nano .env
```

### Running with Docker

```bash
docker compose up --build
```

### Running Locally

```bash
python -m decepticon run --target openai --model gpt-4o --attack-suite default
```

## Usage

```bash
# List available attack suites
python -m decepticon list-attacks

# Run a specific attack against a target model
python -m decepticon run \
  --target openai \
  --model gpt-4o-mini \
  --attack-suite jailbreak \
  --output report.json

# Evaluate defenses
python -m decepticon evaluate \
  --config config/eval_config.yaml \
  --report results/
```

## Project Structure

```
Decepticon/
├── decepticon/          # Core application package
│   ├── attacks/         # Attack strategy implementations
│   ├── providers/       # LLM provider integrations
│   ├── evaluators/      # Response evaluation logic
│   ├── reporting/       # Report generation
│   └── cli/             # Command-line interface
├── config/              # Configuration files
├── tests/               # Test suite
├── docs/                # Documentation
├── .env.example         # Environment variable template
├── docker-compose.yml   # Docker Compose configuration
└── requirements.txt     # Python dependencies
```

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) and check the [issue tracker](https://github.com/your-org/Decepticon/issues) before submitting a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-new-feature`)
3. Commit your changes following [Conventional Commits](https://www.conventionalcommits.org/)
4. Push to your branch and open a Pull Request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

> **Personal note:** I'm using this fork primarily to experiment with the `jailbreak` attack suite against open-source models (Mistral, LLaMA). The upstream project focuses mostly on OpenAI/Anthropic targets, so I may add a local Ollama provider integration down the line.
