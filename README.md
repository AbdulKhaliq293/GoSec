# GoSec-ADK: Agentic Security Compliance & Recon Tool

GoSec-ADK is an open-source, model-agnostic security compliance and reconnaissance tool built using the **Google Agent Development Kit (ADK)** pattern. It bridges the gap between natural language and complex security operations by giving an AI agent "hands" (standard security tools) and "eyes" (a unified knowledge graph) to perform tasks, analyze results, and recommend fixes.

## 🚀 Features

### 🧠 Intelligent Security Agent
-   **Natural Language Interface:** Interact with your security tools using plain English (e.g., "Scan localhost and check for open ports").
-   **Model Agnostic:** Supports **Google Gemini**, **OpenAI GPT-4**, and **Anthropic Claude**.
-   **ReAct Pattern:** The agent reasons about the user's request, selects the appropriate tool, executes it, and analyzes the output.

### 🕸️ Unified Knowledge Graph
-   **Centralized Memory:** Instead of disparate log files, all findings are ingested into a graph database (in-memory).
-   **Contextual Analysis:** Links Assets (Hosts) to Services, Vulnerabilities, and Compliance Failures.
-   **Attack Path Detection:** Automatically identifies potential paths an attacker could take from an external entry point to critical assets.

### 🛡️ Comprehensive Tool Suite
-   **Network Recon:** Wraps **Nmap** to map attack surfaces.
-   **System Auditing:** Wraps **Lynis** for in-depth system hardening checks.
-   **Secret Scanning:** Wraps **Gitleaks** to find hardcoded secrets in repositories.
-   **Web Scanning:** Wraps **Nikto** for web server vulnerability scanning.

### 📋 Dynamic Compliance Engine
-   **Policy as Code:** Compliance standards are defined in simple YAML profiles.
-   **Supported Standards:**
    -   HIPAA
    -   PCI-DSS
    -   GDPR
    -   NIST
    -   CIS Benchmarks
-   **Extensible:** Add custom standards by dropping a new `.yaml` file into the `profiles/` directory.

### 🔧 Auto-Remediation
-   **Fix Generation:** Generates actionable remediation scripts based on detected issues.
-   **Templated Fixes:** Uses safe, variable-substituted templates to ensure reliability.
-   **Validation:** Includes commands to verify the fix was applied successfully.

### 📸 Snapshot & Diff
-   **State Tracking:** Save the current state of the knowledge graph to a JSON snapshot.
-   **Change Detection:** Compare two snapshots to see what changed (new open ports, fixed vulnerabilities, etc.).

## 🏗️ Architecture

GoSec-ADK follows a modular architecture based on the Agentic Workflow pattern:

1.  **The Brain (Agent):** Located in `pkg/adk`, this component handles the conversation loop, manages context, and interfaces with the LLM Provider.
2.  **The Memory (Graph Engine):** Located in `pkg/engine/graph.go`, acts as the source of truth, storing nodes (Assets) and edges (Relationships).
3.  **The Hands (Wrappers):** Located in `pkg/wrappers`, these adaptors translate LLM intent into specific CLI commands for tools like Nmap or Gitleaks.
4.  **The Logic (Engines):** Specialized engines for `Compliance`, `Attack Path` analysis, and `Remediation`.

## 📦 Installation

### Prerequisites
-   **Go 1.21** or higher
-   **Git**

### 1. External Tools
GoSec-ADK relies on standard security tools. Install them for your OS:

#### 🍎 macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install nmap lynis gitleaks nikto
```

#### 🐧 Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install nmap lynis nikto git
# Install Gitleaks (via release binary or package manager if available)
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
tar -xzf gitleaks_8.18.2_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

#### 🪟 Windows
*Note: WSL2 (Windows Subsystem for Linux) is highly recommended for the best experience.*

**Using Chocolatey:**
```powershell
choco install nmap gitleaks
# Lynis and Nikto are best run via WSL2 or Docker containers on Windows.
```

### 2. Build GoSec-ADK

```bash
# Clone the repository
git clone https://github.com/AbdulKhaliq293/GoSec.git
cd gosec-adk

# Install Go dependencies
go mod download

# Build the binary
go build -o gosec-adk cmd/main.go
```

## ⚙️ Configuration

You need an API key for at least one LLM provider (Gemini is the default).

1.  **Interactive Setup:**
    ```bash
    ./gosec-adk config setup
    ```
    Follow the prompts to enter your API keys.

2.  **Manual Configuration:**
    Set environment variables:
    ```bash
    export GOOGLE_API_KEY="your_gemini_key"
    # Optional
    export OPENAI_API_KEY="your_openai_key"
    export ANTHROPIC_API_KEY="your_anthropic_key"
    ```

## 🚀 Usage

### Quick Start (No Build Required)
Run directly with Go:
```bash
go run main.go interactive
```

### Using the Binary (If Built)
```bash
./gosec-adk interactive
```

### CLI Command Reference
Besides the interactive agent, you can use the CLI for configuration:

-   **Setup Wizard:**
    ```bash
    go run main.go config setup
    ```

-   **List Available AI Models:**
    ```bash
    go run main.go config list-models
    ```

-   **Manually Set API Key:**
    ```bash
    go run main.go config set-key --provider gemini --key "YOUR_KEY"
    ```

-   **Switch Model/Provider:**
    ```bash
    go run main.go config set-model --provider openai --model "gpt-4"
    ```

### Interactive Session Examples
Once inside the interactive session (`go run main.go interactive`), try these natural language commands:

-   **Reconnaissance:**
    > "Run a fast Nmap scan on localhost."
    > "Scan 192.168.1.10 for web vulnerabilities using Nikto."

-   **Compliance:**
    > "Check if this system meets HIPAA requirements."
    > "Run a CIS benchmark audit."

-   **Analysis:**
    > "Are there any attack paths to critical assets?"
    > "Show me a summary of high severity findings."

-   **Remediation:**
    > "How do I fix the SSH root login issue?"
    > "Generate a fix plan for the open telnet port."

-   **Secrets:**
    > "Scan the current directory for hardcoded secrets."

## 🤝 Contributing
Contributions are welcome!
-   Add new **Compliance Profiles** in `profiles/`.
-   Add new **Remediation Templates** in `remediation_templates/`.
-   Implement new **Tool Wrappers** in `pkg/wrappers/`.

## 📄 License
MIT
