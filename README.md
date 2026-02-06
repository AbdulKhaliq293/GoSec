# GoSec-ADK: Agentic Security Compliance & Recon Tool

GoSec-ADK is an open-source, model-agnostic security compliance and reconnaissance tool built using the **Google Agent Development Kit (ADK)** pattern. It leverages existing industry-standard tools (`nmap`, `lynis`) and wraps them in an intelligent agent framework.

## Features

*   **Model Agnostic**: Compatible with Gemini, Vertex AI, and other LLMs via adapters.
*   **Dynamic Compliance Engine**: Define compliance standards (CIS, HIPAA, GDPR) as YAML profiles.
*   **Intelligent Agent**: Uses function calling to determine which checks to run based on natural language commands.
*   **Extensible**: Easily add new tools or compliance standards without recompiling.

## Architecture

*   `pkg/adk`: Core agent logic and tool interfaces.
*   `pkg/engine`: Compliance profile parser and runner.
*   `pkg/wrappers`: Wrappers for external tools (`nmap`, `lynis`).
*   `profiles/`: YAML definitions for compliance standards.

## Prerequisites

*   Go 1.21+
*   `nmap` installed
*   `lynis` installed
*   `GOOGLE_API_KEY` environment variable (for Gemini)

## Usage

```bash
# Build
go build -o gosec-adk cmd/main.go

# Interactive Mode
./gosec-adk interactive

# Example Prompt
> "Check if my system meets HIPAA encryption requirements."
```

## Contributing

Add new compliance profiles in `profiles/` or implement new tool wrappers in `pkg/wrappers/`.
