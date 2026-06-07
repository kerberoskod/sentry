# Sentry — Security Scanner

![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

**Sentry** scans your project for hardcoded secrets, misconfigurations, and security issues — right from the terminal.

## Installation

```bash
# Ensure you have Go 1.23+
go install github.com/kerberoskod/sentry@main
```

Or build from source:

```bash
git clone https://github.com/kerberoskod/sentry.git
cd sentry
go build -o sentry .
```

## Usage

```bash
# Scan current directory
sentry scan

# Scan a specific project
sentry scan --path /path/to/project

# JSON output
sentry scan --json

# Exit with error if any issues found
sentry scan --strict
```

## Checks

| Check | What It Finds | Severity |
|-------|--------------|----------|
| **Secrets** | AWS keys, private keys, API tokens, GitHub tokens | 🔴 Critical |
| **Secrets** | Hardcoded credentials, API keys in code | 🟡 High |
| **Environment** | `.env` not in `.gitignore` | 🟡 High |
| **Environment** | Missing `.env.example` | 🔵 Medium |
| **Docker** | Container running as root | 🟡 High |
| **Docker** | Using `latest` tag | 🔵 Medium |
| **Docker** | Using `ADD` instead of `COPY` | ⚪ Low |
| **.gitignore** | Missing `.gitignore` file | 🔵 Medium |
| **.gitignore** | Missing recommended entries (`.env`, `node_modules/`, etc.) | varies |

## Testing

```bash
go test ./... -v -count=1
```

## License

MIT
