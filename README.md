# 🔍 SecretSweep

**Local machine secret scanner** — find exposed credentials, API keys, and sensitive data lurking on your system.

Unlike repo-scanning tools (GitLeaks, TruffleHog), SecretSweep scans your **entire machine**: shell history, cloud configs, project files, and known secret locations.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)

## Why?

Enterprise DLP tools cost thousands. GitLeaks only scans repos. **Nobody scans your actual machine for free.**

SecretSweep finds:
- 🔑 API keys in shell history (bash, zsh, PowerShell)
- 📁 `.env` files scattered across projects
- ☁️ Cloud credentials (AWS, GCP, Azure) in default locations
- 🔐 SSH keys without passphrases
- 🐳 Docker/Kubernetes configs with embedded auth
- 💳 Stripe, GitHub, Slack, Discord tokens in code
- 📦 Package manager tokens (.npmrc, .pypirc)
- 🗄️ Database connection strings with passwords

## Quick Start

```bash
# No installation needed — just Python 3.8+
python secretsweep.py

# Scan a specific project
python secretsweep.py --path /path/to/project

# Deep scan (home directory + common project folders)
python secretsweep.py --deep

# Export reports
python secretsweep.py --json report.json
python secretsweep.py --html report.html
```

## Installation

```bash
git clone https://github.com/MokashSahi/secretsweep.git
cd secretsweep
python secretsweep.py
```

**Zero dependencies.** Only Python standard library. Works on Windows, macOS, and Linux.

## What It Scans

### Phase 1 — Known Secret Locations
Checks ~20 well-known paths where credentials accumulate:
- `~/.aws/credentials`, `~/.azure/accessTokens.json`
- `~/.docker/config.json`, `~/.kube/config`
- `~/.ssh/id_*` (also checks permissions & passphrase)
- `~/.npmrc`, `~/.pypirc`, `~/.netrc`
- `~/.git-credentials`

### Phase 2 — Shell History
Scans your last 5000 commands for:
- API keys passed in URLs (`curl ...?api_key=...`)
- Secrets exported as env vars
- Database passwords in CLI commands
- Passwords in SSH/SCP commands

### Phase 3 — Pattern Matching
Scans files using 20+ regex rules detecting:

| Provider | Pattern |
|----------|---------|
| AWS | Access keys (`AKIA...`), secret keys |
| GCP | Service account JSON keys |
| Azure | Storage account keys |
| GitHub | PATs (`ghp_`, `github_pat_`) |
| Stripe | Live secret keys (`sk_live_`) |
| OpenAI | API keys (`sk-...`) |
| Slack | Bot/user tokens (`xox...`) |
| Discord | Bot tokens |
| Telegram | Bot tokens |
| Twilio | API keys |
| SendGrid | API keys |
| Generic | `password=`, `secret=`, JWTs, DB URLs |

## Output

### Terminal
```
╔═══════════════════════════════════════════╗
║       🔍 SecretSweep v1.0.0              ║
║   Local Machine Secret Scanner           ║
╚═══════════════════════════════════════════╝

[1/3] Checking known secret locations...
  ⚠️  Found: /home/user/.aws/credentials
  ⚠️  Found: /home/user/.ssh/id_rsa

[2/3] Scanning shell history...
  ⚠️  Found 2 potential secret(s) in .bash_history

[3/3] Scanning files for secret patterns...
  Scanning: /home/user/projects

═══ Findings ═══

  [CRITICAL] #1 — AWS Access Key ID
    📁 /home/user/.aws/credentials:3
    🔑 AKIA●●●●●●●●●●●●●●●●●●●●WXYZ
    💡 Rotate this key immediately via AWS IAM console.

═══ Summary ═══
  Found 5 potential secret(s):
    ■ CRITICAL: 2
    ■ HIGH: 2
    ■ MEDIUM: 1
```

### HTML Report
Dark-themed, professional report with severity breakdown — perfect for audits.

### JSON Export
Machine-readable output for CI/CD integration.

## Options

| Flag | Description |
|------|-------------|
| `--path`, `-p` | Scan specific directory (repeatable) |
| `--deep` | Scan home + common project directories |
| `--max-depth N` | Max directory recursion depth (default: 5) |
| `--severity LEVEL` | Minimum severity: critical/high/medium/low/info |
| `--json FILE` | Export to JSON |
| `--html FILE` | Export to HTML |
| `--no-color` | Disable terminal colors |

## CI/CD Integration

SecretSweep exits with code `1` if any CRITICAL or HIGH findings are detected:

```yaml
# GitHub Actions
- name: Secret Scan
  run: python secretsweep.py --path . --severity high --json secrets-report.json
```

## Privacy

SecretSweep runs **100% locally**. No data is sent anywhere. Matched secrets are masked in output (only first/last 4 chars shown).

## Contributing

PRs welcome! Especially:
- New detection patterns for services/providers
- Platform-specific secret locations
- False positive reduction
- Performance improvements

## License

MIT — use it, share it, improve it.

---

**Built by [MokashSahi](https://github.com/MokashSahi)** — because your secrets deserve better than plaintext.
