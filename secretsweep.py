#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecretSweep - Local Machine Secret Scanner
Finds exposed secrets, credentials, and sensitive data on your machine.
https://github.com/MokashSahi/secretsweep
"""

import argparse
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


__version__ = "1.0.0"

# Severity levels
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91;1m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    file_path: str
    line_number: Optional[int] = None
    matched_text: Optional[str] = None
    description: str = ""
    recommendation: str = ""


def _build_pattern_rules():
    """Build pattern rules at runtime to avoid Python 3.14 parser issues with complex regex strings."""
    Q = "['\"]"  # quote char class
    OQ = Q + "?"  # optional quote
    rules = []

    def add(rid, sev, title, pattern, desc, rec):
        rules.append(dict(id=rid, severity=sev, title=title, pattern=pattern, description=desc, recommendation=rec))

    # AWS
    add("aws-access-key", Severity.CRITICAL, "AWS Access Key ID",
        r"(?:^|[^A-Z0-9])((AKIA|ASIA)[A-Z0-9]{16})(?:[^A-Z0-9]|$)",
        "AWS access key found in plaintext",
        "Rotate this key immediately via AWS IAM console. Use environment variables or AWS SSO.")

    add("aws-secret-key", Severity.CRITICAL, "AWS Secret Access Key",
        r"(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*" + OQ + r"([A-Za-z0-9/+=]{40})" + OQ,
        "AWS secret key found in plaintext",
        "Rotate immediately. Never store AWS secrets in files.")

    # GCP
    add("gcp-service-account", Severity.CRITICAL, "GCP Service Account Key",
        r'"type"\s*:\s*"service_account"',
        "Google Cloud service account JSON key file",
        "Use workload identity federation instead of key files.")

    # Azure
    add("azure-storage-key", Severity.CRITICAL, "Azure Storage Account Key",
        r"(?:AccountKey|azure[_-]?storage[_-]?key)\s*[=:]\s*" + OQ + r"([A-Za-z0-9+/=]{88})" + OQ,
        "Azure storage key found in plaintext",
        "Rotate the key and use Managed Identity or SAS tokens.")

    # Generic API keys
    add("generic-api-key", Severity.HIGH, "API Key / Token",
        r"(?:api[_-]?key|api[_-]?token|apikey)\s*[=:]\s*" + OQ + r"([A-Za-z0-9_\-]{20,})" + OQ,
        "Generic API key or token found",
        "Move to environment variable or secret manager.")

    # Private keys
    add("private-key-pem", Severity.CRITICAL, "Private Key (PEM)",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Private key found in PEM format",
        "Ensure key is encrypted with passphrase. Never commit keys to repos.")

    # GitHub tokens
    add("github-token", Severity.CRITICAL, "GitHub Personal Access Token",
        r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})",
        "GitHub token found in plaintext",
        "Revoke at github.com/settings/tokens and regenerate.")

    # Slack
    add("slack-token", Severity.HIGH, "Slack Token",
        r"(xox[boaprs]-[A-Za-z0-9\-]{10,})",
        "Slack API token found",
        "Revoke at api.slack.com and use environment variables.")

    # Stripe
    add("stripe-key", Severity.CRITICAL, "Stripe Secret Key",
        r"(sk_live_[A-Za-z0-9]{20,})",
        "Stripe live secret key - can charge real money",
        "Rotate immediately at dashboard.stripe.com/apikeys.")

    # Discord
    add("discord-token", Severity.HIGH, "Discord Bot Token",
        r"((?:mfa\.[A-Za-z0-9_-]{84})|(?:[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}))",
        "Discord bot or user token found",
        "Regenerate at discord.com/developers.")

    # Database URLs
    NWS = r"[^\s]{10,}"  # non-whitespace 10+
    add("database-url", Severity.HIGH, "Database Connection String",
        r"(?:mongodb|postgres|postgresql|mysql|redis|amqp)://" + NWS,
        "Database connection string with potential credentials",
        "Use environment variables for connection strings.")

    # Passwords in config
    add("password-in-config", Severity.HIGH, "Password in Configuration",
        r"(?:password|passwd|pwd|secret)\s*[=:]\s*" + Q + r"([^'\"]{8,})" + Q,
        "Password or secret found in configuration file",
        "Use a secret manager or environment variables.")

    # JWT
    add("jwt-token", Severity.MEDIUM, "JWT Token",
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "JSON Web Token found - may contain sensitive claims",
        "Check expiration. Remove if stale.")

    # OpenAI
    add("openai-key", Severity.HIGH, "OpenAI API Key",
        r"(sk-[A-Za-z0-9]{20,})",
        "OpenAI API key found",
        "Rotate at platform.openai.com/api-keys.")

    # SendGrid
    add("sendgrid-key", Severity.HIGH, "SendGrid API Key",
        r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})",
        "SendGrid API key found",
        "Rotate at app.sendgrid.com/settings/api_keys.")

    # Twilio
    add("twilio-key", Severity.HIGH, "Twilio API Key",
        r"(SK[a-f0-9]{32})",
        "Twilio API key found",
        "Rotate at twilio.com/console.")

    # Telegram Bot Token
    add("telegram-bot-token", Severity.HIGH, "Telegram Bot Token",
        r"(\d{8,10}:[A-Za-z0-9_-]{35})",
        "Telegram bot token found",
        "Revoke via @BotFather on Telegram.")

    # Heroku
    add("heroku-key", Severity.HIGH, "Heroku API Key",
        r"(?:heroku[_-]?api[_-]?key)\s*[=:]\s*" + OQ + r"([a-f0-9-]{36})" + OQ,
        "Heroku API key found",
        "Regenerate at dashboard.heroku.com/account.")

    # .env secrets
    add("env-secret", Severity.MEDIUM, "Secret in .env File",
        r"(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*\s*=\s*" + OQ + r"([^\s'\"#]{8,})" + OQ,
        "Potential secret found in environment file",
        "Ensure .env is in .gitignore and not in version control.")

    return rules


PATTERN_RULES = _build_pattern_rules()


# Known secret locations
def get_home():
    return Path.home()


def get_known_secret_locations():
    home = get_home()
    items = [
        ("aws-credentials", home / ".aws" / "credentials", Severity.CRITICAL, "AWS credentials file"),
        ("aws-config", home / ".aws" / "config", Severity.MEDIUM, "AWS config (may contain SSO/role info)"),
        ("gcloud-adc", home / ".config" / "gcloud" / "application_default_credentials.json", Severity.CRITICAL, "GCP Application Default Credentials"),
        ("azure-profile", home / ".azure" / "azureProfile.json", Severity.HIGH, "Azure CLI profile"),
        ("azure-tokens", home / ".azure" / "accessTokens.json", Severity.CRITICAL, "Azure access tokens"),
        ("bash-history", home / ".bash_history", Severity.MEDIUM, "Bash history (may contain secrets in commands)"),
        ("zsh-history", home / ".zsh_history", Severity.MEDIUM, "Zsh history (may contain secrets in commands)"),
        ("ps-history", home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt", Severity.MEDIUM, "PowerShell history"),
        ("ssh-private-key", home / ".ssh" / "id_rsa", Severity.HIGH, "SSH private key (RSA)"),
        ("ssh-ed25519", home / ".ssh" / "id_ed25519", Severity.HIGH, "SSH private key (Ed25519)"),
        ("ssh-ecdsa", home / ".ssh" / "id_ecdsa", Severity.HIGH, "SSH private key (ECDSA)"),
        ("docker-config", home / ".docker" / "config.json", Severity.HIGH, "Docker config (may contain registry auth)"),
        ("kube-config", home / ".kube" / "config", Severity.HIGH, "Kubernetes config (cluster credentials)"),
        ("npmrc", home / ".npmrc", Severity.HIGH, "npm config (may contain auth tokens)"),
        ("pypirc", home / ".pypirc", Severity.HIGH, "PyPI config (may contain upload tokens)"),
        ("gem-credentials", home / ".gem" / "credentials", Severity.HIGH, "RubyGems credentials"),
        ("nuget-config", home / "AppData" / "Roaming" / "NuGet" / "NuGet.Config", Severity.MEDIUM, "NuGet config"),
        ("netrc", home / ".netrc", Severity.HIGH, "Netrc file (plaintext credentials)"),
        ("git-credentials", home / ".git-credentials", Severity.CRITICAL, "Git credential store (plaintext!)"),
    ]
    return [{"id": i, "path": p, "severity": s, "description": d} for i, p, s, d in items]


def check_ssh_key_permissions(path):
    if sys.platform == "win32":
        return None
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            return Finding(
                rule_id="ssh-key-permissions", severity=Severity.HIGH,
                title="SSH Key - Overly Permissive", file_path=str(path),
                description="Permissions %s are too open. Should be 600." % oct(mode)[-3:],
                recommendation="Run: chmod 600 " + str(path))
    except OSError:
        pass
    return None


def check_ssh_key_encrypted(path):
    try:
        content = path.read_text(errors="ignore")[:2000]
        if "ENCRYPTED" not in content and "-----BEGIN" in content and "PRIVATE KEY-----" in content:
            return Finding(
                rule_id="ssh-key-unencrypted", severity=Severity.MEDIUM,
                title="SSH Key - No Passphrase", file_path=str(path),
                description="Private key appears to have no passphrase protection.",
                recommendation="Add passphrase: ssh-keygen -p -f " + str(path))
    except OSError:
        pass
    return None


# File scanning config
SCAN_EXTENSIONS = {
    ".env", ".cfg", ".conf", ".config", ".ini", ".json", ".yaml", ".yml",
    ".toml", ".xml", ".properties", ".sh", ".bash", ".zsh", ".ps1",
    ".py", ".js", ".ts", ".rb", ".go", ".java", ".cs", ".php",
    ".tf", ".tfvars", ".hcl", ".dockerfile", ".txt", ".md", ".log", ".csv",
}

SCAN_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".env.test", ".flaskenv", ".npmrc", ".pypirc", ".netrc",
    "credentials", "secrets", "config", "settings",
    "docker-compose.yml", "docker-compose.yaml", "Vagrantfile", "Procfile",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "vendor", "target", "bin", "obj",
    ".terraform", ".gradle", ".m2",
    "$RECYCLE.BIN", "System Volume Information", "AppData", "Library", "Windows",
}

MAX_FILE_SIZE = 1_000_000
MAX_LINE_LENGTH = 2000


def should_scan_file(path):
    name = path.name.lower()
    if name in {n.lower() for n in SCAN_FILENAMES}:
        return True
    return path.suffix.lower() in SCAN_EXTENSIONS


def scan_file_patterns(file_path, compiled_rules):
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        if len(content) > MAX_FILE_SIZE:
            content = content[:MAX_FILE_SIZE]
    except (OSError, PermissionError):
        return findings

    for rule, pattern in compiled_rules:
        for match in pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            matched = match.group(0)[:80]
            if len(matched) > 12:
                v = 4
                masked = matched[:v] + "*" * min(len(matched) - v * 2, 20) + matched[-v:]
            else:
                masked = matched[:3] + "****"
            findings.append(Finding(
                rule_id=rule["id"], severity=rule["severity"], title=rule["title"],
                file_path=str(file_path), line_number=line_num, matched_text=masked,
                description=rule["description"], recommendation=rule["recommendation"]))
    return findings


def scan_shell_history(path):
    findings = []
    if not path.exists():
        return findings
    history_patterns = [
        (r"(?:curl|wget|http)\s+.*[?&](?:api_?key|token|key|auth)=([^\s&]{8,})", "API key in URL"),
        (r"(?:export|set)\s+(?:\w*(?:SECRET|TOKEN|KEY|PASSWORD|API)\w*)\s*=\s*(\S{8,})", "Secret in env export"),
        (r"(?:mysql|psql|mongo)\s+.*-p\s*(\S{6,})", "Database password in command"),
        (r"(?:sshpass|expect)\s+.*-p\s*(\S{6,})", "Password in SSH command"),
    ]
    compiled = [(desc, re.compile(p, re.IGNORECASE)) for p, desc in history_patterns]
    try:
        lines = path.read_text(errors="ignore").splitlines()
        for i, line in enumerate(lines[-5000:], 1):
            if len(line) > MAX_LINE_LENGTH:
                continue
            for desc, pattern in compiled:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id="history-secret", severity=Severity.MEDIUM,
                        title="Secret in Shell History - " + desc,
                        file_path=str(path), line_number=i,
                        matched_text="[REDACTED - check history file]",
                        description="Shell history contains a command with embedded credentials.",
                        recommendation="Clear history entry or rotate the exposed credential."))
                    break
    except (OSError, PermissionError):
        pass
    return findings


def find_env_files(scan_paths, max_depth=5):
    findings = []
    compiled_rules = [(rule, re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)) for rule in PATTERN_RULES]
    files_scanned = 0
    for scan_path in scan_paths:
        if not scan_path.exists():
            continue
        for root, dirs, files in os.walk(scan_path):
            depth = len(Path(root).relative_to(scan_path).parts)
            if depth > max_depth:
                dirs.clear()
                continue
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                fpath = Path(root) / fname
                if should_scan_file(fpath):
                    try:
                        if fpath.stat().st_size > MAX_FILE_SIZE:
                            continue
                    except OSError:
                        continue
                    findings.extend(scan_file_patterns(fpath, compiled_rules))
                    files_scanned += 1
                    if files_scanned % 500 == 0:
                        print("  %sScanned %d files...%s" % (DIM, files_scanned, RESET), file=sys.stderr)
    return findings


# Report output

def print_banner():
    print("""
%s+-------------------------------------------+
|       SecretSweep v%s                 |
|   Local Machine Secret Scanner            |
+-------------------------------------------+%s
""" % (BOLD, __version__, RESET))


def print_finding(f, index):
    color = SEVERITY_COLORS.get(f.severity, "")
    print("  %s[%s]%s #%d - %s%s%s" % (color, f.severity.value, RESET, index, BOLD, f.title, RESET))
    loc = "    File: %s" % f.file_path
    if f.line_number:
        loc += ":%d" % f.line_number
    print(loc)
    if f.matched_text:
        print("    Match: %s%s%s" % (DIM, f.matched_text, RESET))
    print("    Fix: %s" % f.recommendation)
    print()


def print_summary(findings):
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    print("\n%s=== Summary ===%s" % (BOLD, RESET))
    total = len(findings)
    if total == 0:
        print("  No secrets found! Your machine looks clean.")
        return

    print("  Found %s%d%s potential secret(s):\n" % (BOLD, total, RESET))
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = len(by_sev.get(sev, []))
        if count:
            color = SEVERITY_COLORS[sev]
            print("    %s* %s: %d%s" % (color, sev.value, count, RESET))

    print("\n  %sRun with --json to export findings for processing.%s" % (DIM, RESET))
    print("  %sRun with --html to generate an HTML report.%s" % (DIM, RESET))


def export_json(findings, output_path):
    data = {
        "tool": "secretsweep",
        "version": __version__,
        "scan_time": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    Path(output_path).write_text(json.dumps(data, indent=2, default=str))
    print("  JSON report saved to: %s" % output_path)


def export_html(findings, output_path):
    sev_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04", "LOW": "#2563eb", "INFO": "#6b7280",
    }
    rows = ""
    for i, f in enumerate(findings, 1):
        color = sev_colors.get(f.severity.value, "#333")
        loc = f.file_path
        if f.line_number:
            loc += ":%d" % f.line_number
        rows += "<tr><td>%d</td><td><span style='color:%s;font-weight:bold'>%s</span></td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>\n" % (
            i, color, f.severity.value, f.title, loc, f.matched_text or "", f.recommendation)

    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<title>SecretSweep Report</title>"
        "<style>"
        "body { font-family: -apple-system, sans-serif; max-width: 1200px; margin: 2em auto; padding: 0 1em; background: #0d1117; color: #c9d1d9; }"
        "h1 { color: #58a6ff; } table { width: 100%%; border-collapse: collapse; margin: 1em 0; }"
        "th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }"
        "th { background: #161b22; color: #8b949e; } tr:hover { background: #161b22; }"
        "code { background: #1c2128; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }"
        ".summary { display: flex; gap: 1em; margin: 1em 0; }"
        ".stat { background: #161b22; padding: 1em; border-radius: 8px; text-align: center; }"
        ".stat .num { font-size: 2em; font-weight: bold; }"
        "</style></head><body>"
        "<h1>SecretSweep Report</h1>"
        "<p>Generated: %s</p>"
        "<div class='summary'>"
        "<div class='stat'><div class='num'>%d</div>Total</div>"
        "<div class='stat'><div class='num' style='color:#dc2626'>%d</div>Critical</div>"
        "<div class='stat'><div class='num' style='color:#ea580c'>%d</div>High</div>"
        "<div class='stat'><div class='num' style='color:#ca8a04'>%d</div>Medium</div>"
        "</div>"
        "<table><thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Location</th><th>Match</th><th>Recommendation</th></tr></thead>"
        "<tbody>%s</tbody></table>"
        "</body></html>"
    ) % (now, len(findings), crit, high, med, rows)

    Path(output_path).write_text(html)
    print("  HTML report saved to: %s" % output_path)


def main():
    parser = argparse.ArgumentParser(
        prog="secretsweep",
        description="SecretSweep - Scan your machine for exposed secrets, credentials, and sensitive data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secretsweep                          # Quick scan (home + known locations)
  secretsweep --deep                   # Deep scan (home + project dirs)
  secretsweep --path /path/to/project  # Scan specific directory
  secretsweep --json report.json       # Export JSON report
  secretsweep --html report.html       # Export HTML report
        """)
    parser.add_argument("--path", "-p", action="append", help="Additional paths to scan")
    parser.add_argument("--deep", action="store_true", help="Deep scan (more directories, slower)")
    parser.add_argument("--max-depth", type=int, default=5, help="Max directory depth (default: 5)")
    parser.add_argument("--json", metavar="FILE", help="Export findings to JSON file")
    parser.add_argument("--html", metavar="FILE", help="Export findings to HTML report")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                        default="low", help="Minimum severity to report (default: low)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", "-v", action="version", version="secretsweep " + __version__)

    args = parser.parse_args()

    if args.no_color:
        for key in SEVERITY_COLORS:
            SEVERITY_COLORS[key] = ""
        globals()["RESET"] = ""
        globals()["BOLD"] = ""
        globals()["DIM"] = ""

    min_severity = {
        "critical": [Severity.CRITICAL],
        "high": [Severity.CRITICAL, Severity.HIGH],
        "medium": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
        "low": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
        "info": list(Severity),
    }[args.severity]

    print_banner()
    start = time.time()
    all_findings = []

    # Phase 1: Known secret locations
    print("%s[1/3] Checking known secret locations...%s" % (BOLD, RESET))
    known = get_known_secret_locations()
    compiled_rules = [(rule, re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)) for rule in PATTERN_RULES]

    for loc in known:
        path = loc["path"]
        if path.exists():
            print("  Found: %s" % path)
            all_findings.append(Finding(
                rule_id=loc["id"], severity=loc["severity"],
                title=loc["description"], file_path=str(path),
                description="Sensitive file exists at known location.",
                recommendation="Review contents and ensure this file is necessary."))
            all_findings.extend(scan_file_patterns(path, compiled_rules))
            if "ssh" in loc["id"]:
                for check in [check_ssh_key_permissions, check_ssh_key_encrypted]:
                    result = check(path)
                    if result:
                        all_findings.append(result)

    # Phase 2: Shell history
    print("\n%s[2/3] Scanning shell history...%s" % (BOLD, RESET))
    home = get_home()
    for hf in [
        home / ".bash_history",
        home / ".zsh_history",
        home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
    ]:
        if hf.exists():
            hfindings = scan_shell_history(hf)
            if hfindings:
                print("  Found %d potential secret(s) in %s" % (len(hfindings), hf.name))
            all_findings.extend(hfindings)

    # Phase 3: Directory scan
    print("\n%s[3/3] Scanning files for secret patterns...%s" % (BOLD, RESET))
    scan_paths = []
    if args.path:
        scan_paths.extend(Path(p) for p in args.path)

    if args.deep:
        for candidate in [
            home / "Projects", home / "projects", home / "src",
            home / "repos", home / "code", home / "dev",
            home / "Documents", home / "Desktop", Path("X:\\"),
        ]:
            if candidate.exists():
                scan_paths.append(candidate)
    elif not args.path:
        scan_paths.append(Path.cwd())

    if scan_paths:
        print("  Scanning: %s" % ", ".join(str(p) for p in scan_paths))
        all_findings.extend(find_env_files(scan_paths, args.max_depth))

    # Filter by severity
    all_findings = [f for f in all_findings if f.severity in min_severity]

    # Deduplicate
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    # Sort by severity
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    all_findings.sort(key=lambda f: sev_order[f.severity])

    elapsed = time.time() - start

    if all_findings:
        print("\n%s=== Findings ===%s\n" % (BOLD, RESET))
        for i, f in enumerate(all_findings, 1):
            print_finding(f, i)

    print_summary(all_findings)
    print("\n  %sScan completed in %.1fs%s\n" % (DIM, elapsed, RESET))

    if args.json:
        export_json(all_findings, args.json)
    if args.html:
        export_html(all_findings, args.html)

    critical_high = [f for f in all_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    sys.exit(1 if critical_high else 0)


if __name__ == "__main__":
    main()
