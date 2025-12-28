# Security Hooks

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.x-yellow)

A Claude Code plugin that detects and blocks potential secrets before git commits.

## Quick Start

```bash
# Add the marketplace
/plugin marketplace add /path/to/claude-plugins

# Install the plugin
/plugin install security-hooks@plugins-by-james
```

That's it. The hook automatically scans all `git commit` operations for secrets.

## Table of Contents

- [What Are Security Hooks?](#what-are-security-hooks)
- [How It Works](#how-it-works)
- [Secret Patterns Detected](#secret-patterns-detected)
- [Smart Filtering](#smart-filtering)
- [Output Format](#output-format)
- [Hook Configuration](#hook-configuration)
- [Exit Codes](#exit-codes)
- [Usage Examples](#usage-examples)
- [Running Tests](#running-tests)
- [Environment Variables](#environment-variables)
- [Remediation Guidance](#remediation-guidance)
- [Best Practices](#best-practices)
- [Limitations](#limitations)
- [Debugging](#debugging)
- [License](#license)

## What Are Security Hooks?

Security hooks are PreToolUse hooks that run before git operations to scan staged files for secrets, API keys, credentials, and sensitive data. They act as a final security gate before code is committed.

**Key Features:**
- Fail-closed design (errors block commits for safety)
- TOCTOU-safe (reads from git staging area, not disk)
- Zero external dependencies (Python stdlib only)
- 24 pre-compiled regex patterns for fast detection
- Hardcoded .env value detection with word boundaries

## How It Works

### Detection Methods

#### 1. Pattern-Based Detection
Scans for 24 common secret patterns using pre-compiled regex.

#### 2. Hardcoded .env Value Detection
- Parses `.env` file for environment variable values
- Searches staged files for exact matches using word boundaries
- Catches secrets that are copy-pasted from .env into source code

### Processing Pipeline

```
1. Receive Bash tool call with "git commit" command
2. Get CLAUDE_PROJECT_DIR (or cwd)
3. Parse .env file (if exists)
4. Get staged files: git diff --cached --name-only
5. For each staged file:
   - Skip binary files (30+ extensions)
   - Skip .env files
   - Skip files >10MB
   - Read content from git staging area
   - Check against 24 secret patterns
   - Check against hardcoded .env values
6. If secrets found: block commit with detailed report
7. On errors: block commit (fail-closed)
```

## Secret Patterns Detected

### Cloud Provider Credentials

| Pattern | Example Format |
|---------|---------------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` |
| AWS Secret Access Key | `aws_secret_access_key = ...` |
| Google API Key | `AIza[0-9A-Za-z-_]{35}` |

### AI Service API Keys

| Pattern | Example Format |
|---------|---------------|
| OpenAI API Key | `sk-[a-zA-Z0-9]{20,}` |
| OpenAI Project Key | `sk-proj-[a-zA-Z0-9]{20,}` |
| Anthropic API Key | `sk-ant-[a-zA-Z0-9-]{20,}` |

### Version Control & CI/CD

| Pattern | Example Format |
|---------|---------------|
| GitHub PAT | `ghp_[a-zA-Z0-9]{36}` |
| GitHub OAuth Token | `gho_[a-zA-Z0-9]{36}` |
| GitHub User Token | `ghu_[a-zA-Z0-9]{36}` |
| GitHub Server Token | `ghs_[a-zA-Z0-9]{36}` |
| GitHub Refresh Token | `ghr_[a-zA-Z0-9]{36}` |
| npm Access Token | `npm_[a-zA-Z0-9]{36}` |
| PyPI API Token | `pypi-[a-zA-Z0-9]{43,}` |

### Communication Services

| Pattern | Example Format |
|---------|---------------|
| Slack Token | `xox[baprs]-[a-zA-Z0-9-]{10,}` |
| Discord Bot Token | `[MN][A-Za-z\d]{23,}.[A-Za-z\d_-]{6}.[A-Za-z\d_-]{27}` |
| Twilio API Key | `SK[a-fA-F0-9]{32}` |
| SendGrid API Key | `SG.[a-zA-Z0-9_-]{20,}.[a-zA-Z0-9_-]{20,}` |
| Mailgun API Key | `key-[a-zA-Z0-9]{32}` |

### Payment Services

| Pattern | Example Format |
|---------|---------------|
| Stripe Secret Key | `sk_live_[a-zA-Z0-9]{24,}` |
| Stripe Restricted Key | `rk_live_[a-zA-Z0-9]{24,}` |

### Database Connection Strings

| Pattern | Example Format |
|---------|---------------|
| PostgreSQL | `postgres(ql)?://user:pass@host` |
| MySQL | `mysql://user:pass@host` |
| MongoDB | `mongodb(+srv)?://user:pass@host` |

### Generic Patterns

| Pattern | Description |
|---------|-------------|
| Private Keys | `-----BEGIN (RSA\|DSA\|EC\|OPENSSH) PRIVATE KEY-----` |
| Bearer Tokens | `bearer [a-zA-Z0-9_-.]{20,}` |
| Generic Secrets | `(secret\|token)\s*[:=]\s*[value]{20,}` |

## Smart Filtering

### Binary Files Skipped (30+ extensions)

**Images:** `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.ico`, `.webp`, `.svg`

**Documents:** `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`

**Archives:** `.zip`, `.tar`, `.gz`, `.rar`, `.7z`

**Executables:** `.exe`, `.dll`, `.so`, `.dylib`, `.bin`

**Compiled:** `.wasm`, `.pyc`, `.class`, `.o`, `.obj`

**Fonts:** `.woff`, `.woff2`, `.ttf`, `.otf`, `.eot`

**Media:** `.mp3`, `.mp4`, `.avi`, `.mov`, `.wav`, `.flac`

**Databases:** `.sqlite`, `.db`

### Environment Files Skipped

`.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`, `.env.staging`, `.env.example`

### False Positive Prevention

**Non-Secret Values Ignored:**
- Booleans: `true`, `false`, `yes`, `no`, `on`, `off`
- Environments: `development`, `production`, `staging`, `test`
- Common URLs: `localhost`, `127.0.0.1`, `0.0.0.0`
- Encodings: `utf-8`, `utf8`, `none`, `null`

**Value Filtering:**
- Minimum 8 characters
- Numeric-only values skipped

## Output Format

```
SECURITY WARNING: Potential secrets detected in staged files!

  Pattern-based detections:
    - src/api.js:42 - Found potential GitHub Personal Access Token
    - config/settings.ts:15 - Found potential OpenAI API key

  Hardcoded .env values detected:
    - src/config.py:8 - Found hardcoded value from .env key 'DATABASE_PASSWORD'

Please remove secrets before committing.
Use environment variables at runtime instead of hardcoding values from .env.
Consider using a secrets manager for sensitive credentials.
```

## Hook Configuration

**Location:** `hooks/hooks.json`

```json
[
  {
    "event": "PreToolUse",
    "matchers": [
      {
        "matcher": "Bash",
        "type": "command",
        "command": "${CLAUDE_PLUGIN_ROOT}/scripts/check_secrets.py",
        "timeout": 30
      }
    ]
  }
]
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | No secrets / Non-commit command | Commit proceeds |
| 0 + deny JSON | Secrets detected | Commit blocked |
| 2 | Error (parse, git failure, timeout) | Commit blocked (fail-closed) |

## Usage Examples

**Clean commit:**
```bash
git commit -m "Add feature"
# -> check_secrets.py scans staged files
# -> No secrets found
# -> Commit proceeds
```

**Blocked commit:**
```bash
git commit -m "Add API integration"
# -> check_secrets.py scans staged files
# -> Found: sk-abc123... in src/api.py:42
# -> Commit blocked with detailed report
```

## Running Tests

```bash
# Run with pytest
python -m pytest security-hooks/scripts/test_check_secrets.py -v

# Or run directly
python security-hooks/scripts/test_check_secrets.py
```

**Test Coverage:** 70+ tests across 12 test classes covering:
- .env parsing and filtering
- Binary/env file detection
- All 24 secret patterns
- Line number calculation
- Main function integration
- Error handling (fail-closed)

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CLAUDE_PROJECT_DIR` | Project root for .env file lookup |
| `CLAUDE_PLUGIN_ROOT` | Plugin installation directory |

## Remediation Guidance

1. **Remove the hardcoded secret** from the file
2. **Use environment variables:**
   ```python
   import os
   api_key = os.getenv("API_KEY")
   ```
3. **Ensure .env is gitignored**
4. **Use a secrets manager** for production
5. **Rotate exposed secrets** if accidentally committed

## Best Practices

### For Developers
- Never hardcode secrets
- Use separate credentials per environment
- Document required environment variables

### For CI/CD
- Inject secrets at deploy time
- Scan commit history with `git-secrets`
- Audit secret access

## Limitations

- Cannot catch obfuscated secrets
- Pattern-based only (unknown formats won't match)
- Context-blind (secrets in comments still flagged)
- Requires .env file for hardcoded value detection
- Files >10MB skipped

## Debugging

1. **Verify hook config:** Check `hooks/hooks.json`
2. **Test manually:**
   ```bash
   echo '{"tool_name": "Bash", "tool_input": {"command": "git commit -m test"}}' | \
     ./scripts/check_secrets.py
   ```
3. **Check stderr** for error messages
4. **Enable debug mode:** `claude --debug`

