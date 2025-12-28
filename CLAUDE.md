# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Plugin Overview

**security-hooks** is a Claude Code PreToolUse hook that scans staged files for secrets before git commits. It runs automatically when Claude attempts `git commit` operations.

See the parent [CLAUDE.md](../CLAUDE.md) for marketplace-wide architecture and plugin system documentation.

## Development Commands

```bash
# Run tests (from repo root or this directory)
python -m pytest scripts/test_check_secrets.py -v

# Run a single test class
python -m pytest scripts/test_check_secrets.py::TestCheckFileForSecrets -v

# Run a single test
python -m pytest scripts/test_check_secrets.py::TestCheckFileForSecrets::test_check_file_for_secrets_aws_key -v

# Manual hook testing (simulates hook input)
echo '{"tool_name": "Bash", "tool_input": {"command": "git commit -m test"}}' | ./scripts/check_secrets.py
```

## Architecture

### Core Detection Logic (`scripts/check_secrets.py`)

**Entry Flow:**
1. `main()` → Parses stdin JSON, validates it's a Bash tool with `git commit`
2. `_run_secret_check()` → Orchestrates the scan
3. `check_file_for_secrets()` → Scans individual files against patterns and .env values

**Key Data Structures:**
- `SECRET_PATTERNS`: List of `(compiled_regex, description)` tuples (24 patterns, pre-compiled at module load)
- `BINARY_EXTENSIONS`, `ENV_FILE_NAMES`, `SKIP_VALUES`: Frozensets for O(1) lookups

**TOCTOU Safety:** All file content is read from git staging area via `git show :filepath`, not from disk.

**Exit Behavior:**
- Secrets found: Exit 0 with JSON `{"hookSpecificOutput": {"permissionDecision": "deny", ...}}`
- No secrets: Exit 0
- Parse/git errors: Exit 2 (fail-closed)

### Test Suite (`scripts/test_check_secrets.py`)

70+ tests across 12 test classes:
- `TestParseEnvFile`: .env parsing edge cases
- `TestFilterEnvValues`: Secret value filtering
- `TestCheckFileForSecrets`: Pattern detection for all 24 secret types
- `TestMain`: Integration tests with mocked git operations

## Key Implementation Details

**Pattern matching uses pre-compiled regex** at module load for performance:
```python
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), "OpenAI API key"),
    # ... 23 more patterns
]
```

**Git commit detection uses word boundaries** to avoid false positives:
```python
re.search(r'\bgit\b.*\bcommit\b', command, re.IGNORECASE)
```

**.env value patterns are compiled once per scan**, not per file:
```python
env_patterns = {key: re.compile(rf'\b{re.escape(value)}\b') for key, value in secret_env_values.items()}
```

## Adding New Secret Patterns

1. Add pattern to `SECRET_PATTERNS` list in `check_secrets.py:74-118`
2. Add test case in `TestCheckFileForSecrets` or `TestNewSecretPatterns` class
3. Update pattern count in README and parent CLAUDE.md

## Common Issues

- **Tests fail with import error**: Run from repo root or ensure `scripts/` is in PYTHONPATH
- **Hook not triggering**: Reinstall plugin after code changes (`/plugin uninstall` then `/plugin install`)
- **False positives**: Check if pattern is too greedy; consider adding to `SKIP_VALUES` or adjusting regex
