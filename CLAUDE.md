# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Plugin Overview

**security-hooks** is a Claude Code PreToolUse hook that scans staged files for secrets before git commits. It runs automatically when Claude attempts `git commit` operations. Implemented in Go as a compiled binary.

See the parent [CLAUDE.md](../CLAUDE.md) for marketplace-wide architecture and plugin system documentation.

## Development Commands

```bash
# Build the binary (required before first use)
make build

# Run all tests with race detection and coverage
make test

# Build and test
make install

# Clean build artifacts
make clean

# Run tests directly
cd scripts && go test -v -race -cover ./...

# Run a specific test
cd scripts && go test -v -run TestIsGitCommitCommand ./...

# Manual hook testing (simulates hook input)
echo '{"tool_name": "Bash", "tool_input": {"command": "git commit -m test"}}' | ./scripts/check-secrets
```

## Architecture

### Source Files (`scripts/`)

All Go source is in a single `main` package under `scripts/`.

| File | Purpose |
|------|---------|
| `main.go` | Entry point: stdin JSON parsing, validation, orchestration, deny output |
| `scanner.go` | Core scanning: `CheckFileForSecrets`, `GetLineNumber`, `CompileEnvPatterns` |
| `patterns.go` | All constants, sets, and 26 pre-compiled regex patterns |
| `env.go` | `.env` file parsing: `ParseEnvFile`, `FilterEnvValues` |
| `files.go` | File type detection: `IsEnvFile`, `IsBinaryFile` |
| `git.go` | Git operations: `GetStagedFiles`, `GetStagedContent`, `IsGitCommitCommand` |

**Entry Flow:**
1. `main()` → Parses stdin JSON, validates it's a Bash tool with `git commit`
2. `runSecretCheck()` → Orchestrates the scan (parse .env, get staged files, scan each)
3. `CheckFileForSecrets()` → Scans individual files against patterns and .env values

**Key Data Structures:**
- `secretPatterns`: Slice of `SecretPattern` structs (26 entries, pre-compiled at package init)
- `binaryExtensions`, `envFileNames`, `skipValues`: `map[string]struct{}` for O(1) lookups

**TOCTOU Safety:** All file content is read from git staging area via `git show :filepath`, not from disk.

**Exit Behavior:**
- Secrets found: Exit 2 with JSON `{"hookSpecificOutput": {"permissionDecision": "deny", ...}}`
- No secrets: Exit 0
- Parse/git errors: Exit 2 (fail-closed)

### Test Suite

87+ tests across 10 test files covering:
- Pattern compilation and constant verification (`patterns_test.go`)
- `.env` parsing and filtering edge cases (`env_test.go`)
- File type detection (`files_test.go`)
- Secret pattern detection for all 26 types (`scanner_test.go`)
- Git commit command detection (`git_test.go`)
- Full integration tests via compiled binary (`main_test.go`)

## Key Implementation Details

**Pattern matching uses pre-compiled regex** at package level for performance:
```go
var secretPatterns = []SecretPattern{
    {regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "OpenAI API key"},
    // ... 25 more patterns
}
```

**Git commit detection uses word boundaries** to avoid false positives:
```go
var gitCommandRegex = regexp.MustCompile(`(?i)^(?:\S+[/\\])?git(?:\.exe)?\b`)
var commitWordRegex = regexp.MustCompile(`(?i)\bcommit\b`)
```

**.env value patterns are compiled once per scan**, not per file:
```go
envPatterns := CompileEnvPatterns(secretEnvValues) // \b word boundaries
```

## Adding New Secret Patterns

1. Add pattern to `secretPatterns` slice in `scripts/patterns.go`
2. Add test case in `Test_CheckFileForSecrets_Cases` or `Test_NewSecretPatterns` in `scripts/scanner_test.go`
3. Update pattern count in `Test_SecretPatterns_Count` in `scripts/patterns_test.go`

## Common Issues

- **Binary not found**: Run `make build` to compile the Go binary
- **Hook not triggering**: Reinstall plugin after code changes (`/plugin uninstall` then `/plugin install`)
- **False positives**: Check if pattern is too greedy; consider adding to `skipValues` or adjusting regex
- **Tests need Go**: Requires Go 1.22+ installed (`go version`)
