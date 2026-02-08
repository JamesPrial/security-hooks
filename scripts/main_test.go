package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testBinary holds the path to the compiled check-secrets binary.
// Built once by TestMain before any tests run. Empty string if build failed.
var testBinary string

// testBinaryBuildErr holds the build error message if the binary failed to compile.
var testBinaryBuildErr string

func TestMain(m *testing.M) {
	// Build the binary once for all tests.
	dir, err := os.MkdirTemp("", "check-secrets-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir for test binary: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	binaryName := "check-secrets"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	testBinary = filepath.Join(dir, binaryName)
	cmd := exec.Command("go", "build", "-o", testBinary, ".")
	// go test sets cwd to the package directory, so "." resolves correctly.
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		// Don't panic -- let unit tests in other files still run.
		// Integration tests in this file will skip.
		testBinaryBuildErr = fmt.Sprintf("failed to build test binary: %v\n%s", err, string(out))
		testBinary = ""
		fmt.Fprintln(os.Stderr, testBinaryBuildErr)
	}

	os.Exit(m.Run())
}

// requireBinary skips the test if the binary was not successfully built.
func requireBinary(t *testing.T) {
	t.Helper()
	if testBinary == "" {
		t.Skipf("test binary not available: %s", testBinaryBuildErr)
	}
}

// runBinary runs the compiled binary with the given stdin and optional environment overrides.
// Returns exit code, stdout, and stderr.
func runBinary(t *testing.T, stdin string, env ...string) (exitCode int, stdout string, stderr string) {
	t.Helper()
	requireBinary(t)

	cmd := exec.Command(testBinary)
	cmd.Stdin = bytes.NewBufferString(stdin)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// Start with a clean environment, inheriting PATH for git access.
	baseEnv := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	cmd.Env = append(baseEnv, env...)

	err := cmd.Run()
	exitCode = 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("unexpected error running binary: %v", err)
	}

	return exitCode, outBuf.String(), errBuf.String()
}

// runBinaryInDir runs the compiled binary with the given stdin in a specific working directory.
func runBinaryInDir(t *testing.T, dir string, stdin string, env ...string) (exitCode int, stdout string, stderr string) {
	t.Helper()
	requireBinary(t)

	cmd := exec.Command(testBinary)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewBufferString(stdin)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	baseEnv := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	cmd.Env = append(baseEnv, env...)

	err := cmd.Run()
	exitCode = 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("unexpected error running binary: %v", err)
	}

	return exitCode, outBuf.String(), errBuf.String()
}

// setupGitRepo creates a temporary git repository with basic config.
// Returns the directory path. Cleanup is handled by t.TempDir().
func setupGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// git init
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, out)
	}

	// Set git config so commits don't fail
	gitConfig(t, dir, "user.email", "test@test.com")
	gitConfig(t, dir, "user.name", "Test")

	return dir
}

// gitConfig sets a git config value in the given repo directory.
func gitConfig(t *testing.T, dir, key, value string) {
	t.Helper()
	cmd := exec.Command("git", "config", key, value)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config %s %s failed: %v\n%s", key, value, err, out)
	}
}

// gitAdd stages a file in the given repo directory.
func gitAdd(t *testing.T, dir, filePath string) {
	t.Helper()
	cmd := exec.Command("git", "add", filePath)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add %s failed: %v\n%s", filePath, err, out)
	}
}

// writeTestFile creates a file with the given content relative to dir.
func writeTestFile(t *testing.T, dir, relPath, content string) string {
	t.Helper()
	fullPath := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("failed to create directory for %s: %v", relPath, err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write file %s: %v", relPath, err)
	}
	return fullPath
}

// gitCommitInput returns the standard stdin JSON for a git commit command.
func gitCommitInput(msg string) string {
	return `{"tool_name":"Bash","tool_input":{"command":"git commit -m '` + msg + `'"}}`
}

// hookOutputJSON is the struct used for parsing stdout from the binary.
type hookOutputJSON struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// ---------------------------------------------------------------------------
// Test_Main_NonBashTool - non-Bash tools should be allowed immediately
// ---------------------------------------------------------------------------

func Test_Main_NonBashTool(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
	}{
		{
			name:  "Read tool with file_path",
			stdin: `{"tool_name":"Read","tool_input":{"file_path":"/some/path"}}`,
		},
		{
			name:  "Write tool",
			stdin: `{"tool_name":"Write","tool_input":{"file_path":"/some/path","content":"hello"}}`,
		},
		{
			name:  "Glob tool",
			stdin: `{"tool_name":"Glob","tool_input":{"pattern":"*.go"}}`,
		},
		{
			name:  "Task tool",
			stdin: `{"tool_name":"Task","tool_input":{"description":"do something"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, stdout, _ := runBinary(t, tt.stdin)

			if exitCode != 0 {
				t.Errorf("expected exit code 0 for non-Bash tool, got %d", exitCode)
			}
			if stdout != "" {
				t.Errorf("expected empty stdout for non-Bash tool, got %q", stdout)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_NonCommitCommand - Bash commands that are not git commit should pass
// ---------------------------------------------------------------------------

func Test_Main_NonCommitCommand(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
	}{
		{
			name:  "git status",
			stdin: `{"tool_name":"Bash","tool_input":{"command":"git status"}}`,
		},
		{
			name:  "git log",
			stdin: `{"tool_name":"Bash","tool_input":{"command":"git log --oneline"}}`,
		},
		{
			name:  "git diff",
			stdin: `{"tool_name":"Bash","tool_input":{"command":"git diff HEAD"}}`,
		},
		{
			name:  "ls command",
			stdin: `{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`,
		},
		{
			name:  "echo command",
			stdin: `{"tool_name":"Bash","tool_input":{"command":"echo hello"}}`,
		},
		{
			name:  "git add only",
			stdin: `{"tool_name":"Bash","tool_input":{"command":"git add ."}}`,
		},
		{
			name:  "git push",
			stdin: `{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, stdout, _ := runBinary(t, tt.stdin)

			if exitCode != 0 {
				t.Errorf("expected exit code 0 for non-commit command, got %d", exitCode)
			}
			if stdout != "" {
				t.Errorf("expected empty stdout for non-commit command, got %q", stdout)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_InvalidJSON - malformed JSON should cause exit 2 (fail-closed)
// ---------------------------------------------------------------------------

func Test_Main_InvalidJSON(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
	}{
		{
			name:  "completely invalid",
			stdin: "not valid json",
		},
		{
			name:  "truncated JSON",
			stdin: `{"tool_name":"Bash"`,
		},
		{
			name:  "empty string",
			stdin: "",
		},
		{
			name:  "just whitespace",
			stdin: "   \n\t  ",
		},
		{
			name:  "array instead of object",
			stdin: `["Bash", "git commit"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, stdout, stderr := runBinary(t, tt.stdin)

			if exitCode != 2 {
				t.Errorf("expected exit code 2 for invalid JSON, got %d", exitCode)
			}
			if stdout != "" {
				t.Errorf("expected empty stdout for invalid JSON, got %q", stdout)
			}
			// Stderr should have some error indication
			if stderr == "" {
				t.Error("expected non-empty stderr for invalid JSON, got empty")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_ToolInputIsString - tool_input as a string should be handled gracefully
// ---------------------------------------------------------------------------

func Test_Main_ToolInputIsString(t *testing.T) {
	stdin := `{"tool_name":"Bash","tool_input":"string instead of dict"}`

	exitCode, stdout, _ := runBinary(t, stdin)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 for string tool_input, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout for string tool_input, got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test_Main_ToolInputIsNull - tool_input as null should be handled gracefully
// ---------------------------------------------------------------------------

func Test_Main_ToolInputIsNull(t *testing.T) {
	stdin := `{"tool_name":"Bash","tool_input":null}`

	exitCode, stdout, _ := runBinary(t, stdin)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 for null tool_input, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout for null tool_input, got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test_Main_GitCommitNoStagedFiles - git commit with no staged files should pass
// ---------------------------------------------------------------------------

func Test_Main_GitCommitNoStagedFiles(t *testing.T) {
	dir := setupGitRepo(t)

	stdin := gitCommitInput("test commit")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 for git commit with no staged files, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout for git commit with no staged files, got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test_Main_GitCommitWithSecrets - staged files containing secrets should be blocked
// ---------------------------------------------------------------------------

func Test_Main_GitCommitWithSecrets(t *testing.T) {
	tests := []struct {
		name          string
		fileName      string
		fileContent   string
		wantSubstring string // expected in permissionDecisionReason
	}{
		{
			name:          "Anthropic API key",
			fileName:      "config.py",
			fileContent:   "api_key = 'sk-ant-" + strings.Repeat("a", 30) + "'",
			wantSubstring: "SECURITY WARNING",
		},
		{
			name:          "AWS Access Key ID",
			fileName:      "aws_config.py",
			fileContent:   "aws_key = 'AKIA2B3C4D5E6F7G8H9I'",
			wantSubstring: "SECURITY WARNING",
		},
		{
			name:          "GitHub PAT",
			fileName:      "github.py",
			fileContent:   "token = 'ghp_" + strings.Repeat("A", 36) + "'",
			wantSubstring: "SECURITY WARNING",
		},
		{
			name:          "Private key header",
			fileName:      "key.pem",
			fileContent:   "-----BEGIN RSA PRIVATE KEY-----\nMIIContent\n-----END RSA PRIVATE KEY-----\n",
			wantSubstring: "SECURITY WARNING",
		},
		{
			name:          "PostgreSQL connection string",
			fileName:      "db.py",
			fileContent:   "db_url = 'postgresql://user:secretpass@localhost/db'",
			wantSubstring: "SECURITY WARNING",
		},
		{
			name:          "OpenAI API key",
			fileName:      "openai.py",
			fileContent:   "openai_key = 'sk-abcdefghij1234567890'",
			wantSubstring: "SECURITY WARNING",
		},
		{
			name:          "Stripe secret key",
			fileName:      "payment.py",
			fileContent:   "stripe_key = 'sk_live_" + strings.Repeat("x", 25) + "'",
			wantSubstring: "SECURITY WARNING",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := setupGitRepo(t)

			writeTestFile(t, dir, tt.fileName, tt.fileContent)
			gitAdd(t, dir, tt.fileName)

			stdin := gitCommitInput("test commit with secrets")

			exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
				"CLAUDE_PROJECT_DIR="+dir,
			)

			if exitCode != 2 {
				t.Errorf("expected exit code 2 (blocked) for secrets in staged files, got %d", exitCode)
			}

			if stdout == "" {
				t.Fatal("expected non-empty stdout with deny JSON, got empty")
			}

			// Parse the JSON output
			var output hookOutputJSON
			if err := json.Unmarshal([]byte(stdout), &output); err != nil {
				t.Fatalf("failed to parse stdout JSON: %v\nstdout was: %q", err, stdout)
			}

			if output.HookSpecificOutput.HookEventName != "PreToolUse" {
				t.Errorf("hookEventName = %q, want %q",
					output.HookSpecificOutput.HookEventName, "PreToolUse")
			}

			if output.HookSpecificOutput.PermissionDecision != "deny" {
				t.Errorf("permissionDecision = %q, want %q",
					output.HookSpecificOutput.PermissionDecision, "deny")
			}

			if !strings.Contains(output.HookSpecificOutput.PermissionDecisionReason, tt.wantSubstring) {
				t.Errorf("permissionDecisionReason does not contain %q, got: %q",
					tt.wantSubstring, output.HookSpecificOutput.PermissionDecisionReason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_GitCommitCleanFiles - staged files without secrets should pass
// ---------------------------------------------------------------------------

func Test_Main_GitCommitCleanFiles(t *testing.T) {
	tests := []struct {
		name        string
		fileName    string
		fileContent string
	}{
		{
			name:        "simple Python file",
			fileName:    "hello.py",
			fileContent: "def hello():\n    print('Hello, World!')\n",
		},
		{
			name:        "Go source file",
			fileName:    "app.go",
			fileContent: "package app\n\nfunc Hello() string {\n    return \"hello\"\n}\n",
		},
		{
			name:        "JavaScript file",
			fileName:    "index.js",
			fileContent: "const x = 42;\nconsole.log(x);\n",
		},
		{
			name:        "markdown documentation",
			fileName:    "README.md",
			fileContent: "# My Project\n\nThis is a clean file with no secrets.\n",
		},
		{
			name:        "JSON config without secrets",
			fileName:    "config.json",
			fileContent: `{"debug": true, "port": 8080, "name": "myapp"}` + "\n",
		},
		{
			name:        "file with short strings that look like prefixes",
			fileName:    "notes.txt",
			fileContent: "sk-short\nghp_short\nAKIA\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := setupGitRepo(t)

			writeTestFile(t, dir, tt.fileName, tt.fileContent)
			gitAdd(t, dir, tt.fileName)

			stdin := gitCommitInput("test clean commit")

			exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
				"CLAUDE_PROJECT_DIR="+dir,
			)

			if exitCode != 0 {
				t.Errorf("expected exit code 0 for clean files, got %d", exitCode)
			}
			if stdout != "" {
				t.Errorf("expected empty stdout for clean files, got %q", stdout)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_SkipsBinaryFiles - binary files should be skipped (not scanned)
// ---------------------------------------------------------------------------

func Test_Main_SkipsBinaryFiles(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		content  []byte
	}{
		{
			name:     "PNG image",
			fileName: "image.png",
			content:  []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
		},
		{
			name:     "JPEG image",
			fileName: "photo.jpg",
			content:  []byte{0xFF, 0xD8, 0xFF, 0xE0},
		},
		{
			name:     "PDF file",
			fileName: "doc.pdf",
			content:  []byte("%PDF-1.4 some binary content"),
		},
		{
			name:     "ZIP archive",
			fileName: "archive.zip",
			content:  []byte{0x50, 0x4B, 0x03, 0x04},
		},
		{
			name:     "compiled binary",
			fileName: "program.exe",
			content:  []byte{0x4D, 0x5A, 0x90, 0x00},
		},
		{
			name:     "wasm module",
			fileName: "module.wasm",
			content:  []byte{0x00, 0x61, 0x73, 0x6D},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := setupGitRepo(t)

			fullPath := filepath.Join(dir, tt.fileName)
			if err := os.WriteFile(fullPath, tt.content, 0o644); err != nil {
				t.Fatalf("failed to write binary file: %v", err)
			}
			gitAdd(t, dir, tt.fileName)

			stdin := gitCommitInput("test binary skip")

			exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
				"CLAUDE_PROJECT_DIR="+dir,
			)

			if exitCode != 0 {
				t.Errorf("expected exit code 0 (binary files skipped), got %d", exitCode)
			}
			if stdout != "" {
				t.Errorf("expected empty stdout (binary files skipped), got %q", stdout)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_SkipsEnvFiles - .env files should be skipped (not scanned)
// ---------------------------------------------------------------------------

func Test_Main_SkipsEnvFiles(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
	}{
		{
			name:     ".env file",
			fileName: ".env",
		},
		{
			name:     ".env.local file",
			fileName: ".env.local",
		},
		{
			name:     ".env.production file",
			fileName: ".env.production",
		},
		{
			name:     ".env.development file",
			fileName: ".env.development",
		},
	}

	// Content that would normally trigger a secret detection
	secretContent := "API_KEY=sk-ant-" + strings.Repeat("a", 30) + "\nSECRET=ghp_" + strings.Repeat("B", 36) + "\n"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := setupGitRepo(t)

			writeTestFile(t, dir, tt.fileName, secretContent)
			gitAdd(t, dir, tt.fileName)

			stdin := gitCommitInput("test env skip")

			exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
				"CLAUDE_PROJECT_DIR="+dir,
			)

			if exitCode != 0 {
				t.Errorf("expected exit code 0 (.env files skipped), got %d", exitCode)
			}
			if stdout != "" {
				t.Errorf("expected empty stdout (.env files skipped), got %q", stdout)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_GitCommitDenyOutputStructure - verify the full JSON structure
// ---------------------------------------------------------------------------

func Test_Main_GitCommitDenyOutputStructure(t *testing.T) {
	dir := setupGitRepo(t)

	// Stage a file with a well-known secret pattern
	secretContent := "api_key = 'sk-ant-" + strings.Repeat("x", 30) + "'"
	writeTestFile(t, dir, "secrets.py", secretContent)
	gitAdd(t, dir, "secrets.py")

	stdin := gitCommitInput("test output structure")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	// Verify it is valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, stdout)
	}

	// Verify top-level key exists
	hookOutput, ok := raw["hookSpecificOutput"]
	if !ok {
		t.Fatal("missing top-level key 'hookSpecificOutput' in output JSON")
	}

	hookMap, ok := hookOutput.(map[string]interface{})
	if !ok {
		t.Fatalf("hookSpecificOutput is not an object, got %T", hookOutput)
	}

	// Verify all required fields exist and have correct values
	requiredFields := map[string]string{
		"hookEventName":      "PreToolUse",
		"permissionDecision": "deny",
	}

	for field, expectedValue := range requiredFields {
		val, exists := hookMap[field]
		if !exists {
			t.Errorf("missing field %q in hookSpecificOutput", field)
			continue
		}
		strVal, ok := val.(string)
		if !ok {
			t.Errorf("field %q is not a string, got %T", field, val)
			continue
		}
		if strVal != expectedValue {
			t.Errorf("field %q = %q, want %q", field, strVal, expectedValue)
		}
	}

	// Verify permissionDecisionReason exists and is a non-empty string
	reason, exists := hookMap["permissionDecisionReason"]
	if !exists {
		t.Error("missing field 'permissionDecisionReason' in hookSpecificOutput")
	} else {
		reasonStr, ok := reason.(string)
		if !ok {
			t.Errorf("permissionDecisionReason is not a string, got %T", reason)
		} else if reasonStr == "" {
			t.Error("permissionDecisionReason is empty")
		} else if !strings.Contains(reasonStr, "SECURITY WARNING") {
			t.Errorf("permissionDecisionReason does not contain 'SECURITY WARNING', got: %q", reasonStr)
		}
	}
}

// ---------------------------------------------------------------------------
// Test_Main_MultipleSecretsInMultipleFiles - multiple files with different secrets
// ---------------------------------------------------------------------------

func Test_Main_MultipleSecretsInMultipleFiles(t *testing.T) {
	dir := setupGitRepo(t)

	// Stage multiple files with different secret patterns
	writeTestFile(t, dir, "aws.py", "key = 'AKIA2B3C4D5E6F7G8H9I'")
	gitAdd(t, dir, "aws.py")

	writeTestFile(t, dir, "github.py", "token = 'ghp_"+strings.Repeat("A", 36)+"'")
	gitAdd(t, dir, "github.py")

	writeTestFile(t, dir, "anthropic.py", "key = 'sk-ant-"+strings.Repeat("b", 30)+"'")
	gitAdd(t, dir, "anthropic.py")

	stdin := gitCommitInput("test multiple secrets")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	if exitCode != 2 {
		t.Errorf("expected exit code 2 for multiple files with secrets, got %d", exitCode)
	}

	if stdout == "" {
		t.Fatal("expected non-empty stdout with deny JSON, got empty")
	}

	var output hookOutputJSON
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("failed to parse stdout JSON: %v", err)
	}

	if output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q",
			output.HookSpecificOutput.PermissionDecision, "deny")
	}
}

// ---------------------------------------------------------------------------
// Test_Main_MixedCleanAndSecretFiles - only secrets in some files should still block
// ---------------------------------------------------------------------------

func Test_Main_MixedCleanAndSecretFiles(t *testing.T) {
	dir := setupGitRepo(t)

	// Stage a clean file
	writeTestFile(t, dir, "clean.py", "def hello():\n    print('world')\n")
	gitAdd(t, dir, "clean.py")

	// Stage a file with secrets
	writeTestFile(t, dir, "secret.py", "key = 'sk-ant-"+strings.Repeat("x", 30)+"'")
	gitAdd(t, dir, "secret.py")

	stdin := gitCommitInput("test mixed files")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	if exitCode != 2 {
		t.Errorf("expected exit code 2 (blocked by secret in one file), got %d", exitCode)
	}

	if stdout == "" {
		t.Fatal("expected non-empty stdout with deny JSON, got empty")
	}

	var output hookOutputJSON
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("failed to parse stdout JSON: %v", err)
	}

	if output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q",
			output.HookSpecificOutput.PermissionDecision, "deny")
	}
}

// ---------------------------------------------------------------------------
// Test_Main_GitCommitVariants - different ways to express git commit
// ---------------------------------------------------------------------------

func Test_Main_GitCommitVariants(t *testing.T) {
	// These tests verify that various git commit command formats are recognized.
	// Each test stages a file with secrets and checks the binary blocks the commit.
	tests := []struct {
		name    string
		command string
	}{
		{
			name:    "basic git commit",
			command: "git commit -m 'test'",
		},
		{
			name:    "git commit with double quotes",
			command: `git commit -m \"test message\"`,
		},
		{
			name:    "git commit --amend",
			command: "git commit --amend",
		},
		{
			name:    "git commit with -a flag",
			command: "git commit -a -m 'test'",
		},
		{
			name:    "git commit with long message flag",
			command: "git commit --message='test'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := setupGitRepo(t)

			writeTestFile(t, dir, "secret.py", "key = 'sk-ant-"+strings.Repeat("z", 30)+"'")
			gitAdd(t, dir, "secret.py")

			stdin := `{"tool_name":"Bash","tool_input":{"command":"` + tt.command + `"}}`

			exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
				"CLAUDE_PROJECT_DIR="+dir,
			)

			if exitCode != 2 {
				t.Errorf("expected exit code 2 for command %q with secrets staged, got %d",
					tt.command, exitCode)
			}
			if stdout == "" {
				t.Errorf("expected non-empty stdout for command %q with secrets staged", tt.command)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_CompoundBinaryExtensionsSkipped - .min.js and .min.css should be skipped
// ---------------------------------------------------------------------------

func Test_Main_CompoundBinaryExtensionsSkipped(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
	}{
		{
			name:     "minified JavaScript",
			fileName: "bundle.min.js",
		},
		{
			name:     "minified CSS",
			fileName: "styles.min.css",
		},
	}

	// Content that would trigger secret detection if not skipped
	secretContent := "var key = 'sk-ant-" + strings.Repeat("a", 30) + "';"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := setupGitRepo(t)

			writeTestFile(t, dir, tt.fileName, secretContent)
			gitAdd(t, dir, tt.fileName)

			stdin := gitCommitInput("test compound ext skip")

			exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
				"CLAUDE_PROJECT_DIR="+dir,
			)

			if exitCode != 0 {
				t.Errorf("expected exit code 0 (compound binary ext skipped), got %d", exitCode)
			}
			if stdout != "" {
				t.Errorf("expected empty stdout (compound binary ext skipped), got %q", stdout)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test_Main_EnvFileUsedForScanning - .env file values should be checked in staged files
// ---------------------------------------------------------------------------

func Test_Main_EnvFileUsedForScanning(t *testing.T) {
	dir := setupGitRepo(t)

	// Create a .env file with a secret value (this should NOT be staged, but should be read)
	envContent := "MY_SECRET_KEY=super_secret_value_12345678\n"
	writeTestFile(t, dir, ".env", envContent)

	// Stage a source file that contains the hardcoded .env value
	sourceContent := "config = 'super_secret_value_12345678'\n"
	writeTestFile(t, dir, "app.py", sourceContent)
	gitAdd(t, dir, "app.py")

	stdin := gitCommitInput("test env value scanning")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	// The binary should detect the hardcoded .env value in the staged file
	if exitCode != 2 {
		t.Errorf("expected exit code 2 (hardcoded .env value detected), got %d", exitCode)
	}

	if stdout == "" {
		t.Fatal("expected non-empty stdout for hardcoded .env value detection, got empty")
	}

	var output hookOutputJSON
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("failed to parse stdout JSON: %v", err)
	}

	if output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q",
			output.HookSpecificOutput.PermissionDecision, "deny")
	}
}

// ---------------------------------------------------------------------------
// Test_Main_EmptyToolName - edge case: empty tool_name
// ---------------------------------------------------------------------------

func Test_Main_EmptyToolName(t *testing.T) {
	stdin := `{"tool_name":"","tool_input":{"command":"git commit -m 'test'"}}`

	exitCode, stdout, _ := runBinary(t, stdin)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 for empty tool_name (not Bash), got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout for empty tool_name, got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test_Main_MissingToolName - edge case: missing tool_name field
// ---------------------------------------------------------------------------

func Test_Main_MissingToolName(t *testing.T) {
	stdin := `{"tool_input":{"command":"git commit -m 'test'"}}`

	exitCode, stdout, _ := runBinary(t, stdin)

	// With no tool_name, the binary should treat this as a non-Bash tool and allow
	if exitCode != 0 {
		t.Errorf("expected exit code 0 for missing tool_name, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout for missing tool_name, got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test_Main_StdoutIsValidJSON - when blocking, stdout must always be valid JSON
// ---------------------------------------------------------------------------

func Test_Main_StdoutIsValidJSON(t *testing.T) {
	dir := setupGitRepo(t)

	writeTestFile(t, dir, "leak.py", "token = 'ghp_"+strings.Repeat("A", 36)+"'")
	gitAdd(t, dir, "leak.py")

	stdin := gitCommitInput("test json validity")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for test setup, got %d", exitCode)
	}

	if !json.Valid([]byte(stdout)) {
		t.Errorf("stdout is not valid JSON: %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test_Main_LockFileSkipped - .lock files should be treated as binary/skipped
// ---------------------------------------------------------------------------

func Test_Main_LockFileSkipped(t *testing.T) {
	dir := setupGitRepo(t)

	// A lock file that contains something that looks like a secret
	lockContent := "resolved \"https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz#sk-ant-" + strings.Repeat("a", 30) + "\"\n"
	writeTestFile(t, dir, "package-lock.lock", lockContent)
	gitAdd(t, dir, "package-lock.lock")

	stdin := gitCommitInput("test lock file skip")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 (.lock files skipped), got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout (.lock files skipped), got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test_Main_SVGFileSkipped - .svg files should be treated as binary/skipped
// ---------------------------------------------------------------------------

func Test_Main_SVGFileSkipped(t *testing.T) {
	dir := setupGitRepo(t)

	svgContent := `<svg xmlns="http://www.w3.org/2000/svg"><text>sk-ant-` + strings.Repeat("a", 30) + `</text></svg>`
	writeTestFile(t, dir, "icon.svg", svgContent)
	gitAdd(t, dir, "icon.svg")

	stdin := gitCommitInput("test svg skip")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 (.svg files skipped), got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout (.svg files skipped), got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test_Main_SubdirectoryFiles - secrets in files in subdirectories should be detected
// ---------------------------------------------------------------------------

func Test_Main_SubdirectoryFiles(t *testing.T) {
	dir := setupGitRepo(t)

	writeTestFile(t, dir, "src/config/secrets.py", "key = 'sk-ant-"+strings.Repeat("d", 30)+"'")
	gitAdd(t, dir, "src/config/secrets.py")

	stdin := gitCommitInput("test subdirectory secrets")

	exitCode, stdout, _ := runBinaryInDir(t, dir, stdin,
		"CLAUDE_PROJECT_DIR="+dir,
	)

	if exitCode != 2 {
		t.Errorf("expected exit code 2 for secrets in subdirectory, got %d", exitCode)
	}
	if stdout == "" {
		t.Error("expected non-empty stdout for secrets in subdirectory, got empty")
	}
}

// ---------------------------------------------------------------------------
// Test_Main_CaseSensitiveToolName - tool_name matching should be case-sensitive
// ---------------------------------------------------------------------------

func Test_Main_CaseSensitiveToolName(t *testing.T) {
	// "bash" (lowercase) is NOT the same as "Bash"
	stdin := `{"tool_name":"bash","tool_input":{"command":"git commit -m 'test'"}}`

	exitCode, stdout, _ := runBinary(t, stdin)

	// If tool_name is case-sensitive, "bash" != "Bash" and should be allowed
	if exitCode != 0 {
		t.Errorf("expected exit code 0 for lowercase 'bash' tool_name, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout for lowercase 'bash' tool_name, got %q", stdout)
	}
}
