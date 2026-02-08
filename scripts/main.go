package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HookInput represents the JSON input received from Claude Code via stdin.
type HookInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// toolInput represents the parsed tool_input object.
type toolInput struct {
	Command string `json:"command"`
}

// hookOutput represents the JSON output sent to Claude Code via stdout.
type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

// hookSpecificOutput contains the permission decision fields.
type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

func main() {
	var input HookInput

	// Parse JSON input from stdin
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY: Hook failed to parse input: %v\n", err)
		os.Exit(ExitBlocked)
	}

	// Check if tool_name is "Bash"
	if input.ToolName != "Bash" {
		os.Exit(ExitSuccess)
	}

	// Try to parse tool_input as an object
	var ti toolInput
	if err := json.Unmarshal(input.ToolInput, &ti); err != nil {
		// tool_input is not an object (could be string, null, etc.)
		os.Exit(ExitSuccess)
	}

	// Check if the command is a git commit
	if !IsGitCommitCommand(ti.Command) {
		os.Exit(ExitSuccess)
	}

	// Get project root from environment or fallback to current directory
	projectDir := os.Getenv("CLAUDE_PROJECT_DIR")
	projectRoot := projectDir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "SECURITY: Failed to get working directory: %v\n", err)
			os.Exit(ExitBlocked)
		}
	}

	// Change to project root if CLAUDE_PROJECT_DIR was set
	if projectDir != "" {
		originalCwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "SECURITY: Failed to get current directory: %v\n", err)
			os.Exit(ExitBlocked)
		}
		if err := os.Chdir(projectRoot); err != nil {
			fmt.Fprintf(os.Stderr, "SECURITY: Failed to change directory: %v\n", err)
			os.Exit(ExitBlocked)
		}
		defer func() { _ = os.Chdir(originalCwd) }()
	}

	runSecretCheck(projectRoot)
}

// runSecretCheck orchestrates the secret scanning process.
func runSecretCheck(projectRoot string) {
	// Parse and filter .env file
	envPath := filepath.Join(projectRoot, ".env")
	envVars := ParseEnvFile(envPath)
	secretEnvValues := FilterEnvValues(envVars)

	// Get staged files
	stagedFiles, err := GetStagedFiles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY: Failed to get staged files: %v\n", err)
		os.Exit(ExitBlocked)
	}

	// Exit successfully if no staged files
	if len(stagedFiles) == 0 {
		os.Exit(ExitSuccess)
	}

	// Compile environment value patterns once for all files
	envPatterns := CompileEnvPatterns(secretEnvValues)

	// Collect all issues
	var allPatternIssues []string
	var allEnvIssues []string

	// Sort staged files for deterministic order
	sort.Strings(stagedFiles)

	for _, filePath := range stagedFiles {
		// Skip binary files
		if IsBinaryFile(filePath) {
			continue
		}

		// Skip .env files
		if IsEnvFile(filePath) {
			continue
		}

		// Get file content from staging area
		content, err := GetStagedContent(filePath)
		if err != nil {
			// Skip file if we can't read it
			continue
		}

		// Skip oversized files
		if len(content) > MaxFileSize {
			fmt.Fprintf(os.Stderr, "Warning: Skipping oversized staged content %s\n", filePath)
			continue
		}

		// Skip very small files
		if len(content) < 10 {
			continue
		}

		// Check file for secrets
		patternIssues, envIssues := CheckFileForSecrets(filePath, content, envPatterns)
		allPatternIssues = append(allPatternIssues, patternIssues...)
		allEnvIssues = append(allEnvIssues, envIssues...)
	}

	// If secrets were found, deny the operation
	if len(allPatternIssues) > 0 || len(allEnvIssues) > 0 {
		output := buildDenyOutput(allPatternIssues, allEnvIssues)
		fmt.Println(output)
		os.Exit(ExitBlocked)
	}

	os.Exit(ExitSuccess)
}

// buildDenyOutput creates the JSON output for denying a git commit due to detected secrets.
func buildDenyOutput(patternIssues, envIssues []string) string {
	var reasonParts []string

	reasonParts = append(reasonParts, "SECURITY WARNING: Potential secrets detected in staged files!")
	reasonParts = append(reasonParts, "")

	if len(patternIssues) > 0 {
		reasonParts = append(reasonParts, "Pattern-based detections:")
		// Sort issues for consistent output
		sortedPatternIssues := make([]string, len(patternIssues))
		copy(sortedPatternIssues, patternIssues)
		sort.Strings(sortedPatternIssues)

		for _, issue := range sortedPatternIssues {
			reasonParts = append(reasonParts, "  - "+issue)
		}
		reasonParts = append(reasonParts, "")
	}

	if len(envIssues) > 0 {
		reasonParts = append(reasonParts, "Hardcoded .env values detected:")
		// Sort issues for consistent output
		sortedEnvIssues := make([]string, len(envIssues))
		copy(sortedEnvIssues, envIssues)
		sort.Strings(sortedEnvIssues)

		for _, issue := range sortedEnvIssues {
			reasonParts = append(reasonParts, "  - "+issue)
		}
		reasonParts = append(reasonParts, "")
	}

	reasonParts = append(reasonParts, "Please remove secrets before committing.")

	if len(envIssues) > 0 {
		reasonParts = append(reasonParts, "Use environment variables at runtime instead of hardcoding values.")
	}

	reasonParts = append(reasonParts, "Consider using a secrets manager for sensitive credentials.")

	reasonText := strings.Join(reasonParts, "\n")

	output := hookOutput{
		HookSpecificOutput: hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reasonText,
		},
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		// This should never happen with our simple struct, but fail closed if it does
		fmt.Fprintf(os.Stderr, "SECURITY: Failed to marshal JSON output: %v\n", err)
		os.Exit(ExitBlocked)
	}

	return string(jsonBytes)
}
