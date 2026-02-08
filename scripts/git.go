package main

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
)

var (
	// Pre-compiled regexes for git commit detection
	commandSeparatorRegex = regexp.MustCompile(`[;&|]+`)
	gitCommandRegex       = regexp.MustCompile(`(?i)^(?:\S+[/\\])?git(?:\.exe)?\b`)
	commitWordRegex       = regexp.MustCompile(`(?i)\bcommit\b`)
)

// IsGitCommitCommand checks if a command string contains a git commit operation.
// Splits command by separators and checks each subcommand.
func IsGitCommitCommand(command string) bool {
	// Split command on separators: ; & |
	subcommands := commandSeparatorRegex.Split(command, -1)

	for _, subcommand := range subcommands {
		subcommand = strings.TrimSpace(subcommand)
		if subcommand == "" {
			continue
		}

		// Check if subcommand starts with git (handles git, /path/to/git, git.exe)
		if !gitCommandRegex.MatchString(subcommand) {
			continue
		}

		// Check if the git command contains the word "commit"
		if commitWordRegex.MatchString(subcommand) {
			return true
		}
	}

	return false
}

// GetStagedFiles returns the list of staged file paths via "git diff --cached --name-only".
func GetStagedFiles() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), SubprocessTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "diff", "--cached", "--name-only")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Split output by newlines and filter empty strings
	lines := strings.Split(string(output), "\n")
	var files []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}

	return files, nil
}

// GetStagedContent reads file content from the git staging area via "git show :filepath".
func GetStagedContent(filePath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), SubprocessTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "show", ":"+filePath)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}
