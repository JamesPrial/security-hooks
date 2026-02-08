package main

import (
	"fmt"
	"regexp"
	"strings"
)

// GetLineNumber calculates the 1-based line number for a byte position in content.
func GetLineNumber(content string, position int) int {
	if position > len(content) {
		position = len(content)
	}
	if position < 0 {
		position = 0
	}
	return strings.Count(content[:position], "\n") + 1
}

// CompileEnvPatterns creates word-boundary-wrapped compiled regexes for each env value.
// Called once per scan, not per file.
func CompileEnvPatterns(secretEnvValues map[string]string) map[string]*regexp.Regexp {
	envPatterns := make(map[string]*regexp.Regexp)

	for key, value := range secretEnvValues {
		// Escape special regex characters and wrap with word boundaries
		pattern := `\b` + regexp.QuoteMeta(value) + `\b`
		envPatterns[key] = regexp.MustCompile(pattern)
	}

	return envPatterns
}

// CheckFileForSecrets scans file content against pre-compiled secret patterns and env value patterns.
// Returns (patternIssues, envIssues) where each issue is a string like:
//
//	"filepath:linenum - Found potential description"
//	"filepath:linenum - Found hardcoded value from .env key 'KEY'"
func CheckFileForSecrets(filePath, content string, envPatterns map[string]*regexp.Regexp) ([]string, []string) {
	var patternIssues []string
	var envIssues []string

	// Check against pre-compiled secret patterns
	for _, pattern := range secretPatterns {
		matches := pattern.Pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			start := match[0]
			lineNum := GetLineNumber(content, start)
			issue := fmt.Sprintf("%s:%d - Found potential %s", filePath, lineNum, pattern.Description)
			patternIssues = append(patternIssues, issue)
		}
	}

	// Check against environment value patterns
	for key, pattern := range envPatterns {
		matches := pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			start := match[0]
			lineNum := GetLineNumber(content, start)
			issue := fmt.Sprintf("%s:%d - Found hardcoded value from .env key '%s'", filePath, lineNum, key)
			envIssues = append(envIssues, issue)
		}
	}

	return patternIssues, envIssues
}
