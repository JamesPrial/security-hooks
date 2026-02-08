package main

import (
	"bufio"
	"os"
	"strings"
)

// ParseEnvFile reads a .env file and returns a dictionary of key-value pairs.
// Returns an empty map if the file does not exist or cannot be read.
// Handles: comments (#), empty lines, quoted values (single/double),
// multiple equals signs, whitespace trimming.
func ParseEnvFile(envPath string) map[string]string {
	envVars := make(map[string]string)

	// Open the file, return empty map if it doesn't exist or can't be read
	file, err := os.Open(envPath)
	if err != nil {
		return envVars
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first '=' only
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Strip matching surrounding quotes
		if len(value) >= 2 {
			firstChar := value[0]
			lastChar := value[len(value)-1]

			// Only remove quotes if they match (both single or both double)
			if (firstChar == '"' && lastChar == '"') || (firstChar == '\'' && lastChar == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		// Only add to map if both key and value are non-empty
		if key != "" && value != "" {
			envVars[key] = value
		}
	}

	return envVars
}

// FilterEnvValues filters env vars to only those likely to be secrets.
// Removes: values shorter than MinSecretLength, values in skipValues (case-insensitive),
// and numeric-only values.
func FilterEnvValues(envVars map[string]string) map[string]string {
	filtered := make(map[string]string)

	for key, value := range envVars {
		// Skip short values (likely not secrets)
		if len(value) < MinSecretLength {
			continue
		}

		// Skip common non-secret values (case-insensitive)
		if _, exists := skipValues[strings.ToLower(value)]; exists {
			continue
		}

		// Skip numeric-only values
		if isAllDigits(value) {
			continue
		}

		filtered[key] = value
	}

	return filtered
}

// isAllDigits checks if a string contains only digit characters.
func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}

	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}

	return true
}
