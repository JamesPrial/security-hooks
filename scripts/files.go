package main

import (
	"path/filepath"
	"strings"
)

// IsEnvFile checks if a file path refers to an environment file that should be skipped.
// Handles both Unix (/) and Windows (\) path separators.
func IsEnvFile(filePath string) bool {
	// Replace all backslashes with forward slashes for consistent handling
	normalizedPath := strings.ReplaceAll(filePath, "\\", "/")

	// Get the filename (last component after splitting on /)
	parts := strings.Split(normalizedPath, "/")
	filename := parts[len(parts)-1]

	// Check if filename is in the envFileNames set
	if _, exists := envFileNames[filename]; exists {
		return true
	}

	// Check if filename starts with .env.
	if strings.HasPrefix(filename, ".env.") {
		return true
	}

	return false
}

// IsBinaryFile checks if a file has a binary extension that should be skipped.
// Case-insensitive matching. Handles compound extensions like .min.js.
func IsBinaryFile(filePath string) bool {
	// Lowercase the full path for case-insensitive matching
	lowerPath := strings.ToLower(filePath)

	// Check single-dot extensions using filepath.Ext
	ext := filepath.Ext(lowerPath)
	if _, exists := binaryExtensions[ext]; exists {
		return true
	}

	// Check compound extensions
	for _, compoundExt := range compoundBinaryExtensions {
		if strings.HasSuffix(lowerPath, compoundExt) {
			return true
		}
	}

	return false
}
