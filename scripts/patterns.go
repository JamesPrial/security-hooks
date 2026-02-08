package main

import (
	"regexp"
	"time"
)

// Exit codes for the security hook.
const (
	ExitSuccess       = 0
	ExitBlocked       = 2
	MinSecretLength   = 8
	MaxFileSize       = 10 * 1024 * 1024 // 10MB
	SubprocessTimeout = 30 * time.Second
)

// SecretPattern represents a compiled regex pattern with its description.
type SecretPattern struct {
	Pattern     *regexp.Regexp
	Description string
}

// skipValues contains common non-secret values to skip (all lowercase).
var skipValues = map[string]struct{}{
	"true":        {},
	"false":       {},
	"yes":         {},
	"no":          {},
	"on":          {},
	"off":         {},
	"development": {},
	"production":  {},
	"staging":     {},
	"test":        {},
	"localhost":   {},
	"127.0.0.1":   {},
	"0.0.0.0":     {},
	"utf-8":       {},
	"utf8":        {},
	"none":        {},
	"null":        {},
}

// binaryExtensions contains single-dot binary file extensions (all lowercase).
var binaryExtensions = map[string]struct{}{
	".png":     {},
	".jpg":     {},
	".jpeg":    {},
	".gif":     {},
	".pdf":     {},
	".zip":     {},
	".wasm":    {},
	".exe":     {},
	".dll":     {},
	".so":      {},
	".pyc":     {},
	".class":   {},
	".woff":    {},
	".woff2":   {},
	".ttf":     {},
	".eot":     {},
	".ico":     {},
	".mp3":     {},
	".mp4":     {},
	".mov":     {},
	".tar":     {},
	".gz":      {},
	".7z":      {},
	".bin":     {},
	".dat":     {},
	".db":      {},
	".sqlite":  {},
	".sqlite3": {},
	".svg":     {},
	".lock":    {},
}

// compoundBinaryExtensions contains multi-dot binary file extensions (all lowercase).
var compoundBinaryExtensions = []string{
	".min.js",
	".min.css",
}

// envFileNames contains environment file names to skip.
var envFileNames = map[string]struct{}{
	".env":             {},
	".env.local":       {},
	".env.production":  {},
	".env.development": {},
	".env.test":        {},
	".env.staging":     {},
	".env.example":     {},
}

// secretPatterns contains all pre-compiled secret detection patterns.
var secretPatterns = []SecretPattern{
	// Generic secrets
	{regexp.MustCompile(`(?i)(secret|token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}`), "secret/token"},
	// AWS
	{regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]`), "AWS credentials"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key ID"},
	// OpenAI
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "OpenAI API key"},
	{regexp.MustCompile(`sk-proj-[a-zA-Z0-9]{20,}`), "OpenAI project API key"},
	// Google
	{regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "Google API key"},
	// GitHub
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "GitHub Personal Access Token"},
	{regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`), "GitHub OAuth Token"},
	{regexp.MustCompile(`ghu_[a-zA-Z0-9]{36}`), "GitHub User Token"},
	{regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`), "GitHub Server Token"},
	{regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`), "GitHub Refresh Token"},
	// Bearer tokens
	{regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`), "Bearer token"},
	// Private keys
	{regexp.MustCompile(`-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`), "Private key"},
	// Slack
	{regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9\-]{10,}`), "Slack token"},
	// Stripe
	{regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`), "Stripe secret key"},
	{regexp.MustCompile(`rk_live_[a-zA-Z0-9]{24,}`), "Stripe restricted key"},
	// SendGrid
	{regexp.MustCompile(`SG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}`), "SendGrid API key"},
	// Database connection strings
	{regexp.MustCompile(`mongodb(\+srv)?://[^:]+:[^@\s]+@`), "MongoDB connection string"},
	{regexp.MustCompile(`postgres(ql)?://[^:]+:[^@\s]+@`), "PostgreSQL connection string"},
	{regexp.MustCompile(`mysql://[^:]+:[^@\s]+@`), "MySQL connection string"},
	// Anthropic
	{regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-]{20,}`), "Anthropic API key"},
	// Discord
	{regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}`), "Discord bot token"},
	// npm
	{regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`), "npm access token"},
	// PyPI
	{regexp.MustCompile(`pypi-[a-zA-Z0-9]{43,}`), "PyPI API token"},
	// Twilio
	{regexp.MustCompile(`SK[a-fA-F0-9]{32}`), "Twilio API key"},
	// Mailgun
	{regexp.MustCompile(`key-[a-zA-Z0-9]{32}`), "Mailgun API key"},
}
