package main

import (
	"regexp"
	"strings"
	"testing"
)

// containsSubstring checks whether any string in issues contains the given substring.
func containsSubstring(t *testing.T, issues []string, sub string) bool {
	t.Helper()
	for _, issue := range issues {
		if strings.Contains(issue, sub) {
			return true
		}
	}
	return false
}

// assertContainsSubstring fails the test if no issue contains the expected substring.
func assertContainsSubstring(t *testing.T, issues []string, sub string) {
	t.Helper()
	if !containsSubstring(t, issues, sub) {
		t.Errorf("expected at least one issue containing %q, got: %v", sub, issues)
	}
}

// assertNotContainsSubstring fails the test if any issue contains the unexpected substring.
func assertNotContainsSubstring(t *testing.T, issues []string, sub string) {
	t.Helper()
	if containsSubstring(t, issues, sub) {
		t.Errorf("expected no issue containing %q, but found one in: %v", sub, issues)
	}
}

// ---------------------------------------------------------------------------
// TestGetLineNumber
// ---------------------------------------------------------------------------

func Test_GetLineNumber_Cases(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		position int
		wantLine int
	}{
		{
			name:     "position 0 in multi-line",
			content:  "first line\nsecond line\n",
			position: 0,
			wantLine: 1,
		},
		{
			name:     "middle of first line",
			content:  "first line\nsecond line\n",
			position: 5,
			wantLine: 1,
		},
		{
			name:     "right after first newline (start of second line)",
			content:  "first line\nsecond line\n",
			position: 11,
			wantLine: 2,
		},
		{
			name:     "middle of second line",
			content:  "first line\nsecond line\n",
			position: 15,
			wantLine: 2,
		},
		{
			name:     "four lines position at line 1",
			content:  "line1\nline2\nline3\nline4\n",
			position: 0,
			wantLine: 1,
		},
		{
			name:     "four lines position at line 2",
			content:  "line1\nline2\nline3\nline4\n",
			position: 6,
			wantLine: 2,
		},
		{
			name:     "four lines position at line 3",
			content:  "line1\nline2\nline3\nline4\n",
			position: 12,
			wantLine: 3,
		},
		{
			name:     "four lines position at line 4",
			content:  "line1\nline2\nline3\nline4\n",
			position: 18,
			wantLine: 4,
		},
		{
			name:     "no newlines position 0",
			content:  "single line content",
			position: 0,
			wantLine: 1,
		},
		{
			name:     "no newlines middle",
			content:  "single line content",
			position: 10,
			wantLine: 1,
		},
		{
			name:     "no newlines last char",
			content:  "single line content",
			position: 18,
			wantLine: 1,
		},
		{
			name:     "empty content position 0",
			content:  "",
			position: 0,
			wantLine: 1,
		},
		{
			name:     "consecutive newlines position 0 is line 1",
			content:  "line1\n\n\nline4\n",
			position: 0,
			wantLine: 1,
		},
		{
			name:     "consecutive newlines first empty line",
			content:  "line1\n\n\nline4\n",
			position: 6,
			wantLine: 2,
		},
		{
			name:     "consecutive newlines second empty line",
			content:  "line1\n\n\nline4\n",
			position: 7,
			wantLine: 3,
		},
		{
			name:     "consecutive newlines line4",
			content:  "line1\n\n\nline4\n",
			position: 8,
			wantLine: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetLineNumber(tt.content, tt.position)
			if got != tt.wantLine {
				t.Errorf("GetLineNumber(%q, %d) = %d, want %d", tt.content, tt.position, got, tt.wantLine)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCheckFileForSecrets
// ---------------------------------------------------------------------------

func Test_CheckFileForSecrets_Cases(t *testing.T) {
	tests := []struct {
		name                  string
		filePath              string
		content               string
		envPatterns           map[string]*regexp.Regexp
		wantMinPatternIssues  int
		wantMinEnvIssues      int
		wantPatternContains   []string // substrings that must appear in at least one patternIssue
		wantEnvContains       []string // substrings that must appear in at least one envIssue
		wantPatternNotContain []string // substrings that must NOT appear in any patternIssue
	}{
		{
			name:                 "no secrets in clean code",
			filePath:             "test.py",
			content:              "def hello_world():\n    print('Hello, World!')\n",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 0,
			wantMinEnvIssues:     0,
		},
		{
			name:                 "AWS Access Key ID",
			filePath:             "config.py",
			content:              "config = {\n    'key': 'AKIA2B3C4D5E6F7G8H9I'\n}",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"AWS"},
		},
		{
			name:                 "OpenAI API key",
			filePath:             "app.py",
			content:              "api_key = 'sk-abcdefghij1234567890'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
		},
		{
			name:                 "GitHub Personal Access Token",
			filePath:             "script.py",
			content:              "token = 'ghp_" + strings.Repeat("A", 36) + "'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"GitHub"},
		},
		{
			name:                 "Private key header",
			filePath:             "key.pem",
			content:              "-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----\n",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"Private key"},
		},
		{
			name:                 "PostgreSQL connection string",
			filePath:             "db.py",
			content:              "url = 'postgresql://user:secretpass@localhost/db'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"PostgreSQL"},
		},
		{
			name:     "env value detected",
			filePath: "config.py",
			content:  "api_key = 'my_secret_value_123456789'",
			envPatterns: map[string]*regexp.Regexp{
				"API_KEY": regexp.MustCompile(`\bmy_secret_value_123456789\b`),
			},
			wantMinPatternIssues: 0,
			wantMinEnvIssues:     1,
			wantEnvContains:      []string{"hardcoded value"},
		},
		{
			name:                 "multiple secrets in one file",
			filePath:             "secrets.py",
			content:              "key1 = 'sk-ant-" + strings.Repeat("a", 30) + "'\nkey2 = 'ghp_" + strings.Repeat("B", 36) + "'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 2,
			wantMinEnvIssues:     0,
		},
		{
			name:                 "correct line numbers reported",
			filePath:             "app.py",
			content:              "line1\napi_key = 'sk-ant-" + strings.Repeat("x", 20) + "'\nline3\n",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{":2 -"},
		},
		{
			name:                 "Slack token",
			filePath:             "slack.py",
			content:              "slack_token = 'xoxb-1111111111-2222222222-aaaaaaaaaaaaaaaa'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"Slack"},
		},
		{
			name:                 "Stripe secret key",
			filePath:             "payment.py",
			content:              "stripe_key = 'sk_live_" + strings.Repeat("x", 25) + "'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"Stripe"},
		},
		{
			name:                 "Bearer token",
			filePath:             "request.py",
			content:              "Authorization: Bearer AbCdEfGhIjKlMnOpQrStUvWxYz123456",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"Bearer"},
		},
		{
			name:                 "filename appears in all pattern issues",
			filePath:             "myfile.py",
			content:              "secret = 'sk-ant-" + strings.Repeat("x", 30) + "'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"myfile.py"},
		},
		{
			name:                 "SendGrid API key",
			filePath:             "email.py",
			content:              "sg_key = 'SG.1234567890abcdef1234567890.abcdefghijklmnopqrstuvwxyz1234567890ABCD'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"SendGrid"},
		},
		{
			name:                 "Anthropic API key",
			filePath:             "claude.py",
			content:              "key = 'sk-ant-" + strings.Repeat("x", 30) + "'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"Anthropic"},
		},
		{
			name:     "env pattern word boundary prevents partial match",
			filePath: "config.py",
			content:  "my_secret_value_123456789_extra",
			envPatterns: map[string]*regexp.Regexp{
				"API_KEY": regexp.MustCompile(`\bmy_secret_value_123456789\b`),
			},
			wantMinPatternIssues: 0,
			wantMinEnvIssues:     0,
		},
		{
			name:                 "MongoDB connection string",
			filePath:             "mongo.py",
			content:              "mongo_url = 'mongodb+srv://user:password@cluster.mongodb.net/db'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"MongoDB"},
		},
		{
			name:                 "MySQL connection string",
			filePath:             "db.py",
			content:              "db_url = 'mysql://username:password@localhost:3306/mydb'",
			envPatterns:          map[string]*regexp.Regexp{},
			wantMinPatternIssues: 1,
			wantMinEnvIssues:     0,
			wantPatternContains:  []string{"MySQL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patternIssues, envIssues := CheckFileForSecrets(tt.filePath, tt.content, tt.envPatterns)

			if len(patternIssues) < tt.wantMinPatternIssues {
				t.Errorf("CheckFileForSecrets() patternIssues count = %d, want >= %d; issues: %v",
					len(patternIssues), tt.wantMinPatternIssues, patternIssues)
			}

			if len(envIssues) < tt.wantMinEnvIssues {
				t.Errorf("CheckFileForSecrets() envIssues count = %d, want >= %d; issues: %v",
					len(envIssues), tt.wantMinEnvIssues, envIssues)
			}

			for _, sub := range tt.wantPatternContains {
				assertContainsSubstring(t, patternIssues, sub)
			}

			for _, sub := range tt.wantEnvContains {
				assertContainsSubstring(t, envIssues, sub)
			}

			for _, sub := range tt.wantPatternNotContain {
				assertNotContainsSubstring(t, patternIssues, sub)
			}
		})
	}
}

// Test_CheckFileForSecrets_FilenameInAllIssues verifies that every single
// pattern issue string contains the file path prefix.
func Test_CheckFileForSecrets_FilenameInAllIssues(t *testing.T) {
	filePath := "myfile.py"
	content := "secret = 'sk-ant-" + strings.Repeat("x", 30) + "'"
	patternIssues, _ := CheckFileForSecrets(filePath, content, map[string]*regexp.Regexp{})

	if len(patternIssues) == 0 {
		t.Fatal("expected at least one pattern issue, got none")
	}

	for i, issue := range patternIssues {
		if !strings.Contains(issue, filePath) {
			t.Errorf("patternIssues[%d] = %q, does not contain file path %q", i, issue, filePath)
		}
	}
}

// ---------------------------------------------------------------------------
// TestSecretPatternEdgeCases
// ---------------------------------------------------------------------------

func Test_SecretPattern_EdgeCases(t *testing.T) {
	t.Run("multiple matches on same line", func(t *testing.T) {
		content := "keys = 'sk-ant-" + strings.Repeat("a", 20) + "' and 'sk-ant-" + strings.Repeat("b", 20) + "'"
		patternIssues, _ := CheckFileForSecrets("test.py", content, map[string]*regexp.Regexp{})
		if len(patternIssues) < 2 {
			t.Errorf("expected >= 2 pattern issues for two keys on one line, got %d: %v",
				len(patternIssues), patternIssues)
		}
	})

	t.Run("generic secret token case insensitive", func(t *testing.T) {
		// The generic pattern is (?i)(secret|token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}
		content := "SECRET = 'value123456789abcdef01234'"
		patternIssues, _ := CheckFileForSecrets("test.py", content, map[string]*regexp.Regexp{})
		if len(patternIssues) < 1 {
			t.Errorf("expected >= 1 pattern issue for case-insensitive secret, got %d: %v",
				len(patternIssues), patternIssues)
		}
	})

	t.Run("secrets in comments are still detected", func(t *testing.T) {
		content := "# TODO: Remove token: sk-ant-" + strings.Repeat("x", 20)
		patternIssues, _ := CheckFileForSecrets("test.py", content, map[string]*regexp.Regexp{})
		if len(patternIssues) < 1 {
			t.Errorf("expected >= 1 pattern issue for secret in comment, got %d: %v",
				len(patternIssues), patternIssues)
		}
	})
}

// ---------------------------------------------------------------------------
// TestNewSecretPatterns
// ---------------------------------------------------------------------------

func Test_NewSecretPatterns(t *testing.T) {
	tests := []struct {
		name          string
		filePath      string
		content       string
		wantContains  string
		wantMinIssues int
	}{
		{
			name:          "Discord bot token",
			filePath:      "discord.py",
			content:       "MFakeTestToken0000000000.AAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBB",
			wantContains:  "Discord",
			wantMinIssues: 1,
		},
		{
			name:          "npm access token",
			filePath:      "npmrc",
			content:       "npm_" + strings.Repeat("a", 36),
			wantContains:  "npm",
			wantMinIssues: 1,
		},
		{
			name:          "PyPI API token",
			filePath:      "pypirc",
			content:       "pypi-" + strings.Repeat("a", 50),
			wantContains:  "PyPI",
			wantMinIssues: 1,
		},
		{
			name:          "Twilio API key",
			filePath:      "twilio.py",
			content:       "SK" + strings.Repeat("a", 32),
			wantContains:  "Twilio",
			wantMinIssues: 1,
		},
		{
			name:          "Mailgun API key",
			filePath:      "mailgun.py",
			content:       "key-" + strings.Repeat("a", 32),
			wantContains:  "Mailgun",
			wantMinIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patternIssues, _ := CheckFileForSecrets(tt.filePath, tt.content, map[string]*regexp.Regexp{})

			if len(patternIssues) < tt.wantMinIssues {
				t.Errorf("expected >= %d pattern issues, got %d: %v",
					tt.wantMinIssues, len(patternIssues), patternIssues)
			}

			assertContainsSubstring(t, patternIssues, tt.wantContains)
		})
	}
}

// ---------------------------------------------------------------------------
// TestSecretPatternFalsePositives
// ---------------------------------------------------------------------------

func Test_SecretPattern_FalsePositives(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		content     string
		notContains string
	}{
		{
			name:        "short sk- prefix is not OpenAI key",
			filePath:    "test.py",
			content:     "key = 'sk-short'",
			notContains: "OpenAI",
		},
		{
			name:        "URL without credentials is not PostgreSQL conn string",
			filePath:    "test.py",
			content:     "url = 'postgresql://localhost/db'",
			notContains: "PostgreSQL",
		},
		{
			name:        "short ghp_ prefix is not GitHub PAT",
			filePath:    "test.py",
			content:     "token = 'ghp_short'",
			notContains: "GitHub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patternIssues, _ := CheckFileForSecrets(tt.filePath, tt.content, map[string]*regexp.Regexp{})
			assertNotContainsSubstring(t, patternIssues, tt.notContains)
		})
	}
}

// ---------------------------------------------------------------------------
// TestCompileEnvPatterns
// ---------------------------------------------------------------------------

func Test_CompileEnvPatterns_Cases(t *testing.T) {
	t.Run("compiles patterns from input map", func(t *testing.T) {
		input := map[string]string{
			"API_KEY": "my_secret_123",
		}
		got := CompileEnvPatterns(input)

		if len(got) != 1 {
			t.Fatalf("CompileEnvPatterns() returned map with %d entries, want 1", len(got))
		}

		pattern, ok := got["API_KEY"]
		if !ok {
			t.Fatal("CompileEnvPatterns() missing key 'API_KEY'")
		}
		if pattern == nil {
			t.Fatal("CompileEnvPatterns() returned nil pattern for 'API_KEY'")
		}
	})

	t.Run("empty input returns empty map", func(t *testing.T) {
		got := CompileEnvPatterns(map[string]string{})
		if len(got) != 0 {
			t.Errorf("CompileEnvPatterns({}) returned map with %d entries, want 0", len(got))
		}
	})

	t.Run("compiled pattern matches exact value", func(t *testing.T) {
		input := map[string]string{
			"SECRET": "test_value_12345",
		}
		got := CompileEnvPatterns(input)
		pattern := got["SECRET"]

		if !pattern.MatchString("test_value_12345") {
			t.Error("compiled pattern should match exact value 'test_value_12345'")
		}
	})

	t.Run("compiled pattern uses word boundaries", func(t *testing.T) {
		input := map[string]string{
			"SECRET": "secret",
		}
		got := CompileEnvPatterns(input)
		pattern := got["SECRET"]

		// "secret" as a whole word should match
		if !pattern.MatchString("the secret is here") {
			t.Error("compiled pattern should match 'secret' as a whole word")
		}

		// "secret" embedded in another word should NOT match
		if pattern.MatchString("my_secret_value") {
			t.Error("compiled pattern should NOT match 'secret' inside 'my_secret_value' due to word boundary")
		}
	})

	t.Run("multiple keys compile correctly", func(t *testing.T) {
		input := map[string]string{
			"KEY1": "value_one_12345",
			"KEY2": "value_two_67890",
			"KEY3": "value_three_abcde",
		}
		got := CompileEnvPatterns(input)

		if len(got) != 3 {
			t.Fatalf("CompileEnvPatterns() returned map with %d entries, want 3", len(got))
		}

		for key := range input {
			if got[key] == nil {
				t.Errorf("CompileEnvPatterns() returned nil pattern for key %q", key)
			}
		}
	})

	t.Run("special regex characters are escaped", func(t *testing.T) {
		// Use a value with regex metacharacters but starting/ending with word chars
		// (word boundaries \b only trigger at word-char boundaries, matching Python behavior)
		input := map[string]string{
			"REGEX_KEY": "value0with+special9chars",
		}
		got := CompileEnvPatterns(input)
		pattern := got["REGEX_KEY"]

		if pattern == nil {
			t.Fatal("CompileEnvPatterns() returned nil pattern for 'REGEX_KEY'")
		}

		// The literal value should match
		if !pattern.MatchString("value0with+special9chars") {
			t.Error("compiled pattern should match exact literal value with special chars")
		}

		// A string where + is treated as regex quantifier should NOT match
		if pattern.MatchString("value0withhhspecial9chars") {
			t.Error("compiled pattern should NOT treat special chars as regex metacharacters")
		}
	})
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func Benchmark_GetLineNumber(b *testing.B) {
	content := strings.Repeat("this is a line of content\n", 1000)
	position := len(content) / 2

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetLineNumber(content, position)
	}
}

func Benchmark_CheckFileForSecrets_CleanFile(b *testing.B) {
	content := strings.Repeat("def hello():\n    print('world')\n", 100)
	envPatterns := map[string]*regexp.Regexp{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckFileForSecrets("test.py", content, envPatterns)
	}
}

func Benchmark_CheckFileForSecrets_WithSecrets(b *testing.B) {
	content := "api_key = 'sk-ant-" + strings.Repeat("x", 30) + "'\n" +
		"token = 'ghp_" + strings.Repeat("A", 36) + "'\n" +
		"db_url = 'postgresql://user:pass@localhost/db'\n"
	envPatterns := map[string]*regexp.Regexp{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckFileForSecrets("secrets.py", content, envPatterns)
	}
}

func Benchmark_CompileEnvPatterns(b *testing.B) {
	input := map[string]string{
		"KEY1": "value_one_12345",
		"KEY2": "value_two_67890",
		"KEY3": "value_three_abcde",
		"KEY4": "another_secret_value_xyz",
		"KEY5": "final_secret_value_abc",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompileEnvPatterns(input)
	}
}
