package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeEnvFile is a test helper that creates a file with the given content
// inside the provided directory and returns its absolute path.
func writeEnvFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test env file %s: %v", path, err)
	}
	return path
}

// assertMapLen is a test helper that checks the length of a map.
func assertMapLen(t *testing.T, m map[string]string, want int) {
	t.Helper()
	if len(m) != want {
		t.Errorf("map length = %d, want %d; map contents: %v", len(m), want, m)
	}
}

// assertMapValue is a test helper that checks a specific key-value pair in a map.
func assertMapValue(t *testing.T, m map[string]string, key, want string) {
	t.Helper()
	got, ok := m[key]
	if !ok {
		t.Errorf("map missing key %q; map contents: %v", key, m)
		return
	}
	if got != want {
		t.Errorf("map[%q] = %q, want %q", key, got, want)
	}
}

// assertMapMissing is a test helper that checks a key is absent from a map.
func assertMapMissing(t *testing.T, m map[string]string, key string) {
	t.Helper()
	if val, ok := m[key]; ok {
		t.Errorf("map should not contain key %q, but found value %q", key, val)
	}
}

func Test_ParseEnvFile_Cases(t *testing.T) {
	tests := []struct {
		name       string
		fileName   string
		content    string
		wantLen    int
		wantKeys   map[string]string // key -> expected value
		absentKeys []string          // keys that must NOT be present
	}{
		{
			name:     "valid key-value pairs",
			fileName: ".env",
			content:  "API_KEY=secret123456789\nDB_URL=postgresql://user:pass@localhost\nDEBUG=true\n",
			wantLen:  3,
			wantKeys: map[string]string{
				"API_KEY": "secret123456789",
				"DB_URL":  "postgresql://user:pass@localhost",
				"DEBUG":   "true",
			},
		},
		{
			name:     "double-quoted values have quotes stripped",
			fileName: ".env",
			content:  "DOUBLE_QUOTE=\"value987654321\"\n",
			wantLen:  1,
			wantKeys: map[string]string{
				"DOUBLE_QUOTE": "value987654321",
			},
		},
		{
			name:     "single-quoted values have quotes stripped",
			fileName: ".env",
			content:  "SINGLE_QUOTE='value123456789'\n",
			wantLen:  1,
			wantKeys: map[string]string{
				"SINGLE_QUOTE": "value123456789",
			},
		},
		{
			name:     "unquoted values",
			fileName: ".env",
			content:  "NO_QUOTE=plainvalue12345\n",
			wantLen:  1,
			wantKeys: map[string]string{
				"NO_QUOTE": "plainvalue12345",
			},
		},
		{
			name:     "comment lines are skipped",
			fileName: ".env",
			content:  "# comment\nAPI_KEY=secret123456789\n  # indented comment\nDEBUG=false\n",
			wantLen:  2,
			wantKeys: map[string]string{
				"API_KEY": "secret123456789",
				"DEBUG":   "false",
			},
		},
		{
			name:     "empty and whitespace-only lines are skipped",
			fileName: ".env",
			content:  "API_KEY=secret123456789\n\n  \nDEBUG=true\n",
			wantLen:  2,
			wantKeys: map[string]string{
				"API_KEY": "secret123456789",
				"DEBUG":   "true",
			},
		},
		{
			name:     "multiple equals signs preserves value after first equals",
			fileName: ".env",
			content:  "BASE64_VALUE=aGVsbG8gd29ybGQ=extradata\n",
			wantLen:  1,
			wantKeys: map[string]string{
				"BASE64_VALUE": "aGVsbG8gd29ybGQ=extradata",
			},
		},
		{
			name:     "whitespace in values is preserved",
			fileName: ".env",
			content:  "WITH_SPACES=value with spaces inside1234\n",
			wantLen:  1,
			wantKeys: map[string]string{
				"WITH_SPACES": "value with spaces inside1234",
			},
		},
		{
			name:     "mismatched quotes are NOT stripped",
			fileName: ".env",
			content:  "MISMATCHED=\"value123456789'\n",
			wantLen:  1,
			wantKeys: map[string]string{
				"MISMATCHED": "\"value123456789'",
			},
		},
		{
			name:       "empty value after equals is excluded",
			fileName:   ".env",
			content:    "EMPTY_KEY=\nVALID_KEY=value123456789\n",
			wantLen:    1,
			wantKeys:   map[string]string{"VALID_KEY": "value123456789"},
			absentKeys: []string{"EMPTY_KEY"},
		},
		{
			name:       "line without equals sign is excluded",
			fileName:   ".env",
			content:    "VALID_KEY=value123456789\nINVALID_LINE_NO_EQUALS\n",
			wantLen:    1,
			wantKeys:   map[string]string{"VALID_KEY": "value123456789"},
			absentKeys: []string{"INVALID_LINE_NO_EQUALS"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeEnvFile(t, dir, tt.fileName, tt.content)

			got := ParseEnvFile(path)

			assertMapLen(t, got, tt.wantLen)
			for key, wantVal := range tt.wantKeys {
				assertMapValue(t, got, key, wantVal)
			}
			for _, key := range tt.absentKeys {
				assertMapMissing(t, got, key)
			}
		})
	}
}

func Test_ParseEnvFile_NonexistentFile(t *testing.T) {
	got := ParseEnvFile("/nonexistent/path/.env")
	assertMapLen(t, got, 0)
}

func Test_ParseEnvFile_UnicodeError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte{0xff, 0xfe}, 0644); err != nil {
		t.Fatalf("failed to write binary test file: %v", err)
	}

	got := ParseEnvFile(path)
	assertMapLen(t, got, 0)
}

func Test_FilterEnvValues_Cases(t *testing.T) {
	tests := []struct {
		name       string
		input      map[string]string
		wantKeys   []string // keys that MUST be present
		absentKeys []string // keys that MUST be absent
		wantLen    int
	}{
		{
			name: "short values are removed",
			input: map[string]string{
				"SHORT": "abc",
				"LONG":  "this_is_a_long_secret_value_that_should_not_be_filtered",
			},
			wantKeys:   []string{"LONG"},
			absentKeys: []string{"SHORT"},
			wantLen:    1,
		},
		{
			name: "skip values are removed",
			input: map[string]string{
				"ENV_TYPE":   "production",
				"DEBUG":      "true",
				"SECRET_KEY": "super_secret_key_that_is_very_long",
			},
			wantKeys:   []string{"SECRET_KEY"},
			absentKeys: []string{"ENV_TYPE", "DEBUG"},
			wantLen:    1,
		},
		{
			name: "numeric values are removed",
			input: map[string]string{
				"PORT":    "3000",
				"POOL":    "20",
				"API_KEY": "sk-proj-ABC123456789DEF123456789",
			},
			wantKeys:   []string{"API_KEY"},
			absentKeys: []string{"PORT", "POOL"},
			wantLen:    1,
		},
		{
			name: "case-insensitive skip values",
			input: map[string]string{
				"E1":     "PRODUCTION",
				"E2":     "Localhost",
				"E3":     "True",
				"SECRET": "actual_secret_key_that_is_quite_long",
			},
			wantKeys:   []string{"SECRET"},
			absentKeys: []string{"E1", "E2", "E3"},
			wantLen:    1,
		},
		{
			name: "valid secrets are all preserved",
			input: map[string]string{
				"API_KEY":     "sk-ant-aaaaaaaaaaaaaaaaaaaaaaaaa",
				"DB_PASSWORD": "MyComplex!Pass#123456789",
				"TOKEN":       "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			wantKeys:   []string{"API_KEY", "DB_PASSWORD", "TOKEN"},
			absentKeys: nil,
			wantLen:    3,
		},
		{
			name:       "empty input returns empty map",
			input:      map[string]string{},
			wantKeys:   nil,
			absentKeys: nil,
			wantLen:    0,
		},
		{
			name: "all values filtered out",
			input: map[string]string{
				"SHORT": "abc",
				"ENV":   "development",
				"PORT":  "5432",
			},
			wantKeys:   nil,
			absentKeys: []string{"SHORT", "ENV", "PORT"},
			wantLen:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterEnvValues(tt.input)

			assertMapLen(t, got, tt.wantLen)
			for _, key := range tt.wantKeys {
				if _, ok := got[key]; !ok {
					t.Errorf("expected key %q in filtered result, but it was absent; got: %v", key, got)
				}
			}
			for _, key := range tt.absentKeys {
				if val, ok := got[key]; ok {
					t.Errorf("expected key %q to be filtered out, but found value %q", key, val)
				}
			}
		})
	}
}
