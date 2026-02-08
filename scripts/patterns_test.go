package main

import (
	"testing"
	"time"
)

func Test_SecretPatterns_Count(t *testing.T) {
	got := len(secretPatterns)
	want := 26
	if got != want {
		t.Errorf("len(secretPatterns) = %d, want %d", got, want)
	}
}

func Test_SkipValues_Count(t *testing.T) {
	got := len(skipValues)
	want := 17
	if got != want {
		t.Errorf("len(skipValues) = %d, want %d", got, want)
	}
}

func Test_BinaryExtensions_Count(t *testing.T) {
	got := len(binaryExtensions)
	want := 30
	if got != want {
		t.Errorf("len(binaryExtensions) = %d, want %d", got, want)
	}
}

func Test_CompoundBinaryExtensions_Count(t *testing.T) {
	got := len(compoundBinaryExtensions)
	want := 2
	if got != want {
		t.Errorf("len(compoundBinaryExtensions) = %d, want %d", got, want)
	}
}

func Test_EnvFileNames_Count(t *testing.T) {
	got := len(envFileNames)
	want := 7
	if got != want {
		t.Errorf("len(envFileNames) = %d, want %d", got, want)
	}
}

func Test_SecretPatterns_NonEmptyDescriptions(t *testing.T) {
	for i, sp := range secretPatterns {
		t.Run(sp.Description, func(t *testing.T) {
			if sp.Description == "" {
				t.Errorf("secretPatterns[%d] has empty Description", i)
			}
		})
	}
}

func Test_SecretPatterns_NonNilPatterns(t *testing.T) {
	for i, sp := range secretPatterns {
		t.Run(sp.Description, func(t *testing.T) {
			if sp.Pattern == nil {
				t.Errorf("secretPatterns[%d] (%q) has nil Pattern", i, sp.Description)
			}
		})
	}
}

func Test_Constants(t *testing.T) {
	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{
			name: "MinSecretLength equals 8",
			got:  MinSecretLength,
			want: 8,
		},
		{
			name: "MaxFileSize equals 10MB",
			got:  MaxFileSize,
			want: 10 * 1024 * 1024,
		},
		{
			name: "ExitSuccess equals 0",
			got:  ExitSuccess,
			want: 0,
		},
		{
			name: "ExitBlocked equals 2",
			got:  ExitBlocked,
			want: 2,
		},
		{
			name: "SubprocessTimeout equals 30 seconds",
			got:  SubprocessTimeout,
			want: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}
