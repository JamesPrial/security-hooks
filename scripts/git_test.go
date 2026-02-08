package main

import "testing"

// ---------------------------------------------------------------------------
// TestIsGitCommitCommand
// ---------------------------------------------------------------------------

func Test_IsGitCommitCommand_Cases(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		// Commands that SHOULD match.
		{
			name:    "simple git commit",
			command: "git commit",
			want:    true,
		},
		{
			name:    "git commit with message flag",
			command: `git commit -m "message"`,
			want:    true,
		},
		{
			name:    "git commit with add-and-message flag",
			command: `git commit -am "message"`,
			want:    true,
		},
		{
			name:    "git commit with message and amend",
			command: `git commit -m "fix" --amend`,
			want:    true,
		},
		{
			name:    "git commit with allow-empty",
			command: "git commit --allow-empty",
			want:    true,
		},
		{
			name:    "git commit with signing and message",
			command: `git commit -S "key" -m "msg"`,
			want:    true,
		},
		{
			name:    "all caps GIT COMMIT",
			command: "GIT COMMIT",
			want:    true,
		},
		{
			name:    "mixed case Git Commit",
			command: `Git Commit -m "msg"`,
			want:    true,
		},
		{
			name:    "random case gIT cOMMIT",
			command: "gIT cOMMIT",
			want:    true,
		},
		{
			name:    "unix path prefix /usr/bin/git commit",
			command: "/usr/bin/git commit",
			want:    true,
		},
		{
			name:    "windows path prefix git.exe commit",
			command: `C:\git\git.exe commit`,
			want:    true,
		},
		{
			name:    "git with -C flag before commit",
			command: "git -C /path/to/repo commit -m 'msg'",
			want:    true,
		},

		// Commands that should NOT match.
		{
			name:    "git push",
			command: "git push",
			want:    false,
		},
		{
			name:    "git pull",
			command: "git pull",
			want:    false,
		},
		{
			name:    "git add",
			command: "git add file.txt",
			want:    false,
		},
		{
			name:    "git status",
			command: "git status",
			want:    false,
		},
		{
			name:    "commit without git prefix",
			command: `commit -m "msg"`,
			want:    false,
		},
		{
			name:    "just commit word",
			command: "just commit",
			want:    false,
		},
		{
			name:    "empty string",
			command: "",
			want:    false,
		},
		{
			name:    "git without subcommand",
			command: "git",
			want:    false,
		},
		{
			name:    "echo with git and commit words",
			command: `echo "git is for commit"`,
			want:    false,
		},
		{
			name:    "gitcommit no word boundary",
			command: "gitcommit",
			want:    false,
		},
		{
			name:    "mygit prefix before git",
			command: "mygit commit",
			want:    false,
		},
		{
			name:    "git with non-commit word mycommit",
			command: "git mycommit",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGitCommitCommand(tt.command)
			if got != tt.want {
				t.Errorf("IsGitCommitCommand(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Additional IsGitCommitCommand edge cases
// ---------------------------------------------------------------------------

func Test_IsGitCommitCommand_CompoundCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "git add then git commit separated by semicolon",
			command: "git add . ; git commit -m 'msg'",
			want:    true,
		},
		{
			name:    "git add then git commit separated by &&",
			command: "git add . && git commit -m 'msg'",
			want:    true,
		},
		{
			name:    "git add then git commit separated by ||",
			command: "git add . || git commit -m 'msg'",
			want:    true,
		},
		{
			name:    "multiple non-commit commands separated by semicolon",
			command: "git add . ; git status ; git diff",
			want:    false,
		},
		{
			name:    "only non-git commands with commit word",
			command: "echo commit ; ls -la",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGitCommitCommand(tt.command)
			if got != tt.want {
				t.Errorf("IsGitCommitCommand(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func Benchmark_IsGitCommitCommand_SimpleCommit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsGitCommitCommand(`git commit -m "test message"`)
	}
}

func Benchmark_IsGitCommitCommand_NonCommit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsGitCommitCommand("git push origin main")
	}
}

func Benchmark_IsGitCommitCommand_CompoundCommand(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsGitCommitCommand("git add . && git commit -m 'msg' && git push")
	}
}
