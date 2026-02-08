package main

import "testing"

func Test_IsEnvFile_Cases(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		// Files that SHOULD be detected as env files.
		{
			name:     "bare .env",
			filePath: ".env",
			want:     true,
		},
		{
			name:     ".env with leading path",
			filePath: "/path/to/.env",
			want:     true,
		},
		{
			name:     ".env.local with project prefix",
			filePath: "project/.env.local",
			want:     true,
		},
		{
			name:     ".env.production",
			filePath: ".env.production",
			want:     true,
		},
		{
			name:     ".env.development",
			filePath: ".env.development",
			want:     true,
		},
		{
			name:     ".env.test",
			filePath: ".env.test",
			want:     true,
		},
		{
			name:     ".env.staging",
			filePath: ".env.staging",
			want:     true,
		},
		{
			name:     ".env.example",
			filePath: ".env.example",
			want:     true,
		},
		{
			name:     ".env.custom",
			filePath: ".env.custom",
			want:     true,
		},
		{
			name:     ".env.anything",
			filePath: ".env.anything",
			want:     true,
		},
		{
			name:     ".env.new_environment",
			filePath: ".env.new_environment",
			want:     true,
		},
		{
			name:     "deep path .env",
			filePath: "/home/user/project/.env",
			want:     true,
		},
		{
			name:     "deep path .env.production",
			filePath: "/var/app/.env.production",
			want:     true,
		},
		{
			name:     "Windows path bare .env",
			filePath: `C:\project\.env`,
			want:     true,
		},
		{
			name:     "Windows path .env.local",
			filePath: `C:\project\.env.local`,
			want:     true,
		},

		// Files that should NOT be detected.
		{
			name:     ".envrc is not an env file",
			filePath: ".envrc",
			want:     false,
		},
		{
			name:     "env.txt is not an env file",
			filePath: "env.txt",
			want:     false,
		},
		{
			name:     ".env-backup is not an env file",
			filePath: ".env-backup",
			want:     false,
		},
		{
			name:     "constants.js is not an env file",
			filePath: "constants.js",
			want:     false,
		},
		{
			name:     ".env_old is not an env file",
			filePath: ".env_old",
			want:     false,
		},
		{
			name:     "constants.js inside .env_config directory",
			filePath: "/home/user/.env_config/constants.js",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsEnvFile(tt.filePath)
			if got != tt.want {
				t.Errorf("IsEnvFile(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func Test_IsBinaryFile_Cases(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		// Image files.
		{name: "png image", filePath: "image.png", want: true},
		{name: "jpg photo", filePath: "photo.jpg", want: true},
		{name: "jpeg picture", filePath: "picture.jpeg", want: true},
		{name: "gif animated", filePath: "animated.gif", want: true},
		{name: "svg icon", filePath: "icon.svg", want: true},

		// Document/archive files.
		{name: "pdf report", filePath: "report.pdf", want: true},
		{name: "zip archive", filePath: "archive.zip", want: true},
		{name: "tar archive", filePath: "data.tar", want: true},
		{name: "gz archive", filePath: "data.gz", want: true},
		{name: "7z archive", filePath: "data.7z", want: true},

		// Executable/compiled files.
		{name: "exe program", filePath: "program.exe", want: true},
		{name: "dll library", filePath: "library.dll", want: true},
		{name: "so library", filePath: "library.so", want: true},
		{name: "pyc compiled", filePath: "compiled.pyc", want: true},
		{name: "class compiled", filePath: "compiled.class", want: true},

		// Font files.
		{name: "woff font", filePath: "font.woff", want: true},
		{name: "woff2 font", filePath: "font.woff2", want: true},
		{name: "ttf font", filePath: "font.ttf", want: true},

		// Database files.
		{name: "db database", filePath: "database.db", want: true},
		{name: "sqlite database", filePath: "database.sqlite", want: true},
		{name: "sqlite3 database", filePath: "database.sqlite3", want: true},

		// Media files.
		{name: "mp3 music", filePath: "music.mp3", want: true},
		{name: "mp4 video", filePath: "video.mp4", want: true},
		{name: "mov video", filePath: "video.mov", want: true},

		// Lock files.
		{name: "package-lock.lock", filePath: "package-lock.lock", want: true},
		{name: "yarn.lock", filePath: "yarn.lock", want: true},

		// Compound binary extensions.
		{name: "minified JS", filePath: "bundle.min.js", want: true},
		{name: "minified CSS", filePath: "styles.min.css", want: true},

		// With path prefix.
		{name: "jpg with path", filePath: "/home/user/images/photo.jpg", want: true},

		// Non-binary files.
		{name: "python script", filePath: "script.py", want: false},
		{name: "javascript code", filePath: "code.js", want: false},
		{name: "json config", filePath: "config.json", want: false},
		{name: "txt document", filePath: "document.txt", want: false},
		{name: "markdown readme", filePath: "README.md", want: false},
		{name: "python script with path", filePath: "/home/user/scripts/script.py", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBinaryFile(tt.filePath)
			if got != tt.want {
				t.Errorf("IsBinaryFile(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func Test_IsBinaryFile_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{name: "uppercase PNG", filePath: "image.PNG", want: true},
		{name: "lowercase png", filePath: "image.png", want: true},
		{name: "uppercase ZIP", filePath: "archive.ZIP", want: true},
		{name: "uppercase JPG", filePath: "photo.JPG", want: true},
		{name: "mixed case Jpg", filePath: "photo.Jpg", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBinaryFile(tt.filePath)
			if got != tt.want {
				t.Errorf("IsBinaryFile(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}
