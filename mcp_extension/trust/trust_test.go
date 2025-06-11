package trust

import (
	"runtime"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func Test_folderContains(t *testing.T) {
	type args struct {
		folderPath string
		path       string
	}
	tests := []struct {
		name     string
		args     args
		expected bool
		goos     string
	}{
		{
			name:     "exact match",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "subfolder match",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "subfolder with file match",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub/file.txt"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "folderPath with trailing slash",
			args:     args{folderPath: "/trusted/folder/", path: "/trusted/folder/sub/file.txt"},
			expected: true,
			goos:     "linux",
		},

		{
			name:     "exact match - windows",
			args:     args{folderPath: "C:\\trusted\\folder", path: "C:\\trusted\\folder"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "subfolder match - windows",
			args:     args{folderPath: "C:\\trusted\\folder", path: "C:\\trusted\\folder\\sub"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "subfolder with file match - windows",
			args:     args{folderPath: "C:\\trusted\\folder", path: "C:\\trusted\\folder\\sub\\file.txt"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "folderPath with trailing slash - windows",
			args:     args{folderPath: "C:\\trusted\\folder\\", path: "C:\\trusted\\folder\\sub\\file.txt"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "windows case-insensitive match - windows",
			args:     args{folderPath: "C:\\Trusted\\Folder", path: "c:\\trusted\\folder\\sub\\file.txt"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "windows case-insensitive exact match - windows",
			args:     args{folderPath: "C:\\Trusted\\Folder", path: "c:\\trusted\\folder"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "windows case-insensitive, folderPath with trailing slash - windows",
			args:     args{folderPath: "C:\\Trusted\\Folder\\", path: "c:\\trusted\\folder\\sub\\file.txt"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "windows case-insensitive, path with trailing slash - windows",
			args:     args{folderPath: "C:\\Trusted\\Folder", path: "c:\\trusted\\folder\\sub\\"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "root path as trusted folder - windows",
			args:     args{folderPath: "C:\\", path: "C:\\some\\subfolder"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "relative paths - exact match - windows",
			args:     args{folderPath: "trusted\\folder", path: "trusted\\folder"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "path with trailing slash",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub/"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "no match - different folder",
			args:     args{folderPath: "/trusted/folder", path: "/untrusted/folder/sub"},
			expected: false,
			goos:     "linux",
		},
		{
			name:     "no match - path is parent of folderPath",
			args:     args{folderPath: "/trusted/folder/sub", path: "/trusted/folder"},
			expected: false,
			goos:     "linux",
		},
		{
			name:     "no match - partial name overlap",
			args:     args{folderPath: "/trusted/fold", path: "/trusted/folder/sub"},
			expected: false,
			goos:     "linux",
		},
		{
			name:     "linux case-sensitive no match",
			args:     args{folderPath: "/Trusted/Folder", path: "/trusted/folder/sub"},
			expected: false,
			goos:     "linux",
		},
		{
			name:     "linux case-sensitive match",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub"},
			expected: true,
			goos:     "linux", // or any other non-windows OS
		},
		{
			name:     "relative paths - subfolder match",
			args:     args{folderPath: "trusted/folder", path: "trusted/folder/sub/file.txt"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "relative paths - exact match",
			args:     args{folderPath: "trusted/folder", path: "trusted/folder"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "root path as trusted folder",
			args:     args{folderPath: "/", path: "/some/subfolder"},
			expected: true,
			goos:     "linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.goos != "" && tt.goos != runtime.GOOS {
				t.Skipf("Skipping OS-specific test %s on %s (meant for %s)", tt.name, runtime.GOOS, tt.goos)
			}
			actual := folderContains(tt.args.folderPath, tt.args.path)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestFolderTrust_AddTrustedFolder_Direct(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	tests := []struct {
		name                string
		initialTrustedPaths []string
		pathToAdd           string
		expectedFinalPaths  []string
		goos                string // For OS-specific path normalization
	}{
		{
			name:                "add to empty list",
			initialTrustedPaths: []string{},
			pathToAdd:           "/my/folder",
			expectedFinalPaths:  []string{"/my/folder"},
		},
		{
			name:                "add to existing list",
			initialTrustedPaths: []string{"/other/folder"},
			pathToAdd:           "/my/folder",
			expectedFinalPaths:  []string{"/other/folder", "/my/folder"},
		},
		{
			name:                "add duplicate path",
			initialTrustedPaths: []string{"/my/folder"},
			pathToAdd:           "/my/folder",
			expectedFinalPaths:  []string{"/my/folder"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.initialTrustedPaths != nil {
				config.Set(TrustedFoldersConfigKey, tt.initialTrustedPaths)
			}
			folderTrust := NewFolderTrust(&logger, config)

			folderTrust.AddTrustedFolder(tt.pathToAdd)

			actualFinalPaths := config.GetStringSlice(TrustedFoldersConfigKey)
			assert.ElementsMatch(t, tt.expectedFinalPaths, actualFinalPaths, "The final list of trusted paths did not match the expected list.")
		})
	}
}
