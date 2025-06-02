package findexec

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Find searches for an executable in the directories list in 'path'.
// If a path is not supplied, it defaults to those available in the OS' 'PATH' environment variable.
// It returns the complete path to the filename if found, otherwise it returns an empty string
func Find(executable, path string) string {
	ext := filepath.Ext(executable)
	if runtime.GOOS == "windows" && ext != ".exe" {
		executable += ".exe"
	}
	if _, err := os.Stat(executable); err == nil {
		return executable
	}
	if path == "" {
		path = os.Getenv("PATH")
		if path == "" {
			return ""
		}
	}
	paths := strings.Split(path, string(os.PathListSeparator))
	for i := range paths {
		f := filepath.Join(paths[i], executable)
		if _, err := os.Stat(f); err == nil {
			absPath, err := filepath.Abs(f)
			if err != nil {
				return ""
			}
			return absPath
		}
	}
	return ""
}
