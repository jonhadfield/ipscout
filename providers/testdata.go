package providers

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// testDataFS holds every provider's checked-in test data.
//
// The providers read their test data from disk, relative to the directory
// containing go.mod, which only exists when ipscout runs from a source
// checkout. Embedding the same files means --use-test-data also works for an
// installed binary run from anywhere.
//
//go:embed */testdata
var testDataFS embed.FS

const (
	// testDataDirPerm and testDataFilePerm are deliberately owner-only: the
	// extracted tree is a private cache, not something other users need.
	testDataDirPerm  = 0o700
	testDataFilePerm = 0o600
)

// TestDataRootName is the directory, below the extraction target, that holds
// the extracted tree. It mirrors the repository layout so that a path built as
// <root>/providers/<name>/testdata/<file> resolves the same way it does in a
// source checkout.
const TestDataRootName = "providers"

// ExtractTestData writes the embedded provider test data below root, creating
// root/providers/<name>/testdata/<file> for every embedded file. Files that
// already exist with the expected size are left alone, so repeat runs reuse
// what is already on disk rather than rewriting it.
func ExtractTestData(root string) error {
	err := fs.WalkDir(testDataFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// embed paths are always slash separated and rooted at the providers
		// package directory, so they cannot escape the extraction target
		target := filepath.Join(root, TestDataRootName, filepath.FromSlash(path))
		if !strings.HasPrefix(target, filepath.Clean(root)+string(os.PathSeparator)) {
			return fmt.Errorf("refusing to extract test data outside %s: %s", root, path)
		}

		data, err := testDataFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("error reading embedded test data %s: %w", path, err)
		}

		if info, sErr := os.Stat(target); sErr == nil && info.Size() == int64(len(data)) {
			return nil
		}

		if err = os.MkdirAll(filepath.Dir(target), testDataDirPerm); err != nil {
			return fmt.Errorf("error creating test data directory for %s: %w", path, err)
		}

		if err = os.WriteFile(target, data, testDataFilePerm); err != nil {
			return fmt.Errorf("error writing test data %s: %w", path, err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("error extracting test data to %s: %w", root, err)
	}

	return nil
}
