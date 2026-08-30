package providers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// anthropicReport is a test data file that every extraction must produce. It is
// referenced by providers/anthropic's loadTestData.
const anthropicReport = "providers/anthropic/testdata/anthropic_216_73_216_10_report.json"

func TestExtractTestDataWritesEmbeddedFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	require.NoError(t, ExtractTestData(root))

	target := filepath.Join(root, filepath.FromSlash(anthropicReport))

	data, err := os.ReadFile(target) // #nosec G304 -- path is built from t.TempDir
	require.NoError(t, err)
	require.NotEmpty(t, data)
	require.Contains(t, string(data), "216.73.216.0/22")
}

// The extracted tree must mirror the repository layout, because the providers
// build their paths as <root>/providers/<name>/testdata/<file>.
func TestExtractTestDataMirrorsRepoLayout(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	require.NoError(t, ExtractTestData(root))

	info, err := os.Stat(filepath.Join(root, TestDataRootName))
	require.NoError(t, err)
	require.True(t, info.IsDir())

	// a sample of providers whose test data is loaded at runtime
	for _, name := range []string{"anthropic", "spamhaus", "stripe", "ptr", "shodan"} {
		dir := filepath.Join(root, TestDataRootName, name, "testdata")

		info, err = os.Stat(dir)
		require.NoErrorf(t, err, "missing extracted test data for %s", name)
		require.Truef(t, info.IsDir(), "%s test data is not a directory", name)
	}
}

// Repeat runs reuse what is already on disk, so an unchanged file is left
// untouched rather than rewritten.
func TestExtractTestDataIsIdempotent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	require.NoError(t, ExtractTestData(root))

	target := filepath.Join(root, filepath.FromSlash(anthropicReport))

	before, err := os.Stat(target)
	require.NoError(t, err)

	require.NoError(t, ExtractTestData(root))

	after, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, before.ModTime(), after.ModTime())
	require.Equal(t, before.Size(), after.Size())
}

// A truncated file is rewritten, so a partial extraction repairs itself.
func TestExtractTestDataRepairsTruncatedFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	require.NoError(t, ExtractTestData(root))

	target := filepath.Join(root, filepath.FromSlash(anthropicReport))

	original, err := os.ReadFile(target) // #nosec G304 -- path is built from t.TempDir
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(target, []byte("{"), testDataFilePerm))
	require.NoError(t, ExtractTestData(root))

	repaired, err := os.ReadFile(target) // #nosec G304 -- path is built from t.TempDir
	require.NoError(t, err)
	require.Equal(t, original, repaired)
}
