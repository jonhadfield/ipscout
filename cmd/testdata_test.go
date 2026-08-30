package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/stretchr/testify/require"
)

// Running from a source checkout, the providers can already read their test
// data from the repository, so nothing is extracted and the project root is
// left alone.
func TestEnsureTestDataAvailableUsesSourceTree(t *testing.T) {
	realRoot, err := helpers.FindProjectRoot()
	require.NoError(t, err)

	t.Cleanup(func() { helpers.SetProjectRoot("") })

	require.NoError(t, ensureTestDataAvailable())

	root, err := helpers.FindProjectRoot()
	require.NoError(t, err)
	require.Equal(t, realRoot, root, "project root should be untouched inside a source checkout")
}

// With no go.mod above the working directory — the case for an installed binary
// — the embedded copy is extracted and the providers are pointed at it, so the
// path a provider builds actually resolves.
func TestEnsureTestDataAvailableExtractsForInstalledBinary(t *testing.T) {
	t.Cleanup(func() { helpers.SetProjectRoot("") })

	root := t.TempDir()

	require.NoError(t, providers.ExtractTestData(root))

	helpers.SetProjectRoot(root)

	resolved, err := helpers.PrefixProjectRoot("providers/anthropic/testdata/anthropic_216_73_216_10_report.json")
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(resolved))

	_, err = os.Stat(resolved)
	require.NoError(t, err, "a provider's test data path must resolve against the extracted tree")
}
