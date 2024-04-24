package annotated

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/stretchr/testify/require"
)

func TestReadAnnotatedPrefixesFromFile(t *testing.T) {
	prefixesWithAnnotations := make(map[netip.Prefix][]annotation)
	require.NoError(t, ReadAnnotatedPrefixesFromFile(nil, filepath.Join("testdata", "small", "small.yml"), prefixesWithAnnotations))
	require.Len(t, prefixesWithAnnotations, 2)
	require.Equal(t, time.Date(2024, time.April, 19, 18, 58, 0, 0, time.UTC), prefixesWithAnnotations[netip.MustParsePrefix("8.8.8.8/32")][0].Date)
	require.Equal(t, time.Date(2024, time.April, 19, 19, 0, 0, 0, time.UTC), prefixesWithAnnotations[netip.MustParsePrefix("9.9.9.0/24")][0].Date)
}

func TestLoadFilePrefixesWithAnnotationsFromPath(t *testing.T) {
	prefixesWithAnnotations := make(map[netip.Prefix][]annotation)
	require.NoError(t, LoadAnnotatedIPPrefixesFromPaths([]string{filepath.Join("testdata", "small")}, prefixesWithAnnotations))
	require.Len(t, prefixesWithAnnotations, 2)
	require.Equal(t, time.Date(2024, time.April, 19, 18, 58, 0, 0, time.UTC), prefixesWithAnnotations[netip.MustParsePrefix("8.8.8.8/32")][0].Date)
	require.Equal(t, time.Date(2024, time.April, 19, 19, 0, 0, 0, time.UTC), prefixesWithAnnotations[netip.MustParsePrefix("9.9.9.0/24")][0].Date)
}

func TestInitialise(t *testing.T) {
	c, err := initialiseSetup(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, err)

	uh := generateURLsHash(c.Providers.Annotated.Paths)

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName+"_"+uh)
	require.NoError(t, err)
	require.True(t, ok)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEqual(t, "null", string(res))
}

func initialiseSetup(homeDir string) (*ProviderClient, error) {
	lg := slog.New(slog.NewTextHandler(os.Stdout, nil))

	db, err := cache.Create(lg, filepath.Join(homeDir, ".config", "ipscout"))
	if err != nil {
		return nil, err
	}

	c, err := NewProviderClient(config.Config{
		Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
		Stats:  config.CreateStats(),
		Output: nil,
		Cache:  db,
	})
	if err != nil {
		return nil, err
	}

	if err = c.Validate(); err != nil {
		return nil, err
	}

	// set paths
	c.Providers.Annotated.Paths = []string{filepath.Join("testdata", "small")}

	c.Host = netip.MustParseAddr("9.9.9.9")

	if err = c.Initialise(); err != nil {
		return nil, err
	}

	return c, nil
}

func TestLoadProviderDataFromCache(t *testing.T) {
	c, err := initialiseSetup(t.TempDir())
	require.NoError(t, err)

	uh := generateURLsHash(c.Providers.Annotated.Paths)

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName+"_"+uh)
	require.NoError(t, err)
	require.True(t, ok)

	pData, err := c.loadProviderDataFromCache()
	require.NoError(t, err)
	require.NotNil(t, pData)
}
