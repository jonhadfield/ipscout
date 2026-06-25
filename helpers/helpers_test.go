package helpers

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testProvider = "testprovider"
	trackSleep   = 5 * time.Millisecond
)

func TestParseHostIPv4(t *testing.T) {
	t.Parallel()

	addr, err := ParseHost("8.8.8.8")
	require.NoError(t, err)
	require.True(t, addr.Is4())
	require.Equal(t, "8.8.8.8", addr.String())
}

func TestParseHostIPv6(t *testing.T) {
	t.Parallel()

	addr, err := ParseHost("2001:4860:4860::8888")
	require.NoError(t, err)
	require.True(t, addr.Is6())
	require.Equal(t, "2001:4860:4860::8888", addr.String())
}

func TestParseHostSingleHostCIDR(t *testing.T) {
	t.Parallel()

	addr, err := ParseHost("1.2.3.4/32")
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4", addr.String())
}

func TestParseHostLoopbackFQDN(t *testing.T) {
	t.Parallel()

	addr, err := ParseHost("localhost")
	require.NoError(t, err)
	require.True(t, addr.IsLoopback())
}

func TestParseHostInvalid(t *testing.T) {
	t.Parallel()

	addr, err := ParseHost("this.is.not.a.valid.host.invalid")
	require.Error(t, err)
	require.False(t, addr.IsValid())
}

func TestGetHTTPClient(t *testing.T) {
	t.Parallel()

	hc := GetHTTPClient()
	require.NotNil(t, hc)
	require.NotNil(t, hc.HTTPClient)
}

func TestTrackDuration(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex

	durations := make(map[string]time.Duration)

	done := TrackDuration(&mu, durations, testProvider)

	time.Sleep(trackSleep)
	done()

	mu.Lock()
	defer mu.Unlock()

	d, ok := durations[testProvider]
	require.True(t, ok)
	require.Positive(t, d)
}

func TestFindProjectRoot(t *testing.T) {
	t.Parallel()

	root, err := FindProjectRoot()
	require.NoError(t, err)
	require.NotEmpty(t, root)

	_, statErr := os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, statErr)
}

func TestPrefixProjectRootEmpty(t *testing.T) {
	t.Parallel()

	root, err := FindProjectRoot()
	require.NoError(t, err)

	prefixed, err := PrefixProjectRoot("")
	require.NoError(t, err)
	require.Equal(t, root, prefixed)
}

func TestPrefixProjectRootRelative(t *testing.T) {
	t.Parallel()

	root, err := FindProjectRoot()
	require.NoError(t, err)

	prefixed, err := PrefixProjectRoot("helpers")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "helpers"), prefixed)
}

func TestPrefixProjectRootAbsolute(t *testing.T) {
	t.Parallel()

	abs := filepath.Join(string(filepath.Separator), "tmp", "ipscout-abs")

	prefixed, err := PrefixProjectRoot(abs)
	require.NoError(t, err)
	require.Equal(t, abs, prefixed)
}
