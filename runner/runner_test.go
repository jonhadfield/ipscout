package runner_test

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/providers/ptr"
	"github.com/jonhadfield/ipscout/runner"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testHost   = "8.8.8.8"
	provBroken = "broken"
	provOK     = "ok"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
}

func testSession() *session.Session {
	sess := session.New()
	sess.Logger = discardLogger()
	sess.Host = netip.MustParseAddr(testHost)

	return sess
}

// stub is a ProviderClient whose every answer is set by the test.
type stub struct {
	enabled    bool
	config     *session.Session
	findResult []byte
	findErr    error
	initErr    error
}

func (s stub) Enabled() bool               { return s.enabled }
func (s stub) GetConfig() *session.Session { return s.config }
func (s stub) Initialise() error           { return s.initErr }
func (s stub) FindHost() ([]byte, error)   { return s.findResult, s.findErr }
func (s stub) Priority() *int32            { return nil }
func (s stub) CreateTable([]byte) (*table.Writer, error) {
	return nil, nil
}

func (s stub) RateHostData([]byte, []byte) (providers.RateResult, error) {
	return providers.RateResult{}, nil
}

func (s stub) ExtractThreatIndicators([]byte) (*providers.ThreatIndicators, error) {
	return nil, nil
}

func TestGetEnabledProviders(t *testing.T) {
	t.Parallel()

	runners := map[string]providers.ProviderClient{
		provOK:    stub{enabled: true},
		"skipped": stub{enabled: false},
	}

	enabled := runner.GetEnabledProviders(runners)
	require.Len(t, enabled, 1)
	require.Contains(t, enabled, provOK)

	// nothing enabled reads as nil, so a caller can test it directly
	require.Nil(t, runner.GetEnabledProviders(map[string]providers.ProviderClient{"off": stub{}}))
}

func TestGetEnabledProviderClients(t *testing.T) {
	t.Parallel()

	sess := *testSession()

	enabled := true
	sess.Providers.PTR.Enabled = &enabled

	clients, err := runner.GetEnabledProviderClients(sess, runner.ClientOptions{RequireEnabled: true})
	require.NoError(t, err)
	require.Contains(t, clients, ptr.ProviderName)

	// PTR does not support rating, so asking for raters only leaves it out
	raters, err := runner.GetEnabledProviderClients(sess, runner.ClientOptions{RatingOnly: true})
	require.NoError(t, err)
	require.NotContains(t, raters, ptr.ProviderName)

	// with nothing enabled, RequireEnabled is what turns an empty map into an error
	var bare session.Session

	bare.Logger = discardLogger()

	_, err = runner.GetEnabledProviderClients(bare, runner.ClientOptions{RequireEnabled: true})
	require.Error(t, err)

	empty, err := runner.GetEnabledProviderClients(bare, runner.ClientOptions{})
	require.NoError(t, err)
	require.Empty(t, empty)
}

func TestInitialiseProvidersReportsAndReturnsFailures(t *testing.T) {
	t.Parallel()

	sess := testSession()

	runners := map[string]providers.ProviderClient{
		provOK:    stub{enabled: true},
		"zulu":    stub{enabled: true, initErr: errors.New("boom")},
		"alpha":   stub{enabled: true, initErr: errors.New("boom")},
		"self":    stub{enabled: true, initErr: fmt.Errorf("explained: %w", providers.ErrFailureReported)},
		"skipped": stub{enabled: false, initErr: errors.New("should not run")},
	}

	initFailed := runner.InitialiseProviders(sess, runners, true)

	// every provider that failed is returned, including the self-reporting one
	require.Equal(t, []string{"alpha", "self", "zulu"}, initFailed)

	// but the generic line names only those that did not explain themselves
	require.Len(t, sess.Messages.Error, 1)
	require.Contains(t, sess.Messages.Error[0], "alpha, zulu")
	require.NotContains(t, sess.Messages.Error[0], "self")
	require.NotContains(t, sess.Messages.Error[0], provOK)
}

func TestInitialiseProvidersSilentWhenAllSucceed(t *testing.T) {
	t.Parallel()

	sess := testSession()

	require.Empty(t, runner.InitialiseProviders(sess, map[string]providers.ProviderClient{
		provOK: stub{enabled: true},
	}, true))
	require.Empty(t, sess.Messages.Error)
}

func TestFindHostsCollectsResults(t *testing.T) {
	t.Parallel()

	sess := testSession()

	runners := map[string]providers.ProviderClient{
		"withData": stub{enabled: true, config: sess, findResult: []byte(`{"a":1}`)},
		"noData":   stub{enabled: true, config: sess},
	}

	results := runner.FindHosts(runners, true, nil)

	results.RLock()
	defer results.RUnlock()

	require.Equal(t, []byte(`{"a":1}`), results.Data["withData"])
	require.NotContains(t, results.Data, "noData")
	require.Empty(t, sess.Messages.Error)
}

func TestFindHostsClassifiesErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		initFailed []string
		want       []string
	}{
		{
			name: "no match is routine",
			err:  fmt.Errorf("x: %w", providers.ErrNoMatchFound),
			want: nil,
		},
		{
			name: "no data is routine",
			err:  providers.ErrNoDataFound,
			want: nil,
		},
		{
			name: "already reported is left to the provider",
			err:  fmt.Errorf("quota: %w", providers.ErrFailureReported),
			want: nil,
		},
		{
			name:       "a failed initialise is not reported twice",
			err:        errors.New("no prefixes"),
			initFailed: []string{provBroken},
			want:       nil,
		},
		{
			name: "a refused key names the key",
			err:  fmt.Errorf("shodan: %w", providers.ErrAPIKeyRejected),
			want: []string{"rejected the API key"},
		},
		{
			name: "anything else is a lookup failure",
			err:  errors.New("status 500"),
			want: []string{"lookup failed for " + provBroken},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sess := testSession()

			runner.FindHosts(map[string]providers.ProviderClient{
				provBroken: stub{enabled: true, config: sess, findErr: tt.err},
			}, true, tt.initFailed)

			require.Len(t, sess.Messages.Error, len(tt.want))

			for i, want := range tt.want {
				require.Contains(t, sess.Messages.Error[i], want)
			}
		})
	}
}

func TestFindHostsReportsRejectedKeysBeforeFailures(t *testing.T) {
	t.Parallel()

	sess := testSession()

	runner.FindHosts(map[string]providers.ProviderClient{
		"shodan":   stub{enabled: true, config: sess, findErr: fmt.Errorf("shodan: %w", providers.ErrAPIKeyRejected)},
		provBroken: stub{enabled: true, config: sess, findErr: errors.New("status 500")},
	}, true, nil)

	require.Len(t, sess.Messages.Error, 2)
	require.Contains(t, sess.Messages.Error[0], "Shodan rejected the API key: check SHODAN_API_KEY")
	require.Contains(t, sess.Messages.Error[1], "lookup failed for "+provBroken)
}

func TestOutputMessagesPrintsEveryLevel(t *testing.T) {
	t.Parallel()

	sess := testSession()
	sess.Messages.AddError("an error")
	sess.Messages.AddWarn("a warning")
	sess.Messages.AddInfo("an info")
	sess.Messages.AddTip("a tip")

	// writes to stderr; the point is that every level is handled
	require.NotPanics(t, func() { runner.OutputMessages(sess) })
}

func TestMapsKeys(t *testing.T) {
	t.Parallel()

	keys := runner.MapsKeys(map[string]int{"b": 2, "a": 1})
	sort.Strings(keys)
	require.Equal(t, []string{"a", "b"}, keys)
	require.Empty(t, runner.MapsKeys(map[string]int{}))
}
