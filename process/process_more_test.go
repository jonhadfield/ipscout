package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/runner"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testPriority = int32(50)
	outputJSON   = "json"
	testProvider = "prov"
	testBroken   = "broken"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
}

// configurableStub is a richer provider stub allowing per-test behaviour.
type configurableStub struct {
	enabled    bool
	config     *session.Session
	findResult []byte
	findErr    error
	tbl        *table.Writer
	tblErr     error
	initErr    error
	priority   *int32
}

func (c configurableStub) Enabled() bool               { return c.enabled }
func (c configurableStub) GetConfig() *session.Session { return c.config }
func (c configurableStub) Initialise() error           { return c.initErr }
func (c configurableStub) FindHost() ([]byte, error)   { return c.findResult, c.findErr }

func (c configurableStub) CreateTable([]byte) (*table.Writer, error) {
	return c.tbl, c.tblErr
}

func (c configurableStub) Priority() *int32 { return c.priority }

func (configurableStub) RateHostData([]byte, []byte) (providers.RateResult, error) {
	return providers.RateResult{}, nil
}

func (configurableStub) ExtractThreatIndicators([]byte) (*providers.ThreatIndicators, error) {
	return nil, nil
}

func newTestSession(t *testing.T) *session.Session {
	t.Helper()

	lg := discardLogger()

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	sess := &session.Session{
		Logger:       lg,
		Stats:        session.CreateStats(),
		Cache:        db,
		Target:       os.Stdout,
		Messages:     &session.Messages{},
		HideProgress: true,
		UseTestData:  true,
	}

	return sess
}

func TestFilterProvidersByName(t *testing.T) {
	runners := map[string]providers.ProviderClient{
		"AbuseIPDB": configurableStub{enabled: true},
		"Shodan":    configurableStub{enabled: true},
		"AWS":       configurableStub{enabled: true},
	}

	// case-insensitive match on subset
	filtered := filterProvidersByName(runners, []string{"shodan", "aws"})
	require.Len(t, filtered, 2)
	require.Contains(t, filtered, "Shodan")
	require.Contains(t, filtered, "AWS")
	require.NotContains(t, filtered, "AbuseIPDB")

	// no matches
	require.Empty(t, filterProvidersByName(runners, []string{"nonexistent"}))

	// empty names
	require.Empty(t, filterProvidersByName(runners, nil))
}

func TestGetEnabledProvidersMixed(t *testing.T) {
	runners := map[string]providers.ProviderClient{
		"on1": configurableStub{enabled: true},
		"on2": configurableStub{enabled: true},
		"off": configurableStub{enabled: false},
	}

	res := runner.GetEnabledProviders(runners)
	require.Len(t, res, 2)
	require.Contains(t, res, "on1")
	require.Contains(t, res, "on2")
	require.NotContains(t, res, "off")

	require.Nil(t, runner.GetEnabledProviders(map[string]providers.ProviderClient{}))
}

func TestGetEnabledProviderClientsNoneEnabled(t *testing.T) {
	// With a fresh session no providers are enabled by default, so this
	// should report the "no providers enabled" error.
	sess := session.New()

	_, err := runner.GetEnabledProviderClients(*sess, runner.ClientOptions{RequireEnabled: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no providers enabled")
}

func TestFindHostsAggregates(t *testing.T) {
	cfg := &session.Session{Logger: discardLogger()}

	runners := map[string]providers.ProviderClient{
		"withData": configurableStub{
			enabled:    true,
			config:     cfg,
			findResult: []byte(`{"a":1}`),
		},
		"noData": configurableStub{
			enabled:    true,
			config:     cfg,
			findResult: nil,
		},
		"errored": configurableStub{
			enabled: true,
			config:  cfg,
			findErr: errors.New("lookup failed"),
		},
	}

	results := runner.FindHosts(runners, true, nil)
	require.NotNil(t, results)

	results.RLock()
	defer results.RUnlock()

	require.Len(t, results.Data, 1)
	require.Equal(t, []byte(`{"a":1}`), results.Data["withData"])
	require.NotContains(t, results.Data, "noData")
	require.NotContains(t, results.Data, "errored")
}

func TestFindHostsReportsFailedLookups(t *testing.T) {
	cfg := &session.Session{Logger: discardLogger(), Messages: &session.Messages{}}

	runners := map[string]providers.ProviderClient{
		"noMatch":  configurableStub{enabled: true, config: cfg, findErr: fmt.Errorf("x: %w", providers.ErrNoMatchFound)},
		"noData":   configurableStub{enabled: true, config: cfg, findErr: providers.ErrNoDataFound},
		testBroken: configurableStub{enabled: true, config: cfg, findErr: errors.New("status 403")},
		"alsoBad":  configurableStub{enabled: true, config: cfg, findErr: errors.New("timeout")},
	}

	runner.FindHosts(runners, true, nil)

	// routine misses are not failures; real failures share one sorted line
	require.Equal(t, []string{"lookup failed for alsoBad, broken (run with --log-level DEBUG for details)"}, cfg.Messages.Error)
}

// A provider that has already explained its failure is not named again in the
// generic lookup failure line.
func TestFindHostsSkipsAlreadyReportedFailures(t *testing.T) {
	cfg := &session.Session{Logger: discardLogger(), Messages: &session.Messages{}}

	runners := map[string]providers.ProviderClient{
		"criminalip": configurableStub{enabled: true, config: cfg, findErr: fmt.Errorf("quota exceeded: %w", providers.ErrFailureReported)},
		testBroken:   configurableStub{enabled: true, config: cfg, findErr: errors.New("status 500")},
	}

	runner.FindHosts(runners, true, nil)

	require.Equal(t, []string{"lookup failed for broken (run with --log-level DEBUG for details)"}, cfg.Messages.Error)
}

func TestFindHostsReportsRejectedAPIKeys(t *testing.T) {
	cfg := &session.Session{Logger: discardLogger(), Messages: &session.Messages{}}

	runners := map[string]providers.ProviderClient{
		"shodan":   configurableStub{enabled: true, config: cfg, findErr: fmt.Errorf("loading: shodan: %w", providers.ErrAPIKeyRejected)},
		testBroken: configurableStub{enabled: true, config: cfg, findErr: errors.New("status 500")},
	}

	runner.FindHosts(runners, true, nil)

	// a refused key names the key, and is not also counted as a failure
	require.Equal(t, []string{
		"Shodan rejected the API key: check SHODAN_API_KEY is set to a valid key",
		"lookup failed for broken (run with --log-level DEBUG for details)",
	}, cfg.Messages.Error)
}

func TestInitialiseProvidersHandlesErrors(t *testing.T) {
	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		"ok":      configurableStub{enabled: true},
		"failing": configurableStub{enabled: true, initErr: errors.New("boom")},
		"skipped": configurableStub{enabled: false, initErr: errors.New("should not run")},
	}

	// hideProgress=true to avoid spinner output; must not panic.
	require.NotPanics(t, func() { runner.InitialiseProviders(sess, runners, true) })

	// the failure is buffered as a single message rather than logged while
	// the download is in progress
	require.Len(t, sess.Messages.Error, 1)
	require.Contains(t, sess.Messages.Error[0], "failed to fetch ip ranges for failing")
	require.NotContains(t, sess.Messages.Error[0], "ok")
	require.NotContains(t, sess.Messages.Error[0], "skipped")
}

// Every failing provider is named, once, on a single line.
func TestInitialiseProvidersReportsAllFailuresOnOneLine(t *testing.T) {
	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		"zulu":    configurableStub{enabled: true, initErr: errors.New("boom")},
		"alpha":   configurableStub{enabled: true, initErr: errors.New("boom")},
		"mike":    configurableStub{enabled: true, initErr: errors.New("boom")},
		"working": configurableStub{enabled: true},
	}

	runner.InitialiseProviders(sess, runners, true)

	require.Len(t, sess.Messages.Error, 1)
	// sorted, so the line is stable between runs despite concurrent fetches
	require.Contains(t, sess.Messages.Error[0], "alpha, mike, zulu")
	require.NotContains(t, sess.Messages.Error[0], "working")
}

// A provider whose range fetch failed is still queried, as it may answer from
// cache, but its failed lookup is not reported a second time.
func TestFailedInitialiseReportedOnce(t *testing.T) {
	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		"github": configurableStub{enabled: true, config: sess, initErr: errors.New("fetch failed"), findErr: errors.New("no prefixes")},
		"selfish": configurableStub{
			enabled: true, config: sess,
			initErr: fmt.Errorf("explained: %w", providers.ErrFailureReported),
			findErr: errors.New("no prefixes"),
		},
		"cached":  configurableStub{enabled: true, config: sess, initErr: errors.New("fetch failed"), findResult: []byte(`{"a":1}`)},
		"lookups": configurableStub{enabled: true, config: sess, findErr: errors.New("status 500")},
	}

	initFailed := runner.InitialiseProviders(sess, runners, true)

	// every failed provider is returned, including one that reported itself
	require.Equal(t, []string{"cached", "github", "selfish"}, initFailed)

	results := runner.FindHosts(runners, true, initFailed)

	// the cached provider still answers
	require.Contains(t, results.Data, "cached")

	require.Equal(t, []string{
		"failed to fetch ip ranges for cached, github (run with --log-level DEBUG for details)",
		"lookup failed for lookups (run with --log-level DEBUG for details)",
	}, sess.Messages.Error)
}

// Nothing is reported when every provider fetches successfully.
func TestInitialiseProvidersSilentWhenAllSucceed(t *testing.T) {
	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		"one": configurableStub{enabled: true},
		"two": configurableStub{enabled: true},
	}

	runner.InitialiseProviders(sess, runners, true)

	require.Empty(t, sess.Messages.Error)
}

func TestGenerateTablesBuildsResults(t *testing.T) {
	sess := newTestSession(t)

	tw := table.NewWriter()
	tw.AppendRow(table.Row{"col"})

	prio := testPriority

	runners := map[string]providers.ProviderClient{
		"hasTable": configurableStub{
			enabled:  true,
			tbl:      &tw,
			priority: &prio,
		},
		"nilTable": configurableStub{
			enabled: true,
			tbl:     nil,
		},
		"noResultData": configurableStub{
			enabled: true,
			tbl:     &tw,
		},
	}

	results := &runner.HostResults{Data: map[string][]byte{
		"hasTable": []byte(`{}`),
		"nilTable": []byte(`{}`),
		// noResultData intentionally absent → skipped
	}}

	tables := generateTables(sess, runners, results)
	require.Len(t, tables, 1)
	require.Equal(t, &prio, tables[0].Priority)
	require.NotNil(t, tables[0].Table)
}

func TestGenerateTablesCreateError(t *testing.T) {
	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		"errTable": configurableStub{
			enabled: true,
			tblErr:  errors.New("create failed"),
		},
	}

	results := &runner.HostResults{Data: map[string][]byte{"errTable": []byte(`{}`)}}

	tables := generateTables(sess, runners, results)
	require.Empty(t, tables)
}

func TestOutputUnsupportedFormat(t *testing.T) {
	sess := newTestSession(t)
	sess.Config.Global.Output = "xml"

	results := &runner.HostResults{Data: map[string][]byte{}}

	err := output(sess, map[string]providers.ProviderClient{}, results)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported output format")
}

func TestOutputJSON(t *testing.T) {
	sess := newTestSession(t)
	sess.Config.Global.Output = outputJSON

	results := &runner.HostResults{Data: map[string][]byte{
		testProvider: []byte(`{"k":"v"}`),
	}}

	require.NoError(t, output(sess, map[string]providers.ProviderClient{}, results))
}

func TestOutputJSONMarshalErrorPropagates(t *testing.T) {
	sess := newTestSession(t)
	sess.Config.Global.Output = outputJSON

	// nil data for a provider causes generateJSON to error.
	results := &runner.HostResults{Data: map[string][]byte{"bad": nil}}

	err := output(sess, map[string]providers.ProviderClient{}, results)
	require.Error(t, err)
}

func TestOutputTable(t *testing.T) {
	sess := newTestSession(t)
	sess.Config.Global.Output = "table"

	tw := table.NewWriter()
	tw.AppendRow(table.Row{"data"})

	prio := testPriority

	runners := map[string]providers.ProviderClient{
		testProvider: configurableStub{enabled: true, tbl: &tw, priority: &prio},
	}

	results := &runner.HostResults{Data: map[string][]byte{testProvider: []byte(`{}`)}}

	require.NoError(t, output(sess, runners, results))
}

func TestOutputMessages(t *testing.T) {
	sess := newTestSession(t)
	sess.Messages.AddError("an error")
	sess.Messages.AddWarn("a warning")
	sess.Messages.AddInfo("some info")

	require.NotPanics(t, func() { runner.OutputMessages(sess) })
}

func TestGenerateJSONRoundTrip(t *testing.T) {
	results := &runner.HostResults{Data: map[string][]byte{
		"one": []byte(`{"x":1}`),
		"two": []byte(`{"y":2}`),
	}}

	raw, err := generateJSON(results)
	require.NoError(t, err)

	var out map[string]json.RawMessage

	require.NoError(t, json.Unmarshal(raw, &out))
	require.Len(t, out, 2)
	require.JSONEq(t, `{"x":1}`, string(out["one"]))
	require.JSONEq(t, `{"y":2}`, string(out["two"]))
}
