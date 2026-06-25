package process

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testPriority = int32(50)
	outputJSON   = "json"
	testProvider = "prov"
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

func TestMapsKeys(t *testing.T) {
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	keys := mapsKeys(m)
	require.Len(t, keys, 3)
	require.ElementsMatch(t, []string{"a", "b", "c"}, keys)

	require.Empty(t, mapsKeys(map[string]int{}))
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

	res := getEnabledProviders(runners)
	require.Len(t, res, 2)
	require.Contains(t, res, "on1")
	require.Contains(t, res, "on2")
	require.NotContains(t, res, "off")

	require.Nil(t, getEnabledProviders(map[string]providers.ProviderClient{}))
}

func TestGetEnabledProviderClientsNoneEnabled(t *testing.T) {
	// With a fresh session no providers are enabled by default, so this
	// should report the "no providers enabled" error.
	sess := session.New()

	_, err := getEnabledProviderClients(*sess)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no providers enabled")
}

func TestStopSpinnerIfActiveNil(t *testing.T) {
	// Must not panic with a nil spinner.
	require.NotPanics(t, func() { stopSpinnerIfActive(nil) })
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

	results := findHosts(runners, true)
	require.NotNil(t, results)

	results.RLock()
	defer results.RUnlock()

	require.Len(t, results.m, 1)
	require.Equal(t, []byte(`{"a":1}`), results.m["withData"])
	require.NotContains(t, results.m, "noData")
	require.NotContains(t, results.m, "errored")
}

func TestInitialiseProvidersHandlesErrors(t *testing.T) {
	lg := discardLogger()

	runners := map[string]providers.ProviderClient{
		"ok":      configurableStub{enabled: true},
		"failing": configurableStub{enabled: true, initErr: errors.New("boom")},
		"skipped": configurableStub{enabled: false, initErr: errors.New("should not run")},
	}

	// hideProgress=true to avoid spinner output; must not panic.
	require.NotPanics(t, func() { initialiseProviders(lg, runners, true) })
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

	results := &findHostsResults{m: map[string][]byte{
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

	results := &findHostsResults{m: map[string][]byte{"errTable": []byte(`{}`)}}

	tables := generateTables(sess, runners, results)
	require.Empty(t, tables)
}

func TestOutputUnsupportedFormat(t *testing.T) {
	sess := newTestSession(t)
	sess.Config.Global.Output = "xml"

	results := &findHostsResults{m: map[string][]byte{}}

	err := output(sess, map[string]providers.ProviderClient{}, results)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported output format")
}

func TestOutputJSON(t *testing.T) {
	sess := newTestSession(t)
	sess.Config.Global.Output = outputJSON

	results := &findHostsResults{m: map[string][]byte{
		testProvider: []byte(`{"k":"v"}`),
	}}

	require.NoError(t, output(sess, map[string]providers.ProviderClient{}, results))
}

func TestOutputJSONMarshalErrorPropagates(t *testing.T) {
	sess := newTestSession(t)
	sess.Config.Global.Output = outputJSON

	// nil data for a provider causes generateJSON to error.
	results := &findHostsResults{m: map[string][]byte{"bad": nil}}

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

	results := &findHostsResults{m: map[string][]byte{testProvider: []byte(`{}`)}}

	require.NoError(t, output(sess, runners, results))
}

func TestOutputMessages(t *testing.T) {
	sess := newTestSession(t)
	sess.Messages.AddError("an error")
	sess.Messages.AddWarn("a warning")
	sess.Messages.AddInfo("some info")

	require.NotPanics(t, func() { outputMessages(sess) })
}

func TestGenerateJSONRoundTrip(t *testing.T) {
	results := &findHostsResults{m: map[string][]byte{
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
