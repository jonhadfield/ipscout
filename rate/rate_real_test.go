package rate

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// fakeProviderClient is an in-memory ProviderClient used to exercise the
// rating logic without any network access or real providers.
type fakeProviderClient struct {
	rate       providers.RateResult
	indicators *providers.ThreatIndicators
}

func (f fakeProviderClient) Enabled() bool               { return true }
func (f fakeProviderClient) GetConfig() *session.Session { return nil }
func (f fakeProviderClient) Initialise() error           { return nil }
func (f fakeProviderClient) FindHost() ([]byte, error)   { return nil, nil }
func (f fakeProviderClient) Priority() *int32            { return nil }
func (f fakeProviderClient) CreateTable([]byte) (*table.Writer, error) {
	return nil, nil
}

func (f fakeProviderClient) RateHostData(_ []byte, _ []byte) (providers.RateResult, error) {
	return f.rate, nil
}

func (f fakeProviderClient) ExtractThreatIndicators(_ []byte) (*providers.ThreatIndicators, error) {
	return f.indicators, nil
}

const (
	testScoreHigh     = 8.5
	testHost          = "1.2.3.4"
	providerAbuseIPDB = "abuseipdb"
)

func newTestSession(t *testing.T) *session.Session {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	sess := &session.Session{
		Logger: lg,
		Stats:  session.CreateStats(),
	}
	sess.Host = netip.MustParseAddr(testHost)

	return sess
}

func TestGetRatingConfigDefault(t *testing.T) {
	t.Parallel()

	// Empty path uses the embedded default rating config.
	got, err := GetRatingConfig("")
	require.NoError(t, err)
	require.NotEmpty(t, got)
	require.True(t, json.Valid(got))
}

func TestGetRatingConfigFromFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "ratingConfig.json")

	got, err := GetRatingConfig(path)
	require.NoError(t, err)
	require.NotEmpty(t, got)
	require.True(t, json.Valid(got))
}

func TestGetRatingConfigMissingFile(t *testing.T) {
	t.Parallel()

	got, err := GetRatingConfig(filepath.Join("testdata", "does-not-exist.json"))
	require.Error(t, err)
	require.Nil(t, got)
}

func TestNew(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	rater, err := New(sess)
	require.NoError(t, err)
	require.Same(t, sess, rater.Session)
}

func TestCreateResultsTableWithResults(t *testing.T) {
	t.Parallel()

	rater := Rater{Session: newTestSession(t)}

	info := RatingOutput{
		AverageScore:          testScoreHigh,
		ProvidersThatDetected: 2,
		Recommendation:        txtBlock,
		Results: []rateResultsOutputItem{
			{Provider: providerAbuseIPDB, Detected: true, Score: testScoreHigh, Reason: "known bad actor"},
			{Provider: "shodan", Detected: false, Score: -1, Reason: ""},
		},
	}

	tw, err := rater.CreateResultsTable(info)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, providerAbuseIPDB)
	require.Contains(t, rendered, "shodan")
	// Score of -1 is rendered as a dash.
	require.Contains(t, rendered, "-")
	require.Contains(t, rendered, testHost)
}

func TestCreateResultsTableEmpty(t *testing.T) {
	t.Parallel()

	rater := Rater{Session: newTestSession(t)}

	tw, err := rater.CreateResultsTable(RatingOutput{})
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, "no results found")
}

func TestCreateThreatIndicatorsTableWithIndicators(t *testing.T) {
	t.Parallel()

	rater := Rater{Session: newTestSession(t)}

	ctis := []providers.ThreatIndicators{
		{
			Provider:   providerAbuseIPDB,
			Indicators: map[string]string{"abuseConfidenceScore": "100"},
		},
		{
			Provider:   "shodan",
			Indicators: map[string]string{"openPorts": "22,80,443"},
		},
	}

	tw, err := rater.CreateThreatIndicatorsTable(ctis)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, providerAbuseIPDB)
	require.Contains(t, rendered, "abuseConfidenceScore")
	require.Contains(t, rendered, testHost)
}

func TestCreateThreatIndicatorsTableEmpty(t *testing.T) {
	t.Parallel()

	rater := Rater{Session: newTestSession(t)}

	tw, err := rater.CreateThreatIndicatorsTable(nil)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, "no threat indicators found")
}

func TestGetEnabledProviders(t *testing.T) {
	t.Parallel()

	// Empty input yields nil (no enabled providers).
	require.Nil(t, getEnabledProviders(map[string]providers.ProviderClient{}))
}

func TestMapsKeys(t *testing.T) {
	t.Parallel()

	m := map[string]int{"a": 1, "b": 2, "c": 3}

	keys := mapsKeys(m)
	require.Len(t, keys, len(m))
	require.ElementsMatch(t, []string{"a", "b", "c"}, keys)
}

func TestStaticRateFindHostsResultsBlock(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		providerAbuseIPDB: fakeProviderClient{rate: providers.RateResult{
			Detected: true,
			Score:    testScoreHigh,
			Reasons:  []string{"known bad actor"},
		}},
	}

	results := &findHostsResults{m: map[string][]byte{providerAbuseIPDB: []byte("{}")}}

	cfg, err := GetRatingConfig("")
	require.NoError(t, err)

	out, err := staticRateFindHostsResults(sess, runners, results, cfg)
	require.NoError(t, err)
	require.Equal(t, 1, out.ProvidersThatDetected)
	require.InDelta(t, testScoreHigh, out.AverageScore, 0.001)
	require.Equal(t, txtBlock, out.Recommendation)
	require.Len(t, out.Results, 1)
}

func TestStaticRateFindHostsResultsNoBlockOverride(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		"trusted": fakeProviderClient{rate: providers.RateResult{
			Detected: true,
			Score:    testScoreHigh,
			Reasons:  []string{"on allow list"},
			Threat:   "noblock",
		}},
	}

	results := &findHostsResults{m: map[string][]byte{"trusted": []byte("{}")}}

	cfg, err := GetRatingConfig("")
	require.NoError(t, err)

	out, err := staticRateFindHostsResults(sess, runners, results, cfg)
	require.NoError(t, err)
	// noblock threat forces an allow recommendation regardless of score.
	require.Equal(t, txtAllow, out.Recommendation)
}

func TestStaticRateFindHostsResultsNoDetection(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		"clean": fakeProviderClient{rate: providers.RateResult{Detected: false}},
	}

	results := &findHostsResults{m: map[string][]byte{"clean": []byte("{}")}}

	cfg, err := GetRatingConfig("")
	require.NoError(t, err)

	_, err = staticRateFindHostsResults(sess, runners, results, cfg)
	require.Error(t, err)
}

func TestStaticRateFindHostsResultsBadConfig(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	_, err := staticRateFindHostsResults(sess, nil, &findHostsResults{m: nil}, []byte("not json"))
	require.Error(t, err)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	runners := map[string]providers.ProviderClient{
		providerAbuseIPDB: fakeProviderClient{indicators: &providers.ThreatIndicators{
			Provider:   providerAbuseIPDB,
			Indicators: map[string]string{"abuseConfidenceScore": "100"},
		}},
		"empty": fakeProviderClient{indicators: nil},
	}

	results := &findHostsResults{m: map[string][]byte{
		providerAbuseIPDB: []byte("{}"),
		"empty":           []byte("{}"),
	}}

	tis, err := extractThreatIndicators(sess, runners, results)
	require.NoError(t, err)
	// Only the provider returning non-nil indicators is included.
	require.Len(t, tis, 1)
	require.Equal(t, providerAbuseIPDB, tis[0].Provider)
}

func TestStopSpinnerIfActiveNil(t *testing.T) {
	t.Parallel()

	// Should not panic with a nil spinner.
	require.NotPanics(t, func() { stopSpinnerIfActive(nil) })
}
