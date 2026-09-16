package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/runner"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

type stubProvider struct{ enabled bool }

func (s stubProvider) Enabled() bool                           { return s.enabled }
func (stubProvider) GetConfig() *session.Session               { return nil }
func (stubProvider) Initialise() error                         { return nil }
func (stubProvider) FindHost() ([]byte, error)                 { return nil, nil }
func (stubProvider) CreateTable([]byte) (*table.Writer, error) { return nil, nil }
func (stubProvider) Priority() *int32                          { return nil }
func (stubProvider) RateHostData([]byte, []byte) (providers.RateResult, error) {
	return providers.RateResult{}, nil
}

func (stubProvider) ExtractThreatIndicators([]byte) (*providers.ThreatIndicators, error) {
	return nil, nil
}

func TestNew(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		n, err := New(session.New())
		require.NoError(t, err)
		require.NotNil(t, n)
	})
}

func TestGetEnabledProviders(t *testing.T) {
	runners := map[string]providers.ProviderClient{
		"a": stubProvider{enabled: true},
		"b": stubProvider{enabled: false},
	}

	res := runner.GetEnabledProviders(runners)
	require.Len(t, res, 1)
	require.NotNil(t, res["a"])

	res = runner.GetEnabledProviders(map[string]providers.ProviderClient{"b": stubProvider{enabled: false}})
	require.Nil(t, res)
}

func TestGenerateJSON(t *testing.T) {
	results := &runner.HostResults{Data: map[string][]byte{
		"prov1": []byte(`{"key":"value"}`),
	}}

	jm, err := generateJSON(results)
	require.NoError(t, err)

	var out map[string]map[string]string

	require.NoError(t, json.Unmarshal(jm, &out))
	require.Equal(t, "value", out["prov1"]["key"])

	results = &runner.HostResults{Data: map[string][]byte{"bad": nil}}
	jm, err = generateJSON(results)
	require.Error(t, err)
	require.Nil(t, jm)
}

// failingProvider fails to initialise with whatever error it is given, so the
// two ways a failure can be reported can be told apart.
type failingProvider struct {
	stubProvider
	err error
}

func (f failingProvider) Initialise() error { return f.err }

func TestInitialiseProvidersFailureReporting(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantMessage bool
	}{
		{
			name:        "an unexplained failure is named in the generic line",
			err:         errors.New("connection refused"),
			wantMessage: true,
		},
		{
			name: "a provider that already explained itself is not named again",
			// what azurewaf returns once it has told the user their azure login
			// expired and printed the az command to fix it
			err:         fmt.Errorf("azure waf credentials expired: %w", providers.ErrFailureReported),
			wantMessage: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess := session.New()
			sess.Logger = slog.New(slog.DiscardHandler)
			runners := map[string]providers.ProviderClient{
				"stub": failingProvider{stubProvider: stubProvider{enabled: true}, err: tc.err},
			}

			runner.InitialiseProviders(sess, runners, true)

			sess.Messages.Mu.Lock()
			errs := append([]string(nil), sess.Messages.Error...)
			sess.Messages.Mu.Unlock()

			if tc.wantMessage {
				require.Len(t, errs, 1)
				require.Contains(t, errs[0], "failed to fetch ip ranges for stub")

				return
			}

			require.Empty(t, errs, "provider reported its own failure, so the generic line should be absent")
		})
	}
}
