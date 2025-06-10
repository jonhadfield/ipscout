package process

import (
	"encoding/json"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/providers"
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

	res := getEnabledProviders(runners)
	require.Len(t, res, 1)
	require.NotNil(t, res["a"])

	res = getEnabledProviders(map[string]providers.ProviderClient{"b": stubProvider{enabled: false}})
	require.Nil(t, res)
}

func TestGenerateJSON(t *testing.T) {
	results := &findHostsResults{m: map[string][]byte{
		"prov1": []byte(`{"key":"value"}`),
	}}

	jm, err := generateJSON(results)
	require.NoError(t, err)

	var out map[string]map[string]string
	require.NoError(t, json.Unmarshal(jm, &out))
	require.Equal(t, "value", out["prov1"]["key"])

	results = &findHostsResults{m: map[string][]byte{"bad": nil}}
	jm, err = generateJSON(results)
	require.Error(t, err)
	require.Nil(t, jm)
}
