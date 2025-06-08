package google

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	fetcherGoogle "github.com/jonhadfield/ip-fetcher/providers/google"
	"github.com/stretchr/testify/require"
)

func TestEnabled(t *testing.T) {
	pc := &ProviderClient{}
	enabled := true
	pc.Providers.Google.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.Google.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestUnmarshalResponse(t *testing.T) {
	data := []byte(`{"prefix":"10.0.0.0/8","creation_time":"2024-05-20T10:00:00Z"}`)
	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), res.Prefix)
	require.Equal(t, time.Date(2024, 5, 20, 10, 0, 0, 0, time.UTC), res.CreationTime)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalProviderData(t *testing.T) {
	doc := fetcherGoogle.Doc{
		CreationTime: time.Date(2024, 5, 20, 10, 0, 0, 0, time.UTC),
		IPv4Prefixes: []fetcherGoogle.IPv4Entry{{IPv4Prefix: netip.MustParsePrefix("10.0.0.0/8")}},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.CreationTime, res.CreationTime)
	require.Equal(t, doc.IPv4Prefixes[0].IPv4Prefix, res.IPv4Prefixes[0].IPv4Prefix)
}

func TestLoadResultsFile(t *testing.T) {
	res, err := loadResultsFile("testdata/google_34_3_8_8_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("34.3.8.0/21"), res.Prefix)
	require.False(t, res.CreationTime.IsZero())
}
