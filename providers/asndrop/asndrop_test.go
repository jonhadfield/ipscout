package asndrop

import (
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/asndrop"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const testASN = 64496

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	enabled := true
	pc.Providers.ASNDrop.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.ASNDrop.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"asn":64496,"asname":"EXAMPLE-AS","cc":"NL"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, uint32(testASN), res.ASN)
	require.Equal(t, "EXAMPLE-AS", res.ASName)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := ipfetcher.Doc{Records: []ipfetcher.Record{{ASN: testASN, ASName: "EXAMPLE-AS", CC: "NL"}}}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.Records[0].ASN, res.Records[0].ASN)
}

func newTestClient(t *testing.T) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{Logger: lg, Stats: session.CreateStats(), Cache: db}
	sess.UseTestData = true

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestFindHostUsesTestDataAndRenders(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tw)

	out := (*tw).Render()
	require.Contains(t, out, "ASN-DROP | Host: 192.0.2.1")
	require.Contains(t, out, "AS64496")
	require.Contains(t, out, "EXAMPLE-AS")

	ti, err := c.ExtractThreatIndicators(res)
	require.NoError(t, err)
	require.Equal(t, "true", ti.Indicators["ASNDrop"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)
	cfg := []byte(`{"providers":{"asndrop":{"defaultMatchScore":9.0}}}`)

	rated, err := c.RateHostData([]byte(`{"asn":64496}`), cfg)
	require.NoError(t, err)
	require.True(t, rated.Detected)
	require.InDelta(t, 9.0, rated.Score, 0)
	require.Contains(t, rated.Reasons[0], "AS64496")

	// a result with no ASN is not a detection
	none, err := c.RateHostData([]byte(`{}`), cfg)
	require.NoError(t, err)
	require.False(t, none.Detected)
}

func TestInitialiseRequiresCache(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)
	c.Cache = nil
	require.ErrorIs(t, c.Initialise(), session.ErrCacheNotSet)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/asndrop_192_0_2_1_report.json")
	require.NoError(t, err)
	require.Equal(t, uint32(testASN), res.ASN)
}
