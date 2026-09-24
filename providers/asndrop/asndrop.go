package asndrop

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/asndrop"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/providers/iptoasn"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "asndrop"
	DocTTL       = 24 * time.Hour
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating asndrop client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.ASNDrop.Enabled != nil && *c.Providers.ASNDrop.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.ASNDrop.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	return &providers.ThreatIndicators{
		Provider:   ProviderName,
		Indicators: map[string]string{"ASNDrop": "true"},
	}, nil
}

func (c *ProviderClient) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	if doc.ASN == 0 {
		return providers.RateResult{}, nil
	}

	return providers.RateResult{
		Detected: true,
		Score:    ratingConfig.ProviderRatingsConfigs.ASNDrop.DefaultMatchScore,
		Reasons:  []string{fmt.Sprintf("AS%d is on Spamhaus ASN-DROP", doc.ASN)},
	}, nil
}

func unmarshalResponse(rBody []byte) (*HostSearchResult, error) {
	var res *HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	res.Raw = rBody

	return res, nil
}

func unmarshalProviderData(data []byte) (*ipfetcher.Doc, error) {
	var res *ipfetcher.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling asndrop data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	doc, err := client.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching asndrop data: %w", err)
	}

	if len(doc.Records) == 0 {
		return fmt.Errorf("asndrop document contains no records: %w", providers.ErrFailedToFetchData)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling asndrop provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.ASNDrop.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.ASNDrop.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting asndrop data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising asndrop client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking asndrop cache: %w", err)
	}

	if ok {
		c.Logger.Debug("asndrop provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading asndrop provider data from source")

	if err = c.loadProviderData(); err != nil {
		return fmt.Errorf("loading asndrop api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ipfetcher.Doc, error) {
	c.Logger.Debug("loading asndrop provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	item, err := cache.Read(c.Logger, c.Cache, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("error reading asndrop cache: %w", err)
	}

	doc, uErr := unmarshalProviderData(item.Value)
	if uErr != nil {
		defer func() {
			_ = cache.Delete(c.Logger, c.Cache, cacheKey)
		}()

		return nil, fmt.Errorf("error unmarshalling cached asndrop provider doc: %w", uErr)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/asndrop/testdata/asndrop_192_0_2_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting asndrop test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("asndrop match returned from test data", "host", "192.0.2.1")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost reports whether the AS announcing the host is on ASN-DROP.
//
// ASN-DROP names whole networks rather than addresses, so unlike every other
// provider this one needs the host's AS number. That comes from the ip2asn
// data the iptoasn provider already caches, so no second source is fetched.
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	if c.UseTestData {
		return loadTestData(c)
	}

	asn, err := iptoasn.ASNForHost(c.Session)
	if err != nil {
		return nil, fmt.Errorf("asndrop needs the host's AS number: %w", err)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading asndrop host data from cache: %w", err)
	}

	var result *HostSearchResult

	for _, record := range doc.Records {
		if uint32(record.ASN) != asn { //nolint:gosec // ASNs are within uint32
			continue
		}

		result = &HostSearchResult{
			ASN:    asn,
			ASName: record.ASName,
			RIR:    record.RIR,
			Domain: record.Domain,
			CC:     record.CC,
		}

		c.Logger.Debug("returning asndrop host match data", "asn", asn)

		break
	}

	if result == nil {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	result.Raw = raw

	return result.Raw, nil
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	result, err := unmarshalResponse(data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	tw := table.NewWriter()

	tw.AppendRow(table.Row{providers.PadRight("ASN", providers.Column1MinWidth), providers.DashIfEmpty(fmt.Sprintf("AS%d", result.ASN))})
	tw.AppendRow(table.Row{"AS Name", providers.DashIfEmpty(result.ASName)})
	tw.AppendRow(table.Row{"Domain", providers.DashIfEmpty(result.Domain)})
	tw.AppendRow(table.Row{"Country", providers.DashIfEmpty(result.CC)})
	tw.AppendRow(table.Row{"RIR", providers.DashIfEmpty(result.RIR)})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("ASN-DROP | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("ASN-DROP | Host: %s", "192.0.2.1")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw    []byte `json:"Raw"`
	ASN    uint32 `json:"asn"`
	ASName string `json:"asname"`
	RIR    string `json:"rir"`
	Domain string `json:"domain"`
	CC     string `json:"cc"`
}
