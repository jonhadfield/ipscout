package scaleway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/scaleway"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "scaleway"
	DocTTL       = 24 * time.Hour
)

type Config struct {
	_ struct{}
	session.Session
	Host netip.Addr
}

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating scaleway client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.Scaleway.Enabled != nil && *c.Providers.Scaleway.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Scaleway.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	threatIndicators := providers.ThreatIndicators{
		Provider: ProviderName,
	}

	indicators := make(map[string]string)

	if doc.Prefix.IsValid() {
		indicators["HostedInScaleway"] = "true"
	}

	threatIndicators.Indicators = indicators

	return &threatIndicators, nil
}

func (c *ProviderClient) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	if doc.Prefix.String() == "" {
		return rateResult, errors.New("no prefix found in scaleway data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.Scaleway.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"hosted in Scaleway"}
	}

	return rateResult, nil
}

func unmarshalResponse(rBody []byte) (*HostSearchResult, error) {
	var res *HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	res.Raw = rBody

	return res, nil
}

func unmarshalProviderData(data []byte) (Doc, error) {
	var res Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return Doc{}, fmt.Errorf("error unmarshalling scaleway data: %w", err)
	}

	return res, nil
}

type Doc struct {
	IPv4Prefixes []netip.Prefix `json:"IPv4Prefixes"`
	IPv6Prefixes []netip.Prefix `json:"IPv6Prefixes"`
}

func (c *ProviderClient) loadProviderData() error {
	sc := ipfetcher.New()
	sc.Client = c.HTTPClient

	if c.Providers.Scaleway.URL != "" {
		sc.DownloadURL = c.Providers.Scaleway.URL
		c.Logger.Debug("overriding scaleway source", "url", sc.DownloadURL)
	}

	doc, err := sc.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching scaleway data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling scaleway provider Doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Scaleway.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Scaleway.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting scaleway data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising scaleway client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache,
		providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking scaleway cache: %w", err)
	}

	if ok {
		c.Logger.Info("scaleway provider data found in cache")

		return nil
	}

	c.Logger.Info("loading scaleway provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading scaleway api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (Doc, error) {
	c.Logger.Info("loading scaleway provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return Doc{}, fmt.Errorf("error unmarshalling cached scaleway provider Doc: %w", uErr)
		}
	} else {
		return Doc{}, fmt.Errorf("error reading scaleway cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/scaleway/testdata/scaleway_192_0_2_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting scaleway test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("scaleway match returned from test data", "host", "192.0.2.1")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the scaleway data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	var err error

	// return cached report if test data is enabled
	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading scaleway host data from cache: %w", err)
	}

	for _, p := range doc.IPv4Prefixes {
		if p.Contains(c.Host) {
			result = &HostSearchResult{Prefix: p}

			c.Logger.Debug("returning scaleway host match data")

			break
		}
	}

	for _, p := range doc.IPv6Prefixes {
		if p.Contains(c.Host) {
			result = &HostSearchResult{Prefix: p}

			c.Logger.Debug("returning scaleway host match data")

			break
		}
	}

	if result == nil {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	var raw []byte

	raw, err = json.Marshal(result)
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

	var rows []table.Row

	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), providers.DashIfEmpty(result.Prefix.String())})

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("Scaleway | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("Scaleway | Host: %s", "192.0.2.1")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw    []byte       `json:"Raw"`
	Prefix netip.Prefix `json:"prefix"`
}
