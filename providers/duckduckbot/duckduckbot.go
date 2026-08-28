package duckduckbot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/duckduckbot"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "duckduckbot"
	// DuckDuckGo serves this list with Cache-Control: max-age=31536000, a year,
	// and it had not changed for close to two months at the time of review.
	DocTTL = 7 * 24 * time.Hour
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating duckduckbot client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.DuckDuckBot.Enabled != nil && *c.Providers.DuckDuckBot.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.DuckDuckBot.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	threatIndicators := providers.ThreatIndicators{Provider: ProviderName}

	indicators := make(map[string]string)

	if doc.Prefix.IsValid() {
		indicators["DuckDuckBot"] = "true"
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
		return rateResult, errors.New("no prefix found in duckduckbot data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.DuckDuckBot.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"source is DuckDuckBot"}
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

func unmarshalProviderData(data []byte) (*ipfetcher.Doc, error) {
	var res *ipfetcher.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling duckduckbot data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	doc, err := client.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching duckduckbot data: %w", err)
	}

	// an upstream error response can yield an empty document with a nil error;
	// caching it would blank all lookups until the TTL expires
	if len(doc.IPv4Prefixes) == 0 && len(doc.IPv6Prefixes) == 0 {
		return fmt.Errorf("duckduckbot document contains no prefixes: %w", providers.ErrFailedToFetchData)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling duckduckbot provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.DuckDuckBot.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.DuckDuckBot.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.CreationTime.String(),
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting duckduckbot data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising duckduckbot client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking duckduckbot cache: %w", err)
	}

	if ok {
		c.Logger.Debug("duckduckbot provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading duckduckbot provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading duckduckbot api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ipfetcher.Doc, error) {
	c.Logger.Debug("loading duckduckbot provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *ipfetcher.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached duckduckbot provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading duckduckbot cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/duckduckbot/testdata/duckduckbot_104_43_54_127_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting duckduckbot test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("duckduckbot match returned from test data", "host", "104.43.54.127")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the duckduckbot data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	// return cached report if test data is enabled
	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading duckduckbot host data from cache: %w", err)
	}

	// search in the data for the host
	switch {
	case c.Host.Is4():
		for _, record := range doc.IPv4Prefixes {
			if record.IPv4Prefix.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix:       record.IPv4Prefix,
					CreationTime: doc.CreationTime,
				}

				c.Logger.Debug("returning duckduckbot host match data")

				break
			}
		}
	case c.Host.Is6():
		for _, record := range doc.IPv6Prefixes {
			if record.IPv6Prefix.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix:       record.IPv6Prefix,
					CreationTime: doc.CreationTime,
				}

				c.Logger.Debug("returning duckduckbot host match data")

				break
			}
		}
	default:
		return nil, fmt.Errorf(constants.MsgInvalidHostFmt, c.Host.String())
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

	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), providers.DashIfEmpty(result.Prefix.String())})

	if !result.CreationTime.IsZero() {
		tw.AppendRow(table.Row{"Creation Time", providers.DashIfEmpty(result.CreationTime.String())})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("DuckDuckBot | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("DuckDuckBot | Host: %s", "104.43.54.127")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw          []byte       `json:"Raw"`
	Prefix       netip.Prefix `json:"prefix"`
	CreationTime time.Time    `json:"creation_time"`
}
