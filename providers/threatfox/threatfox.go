package threatfox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/threatfox"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "threatfox"
	DocTTL       = 24 * time.Hour
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating threatfox client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.ThreatFox.Enabled != nil && *c.Providers.ThreatFox.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.ThreatFox.OutputPriority
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
		indicators["ThreatFox"] = "true"
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
		return rateResult, errors.New("no prefix found in threatfox data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.ThreatFox.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"listed by ThreatFox"}
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
		return nil, fmt.Errorf("error unmarshalling threatfox data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	doc, err := client.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching threatfox data: %w", err)
	}

	if len(doc.IPv4Prefixes) == 0 && len(doc.IPv6Prefixes) == 0 {
		return fmt.Errorf("threatfox document contains no prefixes: %w", providers.ErrFailedToFetchData)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling threatfox provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.ThreatFox.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.ThreatFox.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting threatfox data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising threatfox client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking threatfox cache: %w", err)
	}

	if ok {
		c.Logger.Debug("threatfox provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading threatfox provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading threatfox api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ipfetcher.Doc, error) {
	c.Logger.Debug("loading threatfox provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *ipfetcher.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached threatfox provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading threatfox cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/threatfox/testdata/threatfox_192_0_2_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting threatfox test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("threatfox match returned from test data", "host", "192.0.2.1")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the threatfox data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading threatfox host data from cache: %w", err)
	}

	for _, p := range doc.IPv4Prefixes {
		if p.Contains(c.Host) {
			result = &HostSearchResult{Prefix: p}

			c.Logger.Debug("returning threatfox host match data")

			break
		}
	}

	if result == nil {
		for _, p := range doc.IPv6Prefixes {
			if p.Contains(c.Host) {
				result = &HostSearchResult{Prefix: p}

				c.Logger.Debug("returning threatfox host match data")

				break
			}
		}
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

	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), providers.DashIfEmpty(result.Prefix.String())})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("ThreatFox | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("ThreatFox | Host: %s", "192.0.2.1")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw    []byte       `json:"Raw"`
	Prefix netip.Prefix `json:"prefix"`
}
