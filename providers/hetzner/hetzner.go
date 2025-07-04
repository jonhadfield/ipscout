package hetzner

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ip-fetcher/providers/hetzner"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "hetzner"
	DocTTL       = 24 * time.Hour
)

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating hetzner client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.Hetzner.Enabled != nil && *c.Providers.Hetzner.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Hetzner.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	return nil, nil
}

func (c *ProviderClient) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf("error unmarshalling rating config: %w", err)
	}

	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf("error unmarshalling Hetzner find result: %w", err)
	}

	if doc.Prefix.String() == "" {
		return rateResult, errors.New("no prefix found in Hetzner data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.Hetzner.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"hosted in Hetzner"}
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

func unmarshalProviderData(data []byte) (*hetzner.Doc, error) {
	var res *hetzner.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling hetzner data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	hetznerClient := hetzner.New()
	hetznerClient.Client = c.HTTPClient

	if c.Providers.Hetzner.URL != "" {
		hetznerClient.DownloadURL = c.Providers.Hetzner.URL
		c.Logger.Debug("overriding hetzner source", "url", hetznerClient.DownloadURL)
	}

	doc, err := hetznerClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching hetzner data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling hetzner provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Hetzner.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Hetzner.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting hetzner data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising hetzner client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking hetzner cache: %w", err)
	}

	if ok {
		c.Logger.Info("hetzner provider data found in cache")

		return nil
	}

	c.Logger.Info("loading hetzner provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading hetzner api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*hetzner.Doc, error) {
	c.Logger.Info("loading hetzner provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *hetzner.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached hetzner provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading hetzner cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/hetzner/testdata/hetzner.txt")
	if err != nil {
		return nil, fmt.Errorf("error getting hetzner special crawlers test data file path: %w", err)
	}

	tdf, err := loadResultsFile(resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("hetzner match returned from test data", "host", "34.3.8.8")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the hetzner data
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
		return nil, fmt.Errorf("loading hetzner host data from cache: %w", err)
	}

	// search in the data for the host
	switch {
	case c.Host.Is4():
		for _, record := range doc.IPv4Prefixes {
			if record.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix: record,
				}

				c.Logger.Debug("returning hetzner host match data")

				break
			}
		}
	case c.Host.Is6():
		for _, record := range doc.IPv6Prefixes {
			if record.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix: record,
				}

				c.Logger.Debug("returning hetzner host match data")

				break
			}
		}
	default:
		return nil, fmt.Errorf("invalid host: %s", c.Host.String())
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

	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), providers.DashIfEmpty(result.Prefix.String())})

	if !result.CreationTime.IsZero() {
		tw.AppendRow(table.Row{"Creation Time", providers.DashIfEmpty(result.CreationTime.UTC().Format(providers.TimeFormat))})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("HETZNER | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("HETZNER | Host: %s", "34.3.8.8")
	}

	return &tw, nil
}

func loadResultsFile(path string) (*HostSearchResult, error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	defer jf.Close()

	var res HostSearchResult

	decoder := json.NewDecoder(jf)

	if err = decoder.Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding file: %w", err)
	}

	return &res, nil
}

type HostSearchResult struct {
	Raw          json.RawMessage `json:"raw,omitempty"`
	Prefix       netip.Prefix    `json:"prefix"`
	CreationTime time.Time       `json:"creation_time"`
}
