package bingbot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/bingbot"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "bingbot"
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
	c.Logger.Debug("creating bingbot client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.Bingbot.Enabled != nil && *c.Providers.Bingbot.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Bingbot.OutputPriority
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
		indicators["ReputableBot"] = "true"
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
		return providers.RateResult{}, fmt.Errorf("error unmarshalling Bingbot find result: %w", err)
	}

	if doc.Prefix.String() == "" {
		return rateResult, errors.New("no prefix found in bingbot data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.Bingbot.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"hosted in Bingbot"}
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

func unmarshalProviderData(data []byte) (*bingbot.Doc, error) {
	var res *bingbot.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling bingbot data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	bingbotClient := bingbot.New()
	bingbotClient.Client = c.HTTPClient

	if c.Providers.Bingbot.URL != "" {
		bingbotClient.DownloadURL = c.Providers.Bingbot.URL
		c.Logger.Debug("overriding bingbot source", "url", bingbotClient.DownloadURL)
	}

	doc, err := bingbotClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching bingbot data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling bingbot provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Bingbot.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Bingbot.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.CreationTime.String(),
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting bingbot data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	c.Logger.Debug("initialising bingbot client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking bingbot cache: %w", err)
	}

	if ok {
		c.Logger.Info("bingbot provider data found in cache")

		return nil
	}

	c.Logger.Info("loading bingbot provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading bingbot api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*bingbot.Doc, error) {
	c.Logger.Info("loading bingbot provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *bingbot.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached bingbot provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading bingbot cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	tdf, err := loadResultsFile("providers/bingbot/testdata/bingbot_157_55_39_0_report.json")
	if err != nil {
		return nil, err
	}

	c.Logger.Info("bingbot match returned from test data", "host", "66.249.77.135")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the bingbot data
func (c *ProviderClient) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	var result *HostSearchResult

	var err error

	// return cached report if test data is enabled
	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading bingbot host data from cache: %w", err)
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

				c.Logger.Debug("returning bingbot host match data")

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

				c.Logger.Debug("returning bingbot host match data")

				break
			}
		}
	default:
		return nil, fmt.Errorf(constants.MsgInvalidHostFmt, c.Host.String())
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
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	result, err := unmarshalResponse(data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	tw := table.NewWriter()

	var rows []table.Row

	tw.AppendRow(table.Row{"Prefix", providers.DashIfEmpty(result.Prefix.String())})

	if !result.CreationTime.IsZero() {
		tw.AppendRow(table.Row{"Creation Time", providers.DashIfEmpty(result.CreationTime.String())})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("BINGBOT | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("BINGBOT | Host: %s", "157.55.39.0")
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
	Raw          []byte
	Prefix       netip.Prefix `json:"prefix"`
	CreationTime time.Time    `json:"creation_time"`
}
