package spamhaus

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/spamhaus"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "spamhaus"
	DocTTL       = 24 * time.Hour
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating spamhaus client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.Spamhaus.Enabled != nil && *c.Providers.Spamhaus.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Spamhaus.OutputPriority
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
		indicators["SpamhausDROP"] = "true"
	}

	if doc.SBLID != "" {
		indicators["SBLID"] = doc.SBLID
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
		return rateResult, errors.New("no prefix found in spamhaus data")
	}

	if doc.Prefix.IsValid() {
		// a DROP listing means the prefix is not to be routed or peered with
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.Spamhaus.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Threat = "very high"

		reason := "listed on Spamhaus DROP (do not route or peer)"
		if doc.SBLID != "" {
			reason = fmt.Sprintf("%s: %s", reason, doc.SBLID)
		}

		rateResult.Reasons = []string{reason}
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
		return nil, fmt.Errorf("error unmarshalling spamhaus data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	doc, err := client.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching spamhaus data: %w", err)
	}

	// an upstream error response can yield an empty document with a nil error;
	// caching it would blank all lookups until the TTL expires
	if len(doc.IPv4Records) == 0 && len(doc.IPv6Records) == 0 {
		return fmt.Errorf("spamhaus document contains no records: %w", providers.ErrFailedToFetchData)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling spamhaus provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Spamhaus.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Spamhaus.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.Timestamp.String(),
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting spamhaus data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising spamhaus client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking spamhaus cache: %w", err)
	}

	if ok {
		c.Logger.Debug("spamhaus provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading spamhaus provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading spamhaus api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ipfetcher.Doc, error) {
	c.Logger.Debug("loading spamhaus provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *ipfetcher.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached spamhaus provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading spamhaus cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/spamhaus/testdata/spamhaus_192_0_2_5_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting spamhaus test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("spamhaus match returned from test data", "host", "192.0.2.5")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the spamhaus data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	// return cached report if test data is enabled
	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading spamhaus host data from cache: %w", err)
	}

	// search in the data for the host
	switch {
	case c.Host.Is4():
		for _, record := range doc.IPv4Records {
			if record.Prefix.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix:    record.Prefix,
					SBLID:     record.SBLID,
					RIR:       record.RIR,
					Timestamp: doc.Timestamp,
				}

				c.Logger.Debug("returning spamhaus host match data")

				break
			}
		}
	case c.Host.Is6():
		for _, record := range doc.IPv6Records {
			if record.Prefix.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix:    record.Prefix,
					SBLID:     record.SBLID,
					RIR:       record.RIR,
					Timestamp: doc.Timestamp,
				}

				c.Logger.Debug("returning spamhaus host match data")

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

	if result.SBLID != "" {
		tw.AppendRow(table.Row{"SBL ID", providers.DashIfEmpty(result.SBLID)})
	}

	if result.RIR != "" {
		tw.AppendRow(table.Row{"RIR", providers.DashIfEmpty(result.RIR)})
	}

	if !result.Timestamp.IsZero() {
		tw.AppendRow(table.Row{"Timestamp", providers.DashIfEmpty(result.Timestamp.String())})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("Spamhaus DROP | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("Spamhaus DROP | Host: %s", "192.0.2.5")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw       []byte       `json:"Raw"`
	Prefix    netip.Prefix `json:"prefix"`
	SBLID     string       `json:"sblid"`
	RIR       string       `json:"rir"`
	Timestamp time.Time    `json:"timestamp"`
}
