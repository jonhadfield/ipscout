package dshield

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/dshield"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "dshield"
	DocTTL       = 24 * time.Hour
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating dshield client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.DShield.Enabled != nil && *c.Providers.DShield.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.DShield.OutputPriority
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
		indicators["DShieldBlockListed"] = "true"
		indicators["DShieldAttacks"] = strconv.Itoa(doc.Attacks)
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
		return rateResult, errors.New("no prefix found in dshield data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.DShield.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{fmt.Sprintf("listed on the DShield block list with %d attacks", doc.Attacks)}
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
		return nil, fmt.Errorf("error unmarshalling dshield data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	doc, err := client.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching dshield data: %w", err)
	}

	// an upstream error response can yield an empty document with a nil error;
	// caching it would blank all lookups until the TTL expires
	if len(doc.Records) == 0 {
		return fmt.Errorf("dshield document contains no records: %w", providers.ErrFailedToFetchData)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling dshield provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.DShield.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.DShield.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.Updated.String(),
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting dshield data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising dshield client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking dshield cache: %w", err)
	}

	if ok {
		c.Logger.Debug("dshield provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading dshield provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading dshield api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ipfetcher.Doc, error) {
	c.Logger.Debug("loading dshield provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *ipfetcher.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached dshield provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading dshield cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/dshield/testdata/dshield_198_51_100_42_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting dshield test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("dshield match returned from test data", "host", "198.51.100.42")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the dshield data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	// return cached report if test data is enabled
	if c.UseTestData {
		return loadTestData(c)
	}

	// the block list carries both address families in a single record set,
	// so only the validity of the host needs checking before searching
	if !c.Host.Is4() && !c.Host.Is6() {
		return nil, fmt.Errorf(constants.MsgInvalidHostFmt, c.Host.String())
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading dshield host data from cache: %w", err)
	}

	// search in the data for the host
	for _, record := range doc.Records {
		if record.Prefix.Contains(c.Host) {
			result = &HostSearchResult{
				Prefix:  record.Prefix,
				Attacks: record.Attacks,
				Name:    record.Name,
				Country: record.Country,
				Email:   record.Email,
				Updated: doc.Updated,
			}

			c.Logger.Debug("returning dshield host match data")

			break
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

	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), providers.DashIfEmpty(result.Prefix.String())})
	tw.AppendRow(table.Row{"Attacks", providers.DashIfEmpty(result.Attacks)})

	if result.Name != "" {
		tw.AppendRow(table.Row{"Network Name", providers.DashIfEmpty(result.Name)})
	}

	if result.Country != "" {
		tw.AppendRow(table.Row{"Country", providers.DashIfEmpty(result.Country)})
	}

	if result.Email != "" {
		tw.AppendRow(table.Row{"Abuse Contact", providers.DashIfEmpty(result.Email)})
	}

	if !result.Updated.IsZero() {
		tw.AppendRow(table.Row{"Updated", providers.DashIfEmpty(result.Updated.String())})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("DShield | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("DShield | Host: %s", "198.51.100.42")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw     []byte       `json:"Raw"`
	Prefix  netip.Prefix `json:"prefix"`
	Attacks int          `json:"attacks"`
	Name    string       `json:"name,omitempty"`
	Country string       `json:"country,omitempty"`
	Email   string       `json:"email,omitempty"`
	Updated time.Time    `json:"updated"`
}
