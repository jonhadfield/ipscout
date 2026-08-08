package akamai

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/akamai"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "akamai"
	DocTTL       = 24 * time.Hour
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating akamai client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.Akamai.Enabled != nil && *c.Providers.Akamai.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Akamai.OutputPriority
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
		indicators["HostedInAkamai"] = "true"
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
		return rateResult, errors.New("no prefix found in akamai data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.Akamai.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"hosted in Akamai"}
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

func unmarshalProviderData(data []byte) (*ProviderDoc, error) {
	var res *ProviderDoc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling akamai data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	prefixes, err := client.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching akamai data: %w", err)
	}

	// an upstream error response can yield an empty prefix list with a nil error;
	// caching it would blank all lookups until the TTL expires
	if len(prefixes) == 0 {
		return fmt.Errorf("akamai document contains no prefixes: %w", providers.ErrFailedToFetchData)
	}

	var doc ProviderDoc

	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			doc.IPv4Prefixes = append(doc.IPv4Prefixes, prefix)

			continue
		}

		doc.IPv6Prefixes = append(doc.IPv6Prefixes, prefix)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling akamai provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Akamai.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Akamai.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting akamai data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising akamai client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking akamai cache: %w", err)
	}

	if ok {
		c.Logger.Debug("akamai provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading akamai provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading akamai api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ProviderDoc, error) {
	c.Logger.Debug("loading akamai provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *ProviderDoc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached akamai provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading akamai cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/akamai/testdata/akamai_192_0_2_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting akamai test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("akamai match returned from test data", "host", "192.0.2.1")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the akamai data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading akamai host data from cache: %w", err)
	}

	for _, p := range doc.IPv4Prefixes {
		if p.Contains(c.Host) {
			result = &HostSearchResult{Prefix: p}

			c.Logger.Debug("returning akamai host match data")

			break
		}
	}

	if result == nil {
		for _, p := range doc.IPv6Prefixes {
			if p.Contains(c.Host) {
				result = &HostSearchResult{Prefix: p}

				c.Logger.Debug("returning akamai host match data")

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
	tw.SetTitle("Akamai | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("Akamai | Host: %s", "192.0.2.1")
	}

	return &tw, nil
}

// ProviderDoc is the cached representation of the akamai prefix list,
// split into IPv4 and IPv6 prefixes for host matching.
type ProviderDoc struct {
	IPv4Prefixes []netip.Prefix `json:"ipv4_prefixes"`
	IPv6Prefixes []netip.Prefix `json:"ipv6_prefixes"`
}

type HostSearchResult struct {
	Raw    []byte       `json:"Raw"`
	Prefix netip.Prefix `json:"prefix"`
}
