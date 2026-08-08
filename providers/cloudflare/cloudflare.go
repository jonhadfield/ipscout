package cloudflare

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/cloudflare"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "cloudflare"
	DocTTL       = 24 * time.Hour
)

// Doc combines the IPv4 and IPv6 prefixes fetched from cloudflare into a single cacheable document
type Doc struct {
	IPv4Prefixes []netip.Prefix `json:"ipv4_prefixes"`
	IPv6Prefixes []netip.Prefix `json:"ipv6_prefixes"`
}

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating cloudflare client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.Cloudflare.Enabled != nil && *c.Providers.Cloudflare.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Cloudflare.OutputPriority
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
		indicators["HostedInCloudflare"] = "true"
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
		return rateResult, errors.New("no prefix found in cloudflare data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.Cloudflare.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"hosted in Cloudflare"}
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

func unmarshalProviderData(data []byte) (*Doc, error) {
	var res *Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling cloudflare data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	ipv4Data, _, _, err := client.FetchIPv4Data()
	if err != nil {
		return fmt.Errorf("error fetching cloudflare ipv4 data: %w", err)
	}

	ipv4Prefixes, err := ipfetcher.ProcessData(ipv4Data)
	if err != nil {
		return fmt.Errorf("error processing cloudflare ipv4 data: %w", err)
	}

	ipv6Data, _, _, err := client.FetchIPv6Data()
	if err != nil {
		return fmt.Errorf("error fetching cloudflare ipv6 data: %w", err)
	}

	ipv6Prefixes, err := ipfetcher.ProcessData(ipv6Data)
	if err != nil {
		return fmt.Errorf("error processing cloudflare ipv6 data: %w", err)
	}

	// an upstream error response (e.g. an error body served with a nil fetch
	// error) would otherwise be cached as an empty document for the full TTL,
	// blanking all lookups until expiry
	if len(ipv4Prefixes) == 0 && len(ipv6Prefixes) == 0 {
		return fmt.Errorf("cloudflare document contains no prefixes: %w", providers.ErrFailedToFetchData)
	}

	doc := Doc{
		IPv4Prefixes: ipv4Prefixes,
		IPv6Prefixes: ipv6Prefixes,
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling cloudflare provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Cloudflare.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Cloudflare.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting cloudflare data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising cloudflare client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking cloudflare cache: %w", err)
	}

	if ok {
		c.Logger.Debug("cloudflare provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading cloudflare provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading cloudflare api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*Doc, error) {
	c.Logger.Debug("loading cloudflare provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached cloudflare provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading cloudflare cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/cloudflare/testdata/cloudflare_192_0_2_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting cloudflare test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("cloudflare match returned from test data", "host", "192.0.2.1")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the cloudflare data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading cloudflare host data from cache: %w", err)
	}

	for _, p := range doc.IPv4Prefixes {
		if p.Contains(c.Host) {
			result = &HostSearchResult{Prefix: p}

			c.Logger.Debug("returning cloudflare host match data")

			break
		}
	}

	if result == nil {
		for _, p := range doc.IPv6Prefixes {
			if p.Contains(c.Host) {
				result = &HostSearchResult{Prefix: p}

				c.Logger.Debug("returning cloudflare host match data")

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
	tw.SetTitle("Cloudflare | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("Cloudflare | Host: %s", "192.0.2.1")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw    []byte       `json:"Raw"`
	Prefix netip.Prefix `json:"prefix"`
}
