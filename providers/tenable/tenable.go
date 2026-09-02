package tenable

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/tenable"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "tenable"
	// Tenable publishes its cloud scanner ranges as a dated document carrying a
	// syncToken and createDate. A day, matching the other range-list providers.
	DocTTL = 24 * time.Hour
	// testDataHost is the host represented by the checked-in test data report.
	testDataHost = "192.0.2.1"
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating tenable client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.Tenable.Enabled != nil && *c.Providers.Tenable.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Tenable.OutputPriority
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
		indicators["TenableScanner"] = "true"
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
		return rateResult, errors.New("no prefix found in tenable data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.Tenable.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"source is a Tenable cloud scanner"}
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
		return nil, fmt.Errorf("error unmarshalling tenable data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	doc, err := client.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching tenable data: %w", err)
	}

	// ip-fetcher ignores the HTTP status, so an upstream error body can decode
	// to an empty document; refuse to cache it so lookups aren't blanked for the TTL.
	if len(doc.Prefixes) == 0 && len(doc.IPv6Prefixes) == 0 &&
		len(doc.FedRAMPPrefixes) == 0 && len(doc.FedRAMPIPv6Prefixes) == 0 {
		return fmt.Errorf("tenable data contains no prefixes: %w", providers.ErrFailedToFetchData)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling tenable provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Tenable.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Tenable.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting tenable data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising tenable client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking tenable cache: %w", err)
	}

	if ok {
		c.Logger.Debug("tenable provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading tenable provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading tenable api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ipfetcher.Doc, error) {
	c.Logger.Debug("loading tenable provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *ipfetcher.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached tenable provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading tenable cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/tenable/testdata/tenable_192_0_2_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting tenable test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("tenable match returned from test data", "host", testDataHost)

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the tenable data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	if c.UseTestData {
		return loadTestData(c)
	}

	// the list carries a single set of prefixes, so only the validity of the
	// host needs checking before searching
	if !c.Host.Is4() && !c.Host.Is6() {
		return nil, fmt.Errorf(constants.MsgInvalidHostFmt, c.Host.String())
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading tenable host data from cache: %w", err)
	}

	// The document carries four lists: the commercial ranges and Tenable's
	// separately published FedRAMP ranges, each split by address family. A
	// FedRAMP match is flagged so the table can say which pool it came from.
	for _, set := range []struct {
		prefixes []ipfetcher.Prefix
		fedramp  bool
	}{
		{doc.Prefixes, false},
		{doc.IPv6Prefixes, false},
		{doc.FedRAMPPrefixes, true},
		{doc.FedRAMPIPv6Prefixes, true},
	} {
		for _, p := range set.prefixes {
			if p.IPPrefix.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix:      p.IPPrefix,
					Region:      p.Region,
					Service:     p.Service,
					SensorGroup: p.SensorGroup,
					FedRAMP:     set.fedramp,
					SyncToken:   doc.SyncToken,
					CreateDate:  doc.CreateDate,
				}

				c.Logger.Debug("returning tenable host match data")

				break
			}
		}

		if result != nil {
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

	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), providers.DashIfEmpty(result.Prefix.String())})

	if result.Region != "" {
		tw.AppendRow(table.Row{providers.PadRight("Region", providers.Column1MinWidth), providers.DashIfEmpty(result.Region)})
	}

	if result.Service != "" {
		tw.AppendRow(table.Row{providers.PadRight("Service", providers.Column1MinWidth), providers.DashIfEmpty(result.Service)})
	}

	if result.SensorGroup != "" {
		tw.AppendRow(table.Row{providers.PadRight("Sensor Group", providers.Column1MinWidth), providers.DashIfEmpty(result.SensorGroup)})
	}

	if result.FedRAMP {
		tw.AppendRow(table.Row{providers.PadRight("FedRAMP", providers.Column1MinWidth), "true"})
	}

	if result.CreateDate != "" {
		tw.AppendRow(table.Row{providers.PadRight("Created", providers.Column1MinWidth), providers.DashIfEmpty(result.CreateDate)})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("Tenable | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("Tenable | Host: %s", testDataHost)
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw []byte `json:"Raw"`
	// Prefix is the matched range as published.
	Prefix netip.Prefix `json:"prefix"`
	// Region, Service and SensorGroup name the scanner pool the range belongs
	// to; Tenable publishes them alongside every prefix.
	Region      string `json:"region,omitempty"`
	Service     string `json:"service,omitempty"`
	SensorGroup string `json:"sensor_group,omitempty"`
	// FedRAMP marks a match in Tenable's separately published FedRAMP ranges.
	FedRAMP bool `json:"fedramp,omitempty"`
	// SyncToken and CreateDate identify the document the match came from.
	SyncToken  string `json:"sync_token,omitempty"`
	CreateDate string `json:"create_date,omitempty"`
}
