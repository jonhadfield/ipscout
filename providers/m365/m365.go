package m365

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/m365"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "m365"
	// Microsoft versions this endpoint and changes it on a published cadence
	// rather than continuously. A day, as for the other saas providers.
	DocTTL = 24 * time.Hour
	// testDataHost is the host represented by the checked-in test data report.
	testDataHost = "192.0.2.1"
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating m365 client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.M365.Enabled != nil && *c.Providers.M365.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.M365.OutputPriority
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
		indicators["Microsoft365"] = "true"
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
		return rateResult, errors.New("no prefix found in m365 data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.M365.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"source is Microsoft 365 infrastructure"}
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
		return nil, fmt.Errorf("error unmarshalling m365 data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	doc, err := client.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching m365 data: %w", err)
	}

	// ip-fetcher ignores the HTTP status, so an upstream error body can decode
	// to an empty document; refuse to cache it so lookups aren't blanked for the TTL.
	if len(doc.Endpoints) == 0 {
		return fmt.Errorf("m365 data contains no endpoints: %w", providers.ErrFailedToFetchData)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling m365 provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.M365.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.M365.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting m365 data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising m365 client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking m365 cache: %w", err)
	}

	if ok {
		c.Logger.Debug("m365 provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading m365 provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading m365 api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ipfetcher.Doc, error) {
	c.Logger.Debug("loading m365 provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *ipfetcher.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached m365 provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading m365 cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/m365/testdata/m365_192_0_2_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting m365 test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("m365 match returned from test data", "host", testDataHost)

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the m365 data
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
		return nil, fmt.Errorf("loading m365 host data from cache: %w", err)
	}

	// prefixes are grouped by endpoint set, so the service area and category are
	// recorded alongside the match
	for _, ep := range doc.Endpoints {
		for _, p := range append(append([]netip.Prefix{}, ep.IPv4Prefixes...), ep.IPv6Prefixes...) {
			if p.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix:      p,
					ServiceArea: ep.ServiceAreaDisplayName,
					Category:    ep.Category,
				}

				c.Logger.Debug("returning m365 host match data")

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

	if result.ServiceArea != "" {
		tw.AppendRow(table.Row{providers.PadRight("Service Area", providers.Column1MinWidth), providers.DashIfEmpty(result.ServiceArea)})
	}

	if result.Category != "" {
		tw.AppendRow(table.Row{providers.PadRight("Category", providers.Column1MinWidth), providers.DashIfEmpty(result.Category)})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("Microsoft 365 | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("Microsoft 365 | Host: %s", testDataHost)
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw    []byte       `json:"Raw"`
	Prefix netip.Prefix `json:"prefix"`
	// ServiceArea names which part of Microsoft 365 the range serves - Exchange,
	// SharePoint, Skype or the common set - and Category how Microsoft expects it
	// to be treated: Optimize, Allow or Default.
	ServiceArea string `json:"service_area,omitempty"`
	Category    string `json:"category,omitempty"`
}
