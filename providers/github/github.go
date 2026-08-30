package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/github"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "github"
	DocTTL       = 24 * time.Hour
)

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating github client")

	return &ProviderClient{Session: c}, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.GitHub.Enabled != nil && *c.Providers.GitHub.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.GitHub.OutputPriority
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
		indicators["HostedInGitHub"] = "true"
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
		return rateResult, errors.New("no prefix found in github data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.GitHub.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"hosted in GitHub"}
	}

	return rateResult, nil
}

// Doc holds the GitHub meta prefixes keyed by the service lists they appear in.
type Doc struct {
	Services map[string][]netip.Prefix `json:"services"`
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
		return nil, fmt.Errorf("error unmarshalling github data: %w", err)
	}

	return res, nil
}

// processData parses the GitHub meta document, keeping the service list names
// (hooks, web, api, git, actions, pages, etc.) that each prefix belongs to.
func processData(data []byte) (*Doc, error) {
	var raw map[string]json.RawMessage

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("error unmarshalling github meta data: %w", err)
	}

	doc := &Doc{Services: make(map[string][]netip.Prefix)}

	for service, v := range raw {
		var entries []string
		if err := json.Unmarshal(v, &entries); err != nil {
			continue
		}

		var prefixes []netip.Prefix

		for _, entry := range entries {
			prefix, perr := netip.ParsePrefix(entry)
			if perr != nil {
				continue
			}

			prefixes = append(prefixes, prefix)
		}

		if len(prefixes) > 0 {
			doc.Services[service] = prefixes
		}
	}

	return doc, nil
}

func (c *ProviderClient) loadProviderData() error {
	client := ipfetcher.New()
	client.Client = c.HTTPClient

	rawData, _, _, err := client.FetchData()
	if err != nil {
		return fmt.Errorf("error fetching github data: %w", err)
	}

	doc, err := processData(rawData)
	if err != nil {
		return fmt.Errorf("error processing github data: %w", err)
	}

	// an upstream error response can yield an empty document with a nil error;
	// caching it would blank all lookups until the TTL expires
	if len(doc.Services) == 0 {
		return fmt.Errorf("github document contains no prefixes: %w", providers.ErrFailedToFetchData)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling github provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.GitHub.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.GitHub.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting github data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising github client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking github cache: %w", err)
	}

	if ok {
		c.Logger.Debug("github provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading github provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading github api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*Doc, error) {
	c.Logger.Debug("loading github provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached github provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading github cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/github/testdata/github_192_0_2_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting github test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("github match returned from test data", "host", "192.0.2.1")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the github data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading github host data from cache: %w", err)
	}

	var matchedPrefix netip.Prefix

	var matchedServices []string

	for service, prefixes := range doc.Services {
		for _, p := range prefixes {
			if p.Contains(c.Host) {
				if !matchedPrefix.IsValid() {
					matchedPrefix = p
				}

				matchedServices = append(matchedServices, service)

				break
			}
		}
	}

	if len(matchedServices) > 0 {
		sort.Strings(matchedServices)

		result = &HostSearchResult{Prefix: matchedPrefix, Services: matchedServices}

		c.Logger.Debug("returning github host match data")
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
	tw.AppendRow(table.Row{providers.PadRight("Services", providers.Column1MinWidth), providers.DashIfEmpty(strings.Join(result.Services, ", "))})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("GitHub | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("GitHub | Host: %s", "192.0.2.1")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw      []byte       `json:"Raw"`
	Prefix   netip.Prefix `json:"prefix"`
	Services []string     `json:"services"`
}
