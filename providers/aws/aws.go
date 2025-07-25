package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/aws"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "aws"
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
	c.Logger.Debug("creating aws client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.AWS.Enabled != nil && *c.Providers.AWS.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.AWS.OutputPriority
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

	if doc.IPPrefix.IsValid() || doc.IPv6Prefix.IPv6Prefix.IsValid() {
		indicators["HostedInAWS"] = "true"
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

	if doc.IPPrefix.String() == "" {
		return rateResult, errors.New("no prefix found in aws data")
	}

	if doc.IPPrefix.IsValid() || doc.IPv6Prefix.IPv6Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.AWS.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"hosted in AWS"}
	}

	return rateResult, nil
}

func unmarshalProviderData(rBody []byte) (*aws.Doc, error) {
	var res *aws.Doc

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling aws provider doc: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	awsClient := aws.New()
	awsClient.Client = c.HTTPClient

	if c.Providers.AWS.URL != "" {
		awsClient.DownloadURL = c.Providers.AWS.URL
		c.Logger.Debug("overriding aws source", "url", aws.DownloadURL)
	}

	doc, etag, err := awsClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching aws provider data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling aws provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.AWS.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.AWS.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    etag,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error caching aws provider data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising aws client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("error checking cache for aws provider data: %w", err)
	}

	if ok {
		c.Logger.Info("aws provider data found in cache")

		return nil
	}

	// load data from source and store in cache
	err = c.loadProviderData()
	if err != nil {
		return err
	}

	return nil
}

func loadTestData() ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/aws/testdata/aws_18_164_52_75_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting aws test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*aws.Doc, error) {
	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *aws.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached aws provider doc: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("error reading aws provider cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var out []byte

	var err error

	// load test results data
	if c.UseTestData {
		var loadErr error

		out, loadErr = loadTestData()
		if loadErr != nil {
			return nil, loadErr
		}

		c.Logger.Info("aws match returned from test data", "host", c.Host.String())

		return out, nil
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, err
	}

	match, err := MatchIPToDoc(c.Host, doc)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("aws match found", "host", c.Host.String())

	match.SyncToken = doc.SyncToken

	match.CreateDate, err = time.Parse("2006-01-02-15-04-05", doc.CreateDate)
	if err != nil {
		return nil, fmt.Errorf("error parsing create date: %w", err)
	}

	var raw []byte

	raw, err = json.Marshal(match)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	return raw, nil
}

func MatchIPToDoc(host netip.Addr, doc *aws.Doc) (*HostSearchResult, error) {
	var match *HostSearchResult

	if host.Is4() {
		return matchIPv4ToDoc(host, doc)
	}

	if host.Is6() {
		return matchIPv6ToDoc(host, doc)
	}

	return match, nil
}

func matchIPv6ToDoc(host netip.Addr, doc *aws.Doc) (*HostSearchResult, error) {
	var match *HostSearchResult

	for _, prefix := range doc.IPv6Prefixes {
		if prefix.IPv6Prefix.Contains(host) {
			match = &HostSearchResult{
				Prefix: aws.Prefix{
					IPPrefix: prefix.IPv6Prefix,
					Region:   prefix.Region,
					Service:  prefix.Service,
				},
			}

			return match, nil
		}
	}

	return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
}

func matchIPv4ToDoc(host netip.Addr, doc *aws.Doc) (*HostSearchResult, error) {
	var match *HostSearchResult

	for _, prefix := range doc.Prefixes {
		if prefix.IPPrefix.Contains(host) {
			match = &HostSearchResult{
				Prefix: aws.Prefix{
					IPPrefix: prefix.IPPrefix,
					Region:   prefix.Region,
					Service:  prefix.Service,
				},
			}

			return match, nil
		}
	}

	return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	var result HostSearchResult

	if err := json.Unmarshal(data, &result); err != nil {
		switch {
		case errors.Is(err, providers.ErrNoDataFound):
			return nil, fmt.Errorf("data not loaded: %w", err)
		case errors.Is(err, providers.ErrFailedToFetchData):
			return nil, fmt.Errorf("error fetching aws data: %w", err)
		case errors.Is(err, providers.ErrNoMatchFound):
			// reset the error as no longer useful for table creation
			return nil, nil
		default:
			return nil, fmt.Errorf("error loading aws api response: %w", err)
		}
	}

	tw := table.NewWriter()

	var rows []table.Row

	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), providers.DashIfEmpty(result.IPPrefix.String())})
	tw.AppendRow(table.Row{"Service", providers.DashIfEmpty(result.Prefix.Service)})
	tw.AppendRow(table.Row{"Region", providers.DashIfEmpty(result.Prefix.Region)})

	if !result.CreateDate.IsZero() {
		tw.AppendRow(table.Row{"Source Update", providers.DashIfEmpty(result.CreateDate.String())})
	}

	if result.SyncToken != "" {
		tw.AppendRow(table.Row{"Sync Token", providers.DashIfEmpty(result.SyncToken)})
	}

	if result.ETag != "" {
		tw.AppendRow(table.Row{"Version", providers.DashIfEmpty(result.ETag)})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("AWS | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("AWS | Host: 18.164.100.99")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw            []byte
	aws.Prefix     `json:"prefix"`
	aws.IPv6Prefix `json:"ipv6Prefix"`
	ETag           string    `json:"etag"`
	SyncToken      string    `json:"syncToken"`
	CreateDate     time.Time `json:"createDate"`
}
