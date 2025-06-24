package icloudpr

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jonhadfield/ipscout/helpers"
	"net/netip"
	"os"
	"time"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/icloudpr"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "icloudpr"
	DocTTL       = 24 * time.Hour
)

var ErrInvalidIPVersion = errors.New("invalid ip version")

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
	c.Logger.Debug("creating icloudpr client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.ICloudPR.Enabled != nil && *c.Providers.ICloudPR.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.ICloudPR.OutputPriority
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
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf("error unmarshalling iCloud Private Relay find result: %w", err)
	}

	if doc.Prefix.String() == "" {
		return rateResult, errors.New("no prefix found in iCloud Private Relay data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.ICloudPR.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"source is iCloud Private Relay"}
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

func unmarshalProviderData(data []byte) (*icloudpr.Doc, error) {
	var res *icloudpr.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling icloudpr data: %w", err)
	}

	return res, nil
}

func splitRecords(records []icloudpr.Record) ([]icloudpr.Record, []icloudpr.Record) {
	var fours []icloudpr.Record

	var sixes []icloudpr.Record

	for _, record := range records {
		if record.Prefix.Addr().Is4() {
			fours = append(fours, record)
		} else {
			sixes = append(sixes, record)
		}
	}

	return fours, sixes
}

func createSkeletonDocs(doc *icloudpr.Doc) (icloudpr.Doc, icloudpr.Doc) {
	var fourDoc icloudpr.Doc

	var sixDoc icloudpr.Doc

	fourDoc.ETag = doc.ETag
	fourDoc.LastModified = doc.LastModified

	sixDoc.ETag = doc.ETag
	sixDoc.LastModified = doc.LastModified

	return fourDoc, sixDoc
}

func (c *ProviderClient) loadProviderData() error {
	icloudprClient := icloudpr.New()
	icloudprClient.Client = c.HTTPClient

	if c.Providers.ICloudPR.URL != "" {
		icloudprClient.DownloadURL = c.Providers.ICloudPR.URL
		c.Logger.Debug("overriding icloudpr source", "url", icloudprClient.DownloadURL)
	}

	doc, err := icloudprClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching icloudpr data: %w", err)
	}

	// split into ipv4 and ipv6
	fourDoc, sixDoc := createSkeletonDocs(&doc)
	fourDoc.Records, sixDoc.Records = splitRecords(doc.Records)

	fourData, err := json.Marshal(fourDoc)
	if err != nil {
		return fmt.Errorf("error marshalling icloudpr provider ipv4 doc: %w", err)
	}

	sixData, err := json.Marshal(sixDoc)
	if err != nil {
		return fmt.Errorf("error marshalling icloudpr provider ipv6 doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.ICloudPR.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.ICloudPR.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName + "_4",
		Value:      fourData,
		Version:    doc.ETag,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting icloudpr data: %w", err)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName + "_6",
		Value:      sixData,
		Version:    doc.ETag,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting icloudpr data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising icloudpr client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName+"_4")
	if err != nil {
		return fmt.Errorf("checking icloudpr ipv4 cache: %w", err)
	}

	if ok {
		c.Logger.Info("icloudpr provider ipv4 data found in cache")

		return nil
	}

	// load provider data into cache if not already present and fresh
	ok, err = cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName+"_6")
	if err != nil {
		return fmt.Errorf("checking icloudpr ipv6 cache: %w", err)
	}

	if ok {
		c.Logger.Info("icloudpr provider ipv6 data found in cache")

		return nil
	}

	c.Logger.Info("loading icloudpr provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading icloudpr api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache(is4, is6 bool) (*icloudpr.Doc, error) {
	c.Logger.Info("loading icloudpr provider data from cache")

	var cacheKey string

	switch {
	case is4:
		cacheKey = providers.CacheProviderPrefix + ProviderName + "_4"
	case is6:
		cacheKey = providers.CacheProviderPrefix + ProviderName + "_6"
	default:
		return nil, ErrInvalidIPVersion
	}

	var doc *icloudpr.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached icloudpr provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading icloudpr cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	tdf, err := loadResultsFile("providers/icloudpr/testdata/icloudpr_172_224_224_60_report.json")
	if err != nil {
		return nil, err
	}

	c.Logger.Info("icloudpr match returned from test data", "host", "172.224.224.60")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the icloudpr data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var result *HostSearchResult

	var err error

	// return cached report if test data is enabled
	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache(c.Host.Is4(), c.Host.Is6())
	if err != nil {
		return nil, fmt.Errorf("loading icloudpr host data from cache: %w", err)
	}

	// search in the data for the host
	for _, record := range doc.Records {
		if record.Prefix.Contains(c.Host) {
			result = &HostSearchResult{
				Prefix:       record.Prefix,
				Alpha2Code:   record.Alpha2Code,
				Region:       record.Region,
				City:         record.City,
				PostalCode:   record.PostalCode,
				SyncToken:    doc.ETag,
				CreationTime: time.Time{},
			}

			c.Logger.Debug("returning icloudpr host match data")

			break
		}
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
	tw.AppendRow(table.Row{"Alpha2Code", providers.DashIfEmpty(result.Alpha2Code)})
	tw.AppendRow(table.Row{"Region", providers.DashIfEmpty(result.Region)})
	tw.AppendRow(table.Row{"City", providers.DashIfEmpty(result.City)})
	// tw.AppendRow(table.Row{"Postal Code", providers.DashIfEmpty(result.PostalCode)})

	if !result.CreationTime.IsZero() {
		tw.AppendRow(table.Row{"Creation Time", providers.DashIfEmpty(result.CreationTime.String())})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("ICLOUD PRIVATE RELAY | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("ICLOUD PRIVATE RELAY | Host: %s", "172.224.224.60")
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
	Prefix       netip.Prefix `json:"ip_prefix"`
	Alpha2Code   string       `json:"alpha2code"`
	Region       string       `json:"region"`
	City         string       `json:"city"`
	PostalCode   string       `json:"postal_code"`
	SyncToken    string       `json:"synctoken"`
	CreationTime time.Time    `json:"creation_time"`
}
