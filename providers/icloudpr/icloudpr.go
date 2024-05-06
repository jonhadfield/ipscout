package icloudpr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

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
	return c.Session.Providers.ICloudPR.Enabled
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
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

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling icloudpr provider doc: %w", err)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.ETag,
		Created:    time.Now(),
	}, DocTTL)
	if err != nil {
		return fmt.Errorf("error upserting icloudpr data: %w", err)
	}

	return nil
}

const (
	MaxColumnWidth = 120
)

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return errors.New("cache not set")
	}

	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	c.Logger.Debug("initialising icloudpr client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking icloudpr cache: %w", err)
	}

	if ok {
		c.Logger.Info("icloudpr provider data found in cache")

		return nil
	}

	c.Logger.Info("loading icloudpr provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading icloudpr api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*icloudpr.Doc, error) {
	c.Logger.Info("loading icloudpr provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

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

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		c.Logger.Debug("backing up icloudpr host report")

		if err = os.WriteFile(fmt.Sprintf("%s/backups/icloudpr_%s_report.json", session.GetConfigRoot("", session.AppName),
			strings.ReplaceAll(c.Host.String(), ".", "_")), raw, 0o600); err != nil {
			panic(err)
		}
	}

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

	tw.AppendRow(table.Row{"Prefix", dashIfEmpty(result.Prefix.String())})
	tw.AppendRow(table.Row{"Alpha2Code", dashIfEmpty(result.Alpha2Code)})
	tw.AppendRow(table.Row{"Region", dashIfEmpty(result.Region)})
	tw.AppendRow(table.Row{"City", dashIfEmpty(result.City)})
	// tw.AppendRow(table.Row{"Postal Code", dashIfEmpty(result.PostalCode)})

	if !result.CreationTime.IsZero() {
		tw.AppendRow(table.Row{"Creation Time", dashIfEmpty(result.CreationTime.String())})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("ICLOUD PRIVATE RELAY | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("ICLOUD PRIVATE RELAY | Host: %s", "172.224.224.60")
	}

	return &tw, nil
}

func loadResultsFile(path string) (res *HostSearchResult, err error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, fmt.Errorf("error decoding file: %w", err)
	}

	return res, nil
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

func dashIfEmpty(value interface{}) string {
	switch v := value.(type) {
	case string:
		if len(v) == 0 {
			return "-"
		}

		return v
	case *string:
		if v == nil || len(*v) == 0 {
			return "-"
		}

		return *v
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return "-"
	}
}
