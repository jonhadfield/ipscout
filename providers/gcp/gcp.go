package gcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/gcp"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "gcp"
	DocTTL       = time.Duration(24 * time.Hour)
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
	c.Logger.Debug("creating gcp client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.Session.Providers.GCP.Enabled != nil && *c.Session.Providers.GCP.Enabled {
		return true
	}

	return false
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

func unmarshalProviderData(data []byte) (*gcp.Doc, error) {
	var res *gcp.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling gcp data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	gcpClient := gcp.New()
	gcpClient.Client = c.HTTPClient

	if c.Providers.GCP.URL != "" {
		gcpClient.DownloadURL = c.Providers.GCP.URL
		c.Logger.Debug("overriding gcp source", "url", gcpClient.DownloadURL)
	}

	doc, err := gcpClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching gcp data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling gcp provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.GCP.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.GCP.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.SyncToken,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting gcp data: %w", err)
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

	c.Logger.Debug("initialising gcp client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking gcp cache: %w", err)
	}

	if ok {
		c.Logger.Info("gcp provider data found in cache")

		return nil
	}

	c.Logger.Info("loading gcp provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading gcp api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*gcp.Doc, error) {
	c.Logger.Info("loading gcp provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *gcp.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached gcp provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading gcp cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	tdf, err := loadResultsFile("providers/gcp/testdata/gcp_34_128_62_0_report.json")
	if err != nil {
		return nil, err
	}

	c.Logger.Info("gcp match returned from test data", "host", "9.9.9.9")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the gcp data
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
		return nil, fmt.Errorf("loading gcp host data from cache: %w", err)
	}

	// search in the data for the host
	switch {
	case c.Host.Is4():
		for _, record := range doc.IPv4Prefixes {
			if record.IPv4Prefix.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix:       record.IPv4Prefix,
					SyncToken:    doc.SyncToken,
					Scope:        record.Scope,
					Service:      record.Service,
					CreationTime: doc.CreationTime,
				}

				c.Logger.Debug("returning gcp host match data")

				break
			}
		}
	case c.Host.Is6():
		for _, record := range doc.IPv6Prefixes {
			if record.IPv6Prefix.Contains(c.Host) {
				result = &HostSearchResult{
					Prefix:       record.IPv6Prefix,
					SyncToken:    doc.SyncToken,
					Scope:        record.Scope,
					Service:      record.Service,
					CreationTime: doc.CreationTime,
				}

				c.Logger.Debug("returning gcp host match data")

				break
			}
		}
	default:
		return nil, fmt.Errorf("invalid host: %s", c.Host.String())
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
	tw.AppendRow(table.Row{"Scope", dashIfEmpty(result.Scope)})
	tw.AppendRow(table.Row{"Service", dashIfEmpty(result.Service)})

	if !result.CreationTime.IsZero() {
		tw.AppendRow(table.Row{"Creation Time", dashIfEmpty(result.CreationTime.String())})
	}

	if result.SyncToken != "" {
		tw.AppendRow(table.Row{"SyncToken", dashIfEmpty(result.SyncToken)})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("GCP | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("GCP | Host: %s", "34.128.62.2")
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
	Prefix       netip.Prefix `json:"prefix"`
	Service      string       `json:"service"`
	Scope        string       `json:"scope"`
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
