package linode

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/linode"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "linode"
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
	c.Logger.Debug("creating linode client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.Session.Providers.Linode.Enabled != nil && *c.Session.Providers.Linode.Enabled {
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

func unmarshalProviderData(data []byte) (*linode.Doc, error) {
	var res *linode.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling linode data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	linodeClient := linode.New()
	linodeClient.Client = c.HTTPClient

	if c.Providers.Linode.URL != "" {
		linodeClient.DownloadURL = c.Providers.Linode.URL
		c.Logger.Debug("overriding linode source", "url", linodeClient.DownloadURL)
	}

	doc, err := linodeClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching linode data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling linode provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Linode.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Linode.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.ETag,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting linode data: %w", err)
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

	c.Logger.Debug("initialising linode client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking linode cache: %w", err)
	}

	if ok {
		c.Logger.Info("linode provider data found in cache")

		return nil
	}

	c.Logger.Info("loading linode provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading linode api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*linode.Doc, error) {
	c.Logger.Info("loading linode provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *linode.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached linode provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading linode cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	tdf, err := loadResultsFile("providers/linode/testdata/linode_69_164_198_1_report.json")
	if err != nil {
		return nil, err
	}

	c.Logger.Info("linode match returned from test data", "host", "69.164.198.1")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the linode data
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
		return nil, fmt.Errorf("loading linode host data from cache: %w", err)
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

			c.Logger.Debug("returning linode host match data")

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

	if !result.CreationTime.IsZero() {
		tw.AppendRow(table.Row{"Creation Time", dashIfEmpty(result.CreationTime.String())})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("LINODE | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("LINODE | Host: %s", "69.164.198.1")
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
