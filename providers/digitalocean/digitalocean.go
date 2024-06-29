package digitalocean

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/digitalocean"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "digitalocean"
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
	c.Logger.Debug("creating digitalocean client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Session.Providers.DigitalOcean.Enabled != nil && *c.Session.Providers.DigitalOcean.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Session.Providers.DigitalOcean.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) RateHostData(findRes []byte, bytes []byte) (providers.RateResult, error) {
	return providers.RateResult{}, nil
}

func unmarshalResponse(rBody []byte) (*HostSearchResult, error) {
	var res *HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	res.Raw = rBody

	return res, nil
}

func unmarshalProviderData(data []byte) (*digitalocean.Doc, error) {
	var res *digitalocean.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling digitalocean data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	digitaloceanClient := digitalocean.New()
	digitaloceanClient.Client = c.HTTPClient

	if c.Providers.DigitalOcean.URL != "" {
		digitaloceanClient.DownloadURL = c.Providers.DigitalOcean.URL
		c.Logger.Debug("overriding digitalocean source", "url", digitaloceanClient.DownloadURL)
	}

	doc, err := digitaloceanClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching digitalocean data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling digitalocean provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.DigitalOcean.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.DigitalOcean.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.ETag,
		Created:    time.Now(),
	}, docCacheTTL,
	)
	if err != nil {
		return fmt.Errorf("error upserting digitalocean data: %w", err)
	}

	return nil
}

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

	c.Logger.Debug("initialising digitalocean client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking digitalocean cache: %w", err)
	}

	if ok {
		c.Logger.Info("digitalocean provider data found in cache")

		return nil
	}

	c.Logger.Info("loading digitalocean provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading digitalocean api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*digitalocean.Doc, error) {
	c.Logger.Info("loading digitalocean provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *digitalocean.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached digitalocean provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading digitalocean cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	tdf, err := loadResultsFile("providers/digitalocean/testdata/digitalocean_165_232_46_239_report.json")
	if err != nil {
		return nil, err
	}

	c.Logger.Info("digitalocean match returned from test data", "host", "9.9.9.9")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// FindHost searches for the host in the digitalocean data
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
		return nil, fmt.Errorf("loading digitalocean host data from cache: %w", err)
	}

	// search in the data for the host
	for _, record := range doc.Records {
		if record.Network.Contains(c.Host) {
			result = &HostSearchResult{
				Record:       record,
				ETag:         doc.ETag,
				LastModified: doc.LastModified,
			}

			c.Logger.Debug("returning digitalocean host match data")

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

	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), dashIfEmpty(result.Record.NetworkText)})
	tw.AppendRow(table.Row{"Country Code", dashIfEmpty(result.Record.CountryCode)})
	tw.AppendRow(table.Row{"City Name", dashIfEmpty(result.Record.CityName)})
	tw.AppendRow(table.Row{"City Code", dashIfEmpty(result.Record.CityCode)})
	tw.AppendRow(table.Row{"Zip Code", dashIfEmpty(result.Record.ZipCode)})

	if !result.LastModified.IsZero() {
		tw.AppendRow(table.Row{"Source Update", dashIfEmpty(result.LastModified.String())})
	}

	if result.ETag != "" {
		tw.AppendRow(table.Row{"Version", dashIfEmpty(result.ETag)})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("DIGITAL OCEAN | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("DIGITAL OCEAN | Host: %s", "165.232.46.239")
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
	Record       digitalocean.Record `json:"prefix"`
	ETag         string              `json:"etag"`
	LastModified time.Time           `json:"last_modified"`
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
