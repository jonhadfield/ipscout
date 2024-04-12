package digitalocean

import (
	"encoding/json"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/crosscheck-ip/cache"
	"github.com/jonhadfield/crosscheck-ip/config"
	"github.com/jonhadfield/crosscheck-ip/providers"
	"github.com/jonhadfield/ip-fetcher/providers/digitalocean"
	"net/netip"
	"os"
	"strings"
	"time"
)

const (
	ProviderName = "digitalocean"
	DocTTL       = time.Duration(24 * time.Hour)
)

type Config struct {
	_ struct{}
	config.Config
	Host   netip.Addr
	APIKey string
}

func unmarshalResponse(rBody []byte) (*HostSearchResult, error) {
	var res *HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, err
	}

	res.Raw = rBody

	return res, nil
}

func unmarshalProviderData(data []byte) (*digitalocean.Doc, error) {
	var res *digitalocean.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ProviderClient struct {
	config.Config
}

func NewProviderClient(c config.Config) (*ProviderClient, error) {
	c.Logger.Debug("creating digitalocean client")

	tc := &ProviderClient{
		Config: c,
	}

	return tc, nil
}

func (c *ProviderClient) GetConfig() *config.Config {
	return &c.Config
}

func (c *ProviderClient) loadProviderData() error {
	digitaloceanClient := digitalocean.New()
	digitaloceanClient.Client = c.HttpClient

	doc, err := digitaloceanClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching digitalocean data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName,
		Value:   data,
		Version: doc.ETag,
		Created: time.Now(),
	}, DocTTL)
	if err != nil {
		return err
	}

	return nil
}

const (
	MaxColumnWidth = 120
)

func (c *ProviderClient) Initialise() error {
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
		return err
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

		// c.Logger.Info("digitalocean provider data found in cache")
	} else {
		return nil, fmt.Errorf("error reading digitalocean cache: %w", err)
	}

	return doc, nil
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
		result, err = loadResultsFile("providers/digitalocean/testdata/digitalocean_18_164_52_75_report.json")
		if err != nil {
			return nil, err
		}

		c.Logger.Info("digitalocean host match test data loaded")

		return result.Raw, nil
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
		return nil, fmt.Errorf("digitalocean: %w", providers.ErrNoMatchFound)
	}

	var raw []byte
	raw, err = json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	result.Raw = raw

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		c.Logger.Debug("backing up digitalocean host report")

		if err = os.WriteFile(fmt.Sprintf("%s/backups/digitalocean_%s_report.json", config.GetConfigRoot("", config.AppName),
			strings.ReplaceAll(c.Host.String(), ".", "_")), raw, 0644); err != nil {
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
	tw.AppendRow(table.Row{"Prefix", dashIfEmpty(result.Record.NetworkText)})
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
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("DigitalOcean IP | Host: %s", c.Host.String())
	if c.UseTestData {
		tw.SetTitle("DigitalOcean IP | Host: %s", result.Record.NetworkText)
	}

	return &tw, nil
}

func loadResultsFile(path string) (res *HostSearchResult, err error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
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
