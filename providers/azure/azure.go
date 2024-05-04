package azure

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/azure"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "azure"
	DocTTL       = time.Duration(24 * time.Hour)
)

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

func unmarshalProviderData(rBody []byte) (*azure.Doc, error) {
	var res *azure.Doc

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling azure provider doc: %w", err)
	}

	return res, nil
}

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating azure client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	return c.Session.Providers.Azure.Enabled
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

const (
	MaxColumnWidth = 120
)

func (c *ProviderClient) loadProviderDataFromSource() error {
	azureClient := azure.New()
	azureClient.Client = c.HTTPClient

	if c.Providers.Azure.URL != "" {
		azureClient.DownloadURL = c.Providers.Azure.URL
		c.Logger.Debug("overriding azure source", "url", azureClient.DownloadURL)
	}

	doc, etag, err := azureClient.Fetch()
	if err != nil {
		return fmt.Errorf("%s %w", err.Error(), providers.ErrFailedToFetchData)
	}

	c.Logger.Debug("fetched azure data from source", "size", len(doc.Values), "etag", etag)

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling azure provider doc: %w", err)
	}

	c.Logger.Debug("writing azure provider data to cache", "size", len(data), "etag", etag)

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    etag,
		Created:    time.Now(),
	}, DocTTL); err != nil {
		return fmt.Errorf("error writing azure provider data to cache: %w", err)
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

	c.Logger.Debug("initialising azure client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("error checking cache for azure provider data: %w", err)
	}

	if ok {
		c.Logger.Info("azure provider data found in cache")

		return nil
	}

	err = c.loadProviderDataFromSource()
	if err != nil {
		return err
	}

	return nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	tdf, err := loadResultsFile("providers/azure/testdata/azure_40_126_12_192_report.json")
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	c.Logger.Info("azure match returned from test data", "host", c.Host.String())

	return out, nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*azure.Doc, error) {
	c.Logger.Info("loading azure provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *azure.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached azure provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading azure provider data from cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	var out []byte

	var err error

	// load test results data
	if c.UseTestData {
		var loadErr error

		out, loadErr = loadTestData(c)
		if loadErr != nil {
			return nil, loadErr
		}

		c.Logger.Info("azure match returned from test data", "host", c.Host.String())

		return out, nil
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, err
	}

	match, err := matchIPToDoc(c.Host, doc)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("azure match found", "host", c.Host.String())

	var raw []byte

	raw, err = json.Marshal(match)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		if err = os.WriteFile(fmt.Sprintf("%s/backups/azure_%s_report.json", session.GetConfigRoot("", session.AppName),
			strings.ReplaceAll(c.Host.String(), ".", "_")), raw, 0o600); err != nil {
			panic(err)
		}

		c.Logger.Info("backed up azure response", "host", c.Host.String())
	}

	return raw, nil
}

func matchIPToDoc(host netip.Addr, doc *azure.Doc) (*HostSearchResult, error) {
	var match *HostSearchResult

	for _, value := range doc.Values {
		props := value.Properties

		for _, prefix := range props.AddressPrefixes {
			p, err := netip.ParsePrefix(prefix)
			if err != nil {
				return nil, fmt.Errorf("error parsing prefix: %w", err)
			}

			if p.Contains(host) {
				match = &HostSearchResult{
					Raw:          nil,
					Prefix:       p,
					ChangeNumber: props.ChangeNumber,
					Cloud:        doc.Cloud,
					Name:         value.Name,
					ID:           value.ID,
					Properties:   props,
				}

				return match, nil
			}
		}
	}

	return nil, fmt.Errorf("azure: %w", providers.ErrNoMatchFound)
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	var err error

	var result HostSearchResult

	if err = json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("error unmarshalling azure data: %w", err)
	}

	tw := table.NewWriter()

	var rows []table.Row

	tw.AppendRow(table.Row{"Name", dashIfEmpty(result.Name)})
	tw.AppendRow(table.Row{"ID", dashIfEmpty(result.ID)})
	tw.AppendRow(table.Row{"Region", dashIfEmpty(result.Properties.Region)})
	tw.AppendRow(table.Row{"Prefix", dashIfEmpty(result.Prefix)})
	tw.AppendRow(table.Row{"Platform", dashIfEmpty(result.Properties.Platform)})
	tw.AppendRow(table.Row{"Cloud", dashIfEmpty(result.Cloud)})
	tw.AppendRow(table.Row{"System Service", dashIfEmpty(result.Properties.SystemService)})
	tw.AppendRow(table.Row{"Network Features", dashIfEmpty(strings.Join(result.Properties.NetworkFeatures, ","))})
	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("AZURE | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("AZURE | Host: 40.126.12.192")
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
	Prefix       netip.Prefix
	ChangeNumber int              `json:"changeNumber"`
	Cloud        string           `json:"cloud"`
	Name         string           `json:"name"`
	ID           string           `json:"id"`
	Properties   azure.Properties `json:"properties"`
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
