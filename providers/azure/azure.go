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
	DocTTL       = 24 * time.Hour
	dataColumnNo = 2
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
	if c.UseTestData || (c.Providers.Azure.Enabled != nil && *c.Providers.Azure.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Azure.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf("error unmarshalling find result: %w", err)
	}

	threatIndicators := providers.ThreatIndicators{
		Provider: ProviderName,
	}

	indicators := make(map[string]string)

	if doc.Prefix.IsValid() {
		indicators["HostedInAzure"] = "true"
	}

	threatIndicators.Indicators = indicators

	return &threatIndicators, nil
}

func (c *ProviderClient) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf("error unmarshalling rating config: %w", err)
	}

	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf("error unmarshalling azure find result: %w", err)
	}

	if doc.Prefix.String() == "" {
		return rateResult, fmt.Errorf("no prefix found in azure data")
	}

	if doc.Prefix.IsValid() {
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.Azure.DefaultMatchScore
		rateResult.Detected = true
		rateResult.Reasons = []string{"hosted in Azure"}
	}

	return rateResult, nil
}

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

	docCacheTTL := DocTTL
	if c.Providers.Azure.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Azure.DocumentCacheTTL)
	}

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    etag,
		Created:    time.Now(),
	}, docCacheTTL); err != nil {
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

	return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
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

	tw.AppendRow(table.Row{"Name", providers.DashIfEmpty(result.Name)})
	tw.AppendRow(table.Row{"ID", providers.DashIfEmpty(result.ID)})
	tw.AppendRow(table.Row{"Region", providers.DashIfEmpty(result.Properties.Region)})
	tw.AppendRow(table.Row{"Prefix", providers.DashIfEmpty(result.Prefix)})
	tw.AppendRow(table.Row{"Platform", providers.DashIfEmpty(result.Properties.Platform)})
	tw.AppendRow(table.Row{"Cloud", providers.DashIfEmpty(result.Cloud)})
	tw.AppendRow(table.Row{"System Service", providers.DashIfEmpty(result.Properties.SystemService)})
	tw.AppendRow(table.Row{"Net Features", providers.DashIfEmpty(strings.Join(result.Properties.NetworkFeatures, ","))})
	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: dataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
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
