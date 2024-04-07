package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/crosscheck-ip/cache"
	"github.com/jonhadfield/crosscheck-ip/config"
	"github.com/jonhadfield/crosscheck-ip/providers"
	"github.com/jonhadfield/ip-fetcher/providers/aws"
	"net/netip"
	"os"
	"strings"
	"time"
)

const (
	ProviderName = "aws"
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

	return res, nil
}

func unmarshalProviderData(rBody []byte) (*aws.Doc, error) {
	var res *aws.Doc

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ProviderClient struct {
	config.Config
}

func NewProviderClient(c config.Config) (*ProviderClient, error) {
	c.Logger.Debug("creating aws client")

	tc := &ProviderClient{
		Config: c,
	}

	return tc, nil
}

func (c *ProviderClient) GetConfig() *config.Config {
	return &c.Config
}

const (
	MaxColumnWidth = 120
)

func (c *ProviderClient) loadProviderData() error {
	awsClient := aws.New()
	awsClient.Client = c.HttpClient

	doc, etag, err := awsClient.Fetch()
	if err != nil {
		return err
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	return cache.Upsert(c.Cache, cache.Item{
		Key:     ProviderName,
		Value:   data,
		Version: etag,
		Created: time.Now(),
	})
}

func (c *ProviderClient) Initialise() error {
	c.Logger.Debug("initialising aws client")

	ok, err := cache.CheckExists(c.Cache, ProviderName)
	if err != nil {
		return err
	}

	if ok {
		c.Logger.Info("aws provider data found in cache")

		return nil
	}

	err = c.loadProviderData()
	if err != nil {
		return err
	}

	return nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	tdf, err := loadResultsFile("providers/aws/testdata/aws_18_164_52_75_report.json")
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	c.Logger.Info("aws match returned from test data", "host", c.Host.String())

	return out, nil
}

func (c *ProviderClient) loadHostProviderDataFromCache() (*aws.Doc, error) {
	cacheKey := fmt.Sprintf("aws_%s_report.json", strings.ReplaceAll(c.Host.String(), ".", "_"))

	var result *HostSearchResult

	item, err := cache.Read(c.Cache, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("error reading aws cache: %w", err)
	}

	result, err = unmarshalResponse(item.Value)
	if err != nil {
		defer func() {
			c.Logger.Debug("removing invalid item in aws cache", "key", cacheKey)
			_ = cache.Delete(c.Cache, cacheKey)
		}()

		return nil, fmt.Errorf("error unmarshalling cached response: %w", err)
	}

	if len(result.Raw) == 0 {
		return nil, providers.ErrNoMatchFound
	}

	c.Logger.Info("aws host match data found in cache")

	var doc *aws.Doc
	if item, err = cache.Read(c.Cache, ProviderName); err == nil {
		doc, err = unmarshalProviderData(item.Value)
		if err != nil {
			defer func() {
				_ = cache.Delete(c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached aws provider doc: %w", err)
		}

	}
	if err != nil {
		return nil, fmt.Errorf("error reading aws cache: %w", err)
	}

	return doc, nil
}
func (c *ProviderClient) FindHost() ([]byte, error) {
	var out []byte

	// var result *HostSearchResult

	var err error

	// load test results data
	if c.UseTestData {
		var loadErr error
		out, loadErr = loadTestData(c)
		if err != nil {
			return nil, loadErr
		}

		c.Logger.Info("aws match returned from test data", "host", c.Host.String())

		return out, nil
	}

	doc, err := c.loadHostProviderDataFromCache()
	if err != nil {
		return nil, err
	}

	match, err := matchIPToDoc(c.Host, doc)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("aws match found", "host", c.Host.String())

	match.SyncToken = doc.SyncToken

	match.CreateDate, err = time.Parse("2006-01-02-15-04-05", doc.CreateDate)
	if err != nil {
		return nil, fmt.Errorf("error parsing create date: %w", err)
	}

	// match.ETag = item.Version

	var raw []byte

	raw, err = json.Marshal(match)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	// match.Raw = raw

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		if err = os.WriteFile(fmt.Sprintf("%s/backups/aws_%s_report.json", config.GetConfigRoot("", config.AppName),
			strings.ReplaceAll(c.Host.String(), ".", "_")), raw, 0644); err != nil {
			panic(err)
		}
		c.Logger.Info("backed up aws response", "host", c.Host.String())
	}

	return raw, nil
}

func matchIPToDoc(host netip.Addr, doc *aws.Doc) (*HostSearchResult, error) {
	var match *HostSearchResult

	if host.Is4() {
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
	}

	if host.Is6() {
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
	}

	if match == nil {
		return nil, providers.ErrNoMatchFound
	}

	return match, nil
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	var err error
	var result HostSearchResult
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("error unmarshalling aws data: %w", err)
	}

	if err != nil {
		switch {
		case errors.Is(err, providers.ErrNoDataFound):
			return nil, fmt.Errorf("data not loaded: %w", err)
		case errors.Is(err, providers.ErrFailedToFetchData):
			return nil, err
		case errors.Is(err, providers.ErrNoMatchFound):
			// reset the error as no longer useful for table creation
			return nil, nil
		default:
			return nil, fmt.Errorf("error loading aws api response: %w", err)
		}
	}

	tw := table.NewWriter()
	var rows []table.Row
	tw.AppendRow(table.Row{"Prefix", dashIfEmpty(result.Prefix.IPPrefix.String())})
	tw.AppendRow(table.Row{"Service", dashIfEmpty(result.Prefix.Service)})
	tw.AppendRow(table.Row{"Region", dashIfEmpty(result.Prefix.Region)})
	if !result.CreateDate.IsZero() {
		tw.AppendRow(table.Row{"Source Update", dashIfEmpty(result.CreateDate.String())})
	}

	if result.SyncToken != "" {
		tw.AppendRow(table.Row{"Sync Token", dashIfEmpty(result.SyncToken)})
	}

	if result.ETag != "" {
		tw.AppendRow(table.Row{"Version", dashIfEmpty(result.ETag)})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("AWS IP | Host: %s", c.Host.String())
	if c.UseTestData {
		tw.SetTitle("AWS IP | Host: %s", result.Prefix.IPPrefix.String())
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
	Raw            []byte
	aws.Prefix     `json:"prefix"`
	aws.IPv6Prefix `json:"ipv6Prefix"`
	ETag           string    `json:"etag"`
	SyncToken      string    `json:"syncToken"`
	CreateDate     time.Time `json:"createDate"`
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
