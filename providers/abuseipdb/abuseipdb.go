package abuseipdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/providers"
)

const (
	ProviderName           = "abuseipdb"
	APIURL                 = "https://api.abuseipdb.com"
	HostIPPath             = "/api/v2/check"
	MaxColumnWidth         = 120
	IndentPipeHyphens      = " |-----"
	portLastModifiedFormat = "2006-01-02T15:04:05+07:00"
	ResultTTL              = time.Duration(12 * time.Hour)
)

type Client struct {
	Config     Config
	HTTPClient *retryablehttp.Client
}

type Config struct {
	_ struct{}
	config.Config
	Host   netip.Addr
	APIKey string
}

func NewProviderClient(c config.Config) (*ProviderClient, error) {
	c.Logger.Debug("creating abuseipdb client")

	tc := &ProviderClient{
		c,
	}

	return tc, nil
}

func (c *Client) GetConfig() *config.Config {
	return &c.Config.Config
}

func (c *Client) GetData() (result *HostSearchResult, err error) {
	result, err = loadResultsFile("abuseipdb/testdata/abuseipdb_google_dns_resp.json")
	if err != nil {
		return nil, err
	}

	return result, nil
}

type Provider interface {
	LoadData() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}

func (c *ProviderClient) Enabled() bool {
	return c.Config.Providers.AbuseIPDB.Enabled
}

func (c *ProviderClient) GetConfig() *config.Config {
	return &c.Config
}

type ProviderClient struct {
	config.Config
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

	c.Logger.Debug("initialising abuseipdb client")
	if c.Providers.AbuseIPDB.APIKey == "" && !c.UseTestData {
		return fmt.Errorf("abuseipdb provider api key not set")
	}

	return nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	result, err := fetchData(c.Config)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("abuseipdb host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	var result *HostSearchResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("error unmarshalling abuseipdb data: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	tw := table.NewWriter()
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	tw.AppendRow(table.Row{"Last Reported", providers.DashIfEmpty(result.Data.LastReportedAt)})
	tw.AppendRow(table.Row{"Abuse Confidence Score", providers.DashIfEmpty(result.Data.AbuseConfidenceScore)})
	tw.AppendRow(table.Row{"Public", result.Data.IsPublic})
	tw.AppendRow(table.Row{"Domain", providers.DashIfEmpty(result.Data.Domain)})
	tw.AppendRow(table.Row{"Hostnames", providers.DashIfEmpty(strings.Join(result.Data.Hostnames, ", "))})
	tw.AppendRow(table.Row{"TOR", result.Data.IsTor})
	tw.AppendRow(table.Row{"Country", providers.DashIfEmpty(result.Data.CountryName)})
	tw.AppendRow(table.Row{"Usage Type", providers.DashIfEmpty(result.Data.UsageType)})
	tw.AppendRow(table.Row{"ISP", providers.DashIfEmpty(result.Data.Isp)})
	tw.AppendRow(table.Row{"Reports", fmt.Sprintf("%d (%d days %d users)",
		result.Data.TotalReports, c.Providers.AbuseIPDB.MaxAge, result.Data.NumDistinctUsers)})

	for x, dr := range result.Data.Reports {
		tw.AppendRow(table.Row{"", color.CyanString("%s", dr.ReportedAt.Format(time.DateTime))})
		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Comment: %s", IndentPipeHyphens, dr.Comment)})

		if x == c.Global.MaxReports {
			break
		}
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: true, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("AbuseIPDB | Host: %s", c.Host.String())
	if c.UseTestData {
		tw.SetTitle("AbuseIPDB | Host: %s", result.Data.IPAddress)
	}

	c.Logger.Debug("abuseipdb table created", "host", c.Host.String())

	return &tw, nil
}

func loadAPIResponse(ctx context.Context, c config.Config, apiKey string) (res *HostSearchResult, err error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create abuseipdb api url path: %w", err)
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		panic(err)
	}

	sURL.RawQuery = fmt.Sprintf("ipAddress=%s&verbose=false&maxAgeInDays=1", c.Host.String())

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, sURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Key", apiKey)
	req.Header.Add("Accept", "application/json")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, providers.ErrNoMatchFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb api request failed: %s", resp.Status)
	}

	// read response body
	rBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading abuseipdb response: %w", err)
	}

	defer resp.Body.Close()

	if rBody == nil {
		return nil, providers.ErrNoDataFound
	}

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		if err = os.WriteFile(fmt.Sprintf("%s/backups/abuseipdb_%s_report.json", config.GetConfigRoot("", config.AppName),
			strings.ReplaceAll(c.Host.String(), ".", "_")), rBody, 0o600); err != nil {
			panic(err)
		}
		c.Logger.Debug("backed up abuseipdb response", "host", c.Host.String())
	}

	res, err = unmarshalResponse(rBody)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	res.Raw = rBody
	if res.Raw == nil {
		return nil, fmt.Errorf("abuseipdb: %w", providers.ErrNoMatchFound)
	}

	return res, nil
}

func unmarshalResponse(data []byte) (*HostSearchResult, error) {
	var res HostSearchResult

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	res.Raw = data
	return &res, nil
}

func loadResultsFile(path string) (res *HostSearchResult, err error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening abuseipdb file: %w", err)
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func (ssr *HostSearchResult) CreateTable() *table.Writer {
	tw := table.NewWriter()

	return &tw
}

func fetchData(c config.Config) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if c.UseTestData {
		result, err = loadResultsFile("providers/abuseipdb/testdata/abuseipdb_google_dns_resp.json")
		if err != nil {
			return nil, fmt.Errorf("error loading abuseipdb test data: %w", err)
		}

		return result, nil
	}

	// load data from cache
	cacheKey := fmt.Sprintf("abuseipdb_%s_report.json", strings.ReplaceAll(c.Host.String(), ".", "_"))
	var item *cache.Item
	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		if item.Value != nil && len(item.Value) > 0 {
			result, err = unmarshalResponse(item.Value)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling cached abuseipdb response: %w", err)
			}

			c.Logger.Info("abuseipdb response found in cache", "host", c.Host.String())

			result.Raw = item.Value

			c.Stats.Mu.Lock()
			c.Stats.FindHostUsedCache[ProviderName] = true
			c.Stats.Mu.Unlock()

			return result, nil
		}
	}

	result, err = loadAPIResponse(context.Background(), c, c.Providers.AbuseIPDB.APIKey)
	if err != nil {
		return nil, fmt.Errorf("loading abuseipdb api response: %w", err)
	}

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, ResultTTL); err != nil {
		return nil, err
	}

	return result, nil
}

type HostSearchResult struct {
	Raw  []byte `json:"raw"`
	Data struct {
		IPAddress            string    `json:"ipAddress,omitempty"`
		IsPublic             bool      `json:"isPublic,omitempty"`
		IPVersion            int       `json:"ipVersion,omitempty"`
		IsWhitelisted        bool      `json:"isWhitelisted,omitempty"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore,omitempty"`
		CountryCode          string    `json:"countryCode,omitempty"`
		CountryName          string    `json:"countryName,omitempty"`
		UsageType            string    `json:"usageType,omitempty"`
		Isp                  string    `json:"isp,omitempty"`
		Domain               string    `json:"domain,omitempty"`
		Hostnames            []string  `json:"hostnames,omitempty"`
		IsTor                bool      `json:"isTor,omitempty"`
		TotalReports         int       `json:"totalReports,omitempty"`
		NumDistinctUsers     int       `json:"numDistinctUsers,omitempty"`
		LastReportedAt       time.Time `json:"lastReportedAt,omitempty"`
		Reports              []struct {
			ReportedAt          time.Time `json:"reportedAt,omitempty"`
			Comment             string    `json:"comment,omitempty"`
			Categories          []int     `json:"categories,omitempty"`
			ReporterID          int       `json:"reporterId,omitempty"`
			ReporterCountryCode string    `json:"reporterCountryCode,omitempty"`
			ReporterCountryName string    `json:"reporterCountryName,omitempty"`
		} `json:"reports,omitempty"`
	} `json:"data,omitempty"`
}
