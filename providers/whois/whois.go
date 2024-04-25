package whois

//
//import (
//	"context"
//	"encoding/json"
//	"errors"
//	"fmt"
//	"log"
//	"net/netip"
//	"os"
//	"strings"
//	"time"
//
//	"github.com/miekg/dns"
//
//	"github.com/fatih/color"
//	"github.com/hashicorp/go-retryablehttp"
//	"github.com/jedib0t/go-pretty/v6/table"
//	"github.com/jonhadfield/ipscout/cache"
//	"github.com/jonhadfield/ipscout/config"
//	"github.com/jonhadfield/ipscout/providers"
//)
//
//const (
//	ProviderName           = "PTR"
//	APIURL                 = "https://api.PTR.com"
//	HostIPPath             = "/api/v2/check"
//	MaxColumnWidth         = 120
//	IndentPipeHyphens      = " |-----"
//	portLastModifiedFormat = "2006-01-02T15:04:05+07:00"
//	ResultTTL              = time.Duration(12 * time.Hour)
//)
//
//type Client struct {
//	Config     Config
//	HTTPClient *retryablehttp.Client
//}
//
//type Config struct {
//	_ struct{}
//	config.Config
//	Host   netip.Addr
//	APIKey string
//}
//
//func NewProviderClient(c config.Config) (*ProviderClient, error) {
//	c.Logger.Debug("creating PTR client")
//
//	tc := &ProviderClient{
//		c,
//	}
//
//	return tc, nil
//}
//
//func (c *Client) GetConfig() *config.Config {
//	return &c.Config.Config
//}
//
//func (c *Client) GetData() (result *HostSearchResult, err error) {
//	result, err = loadResultsFile("PTR/testdata/PTR_google_dns_resp.json")
//	if err != nil {
//		return nil, err
//	}
//
//	return result, nil
//}
//
//type Provider interface {
//	LoadData() ([]byte, error)
//	CreateTable([]byte) (*table.Writer, error)
//}
//
//func (c *ProviderClient) Enabled() bool {
//	return c.Config.Providers.PTR.Enabled
//}
//
//func (c *ProviderClient) GetConfig() *config.Config {
//	return &c.Config
//}
//
//type ProviderClient struct {
//	config.Config
//}
//
//func (c *ProviderClient) Initialise() error {
//	if c.Cache == nil {
//		return errors.New("cache not set")
//	}
//
//	start := time.Now()
//	defer func() {
//		c.Stats.Mu.Lock()
//		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
//		c.Stats.Mu.Unlock()
//	}()
//
//	c.Logger.Debug("initialising PTR client")
//	if "ddd" == "" && !c.UseTestData {
//		return fmt.Errorf("PTR provider api key not set")
//	}
//
//	return nil
//}
//
//func (c *ProviderClient) FindHost() ([]byte, error) {
//	start := time.Now()
//	defer func() {
//		c.Stats.Mu.Lock()
//		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
//		c.Stats.Mu.Unlock()
//	}()
//
//	result, err := fetchData(c.Config)
//	if err != nil {
//		return nil, err
//	}
//
//	c.Logger.Debug("PTR host match data", "size", len(result.Raw))
//
//	return result.Raw, nil
//}
//
//func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
//	start := time.Now()
//	defer func() {
//		c.Stats.Mu.Lock()
//		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
//		c.Stats.Mu.Unlock()
//	}()
//
//	var result *HostSearchResult
//	if err := json.Unmarshal(data, &result); err != nil {
//		return nil, fmt.Errorf("error unmarshalling PTR data: %w", err)
//	}
//
//	if result == nil {
//		return nil, nil
//	}
//
//	tw := table.NewWriter()
//	tw.SetColumnConfigs([]table.ColumnConfig{
//		{Number: 1, AutoMerge: true},
//	})
//
//	tw.AppendRow(table.Row{"Last Reported", providers.DashIfEmpty(result.Data.LastReportedAt)})
//	tw.AppendRow(table.Row{"Abuse Confidence Score", providers.DashIfEmpty(result.Data.AbuseConfidenceScore)})
//	tw.AppendRow(table.Row{"Public", result.Data.IsPublic})
//	tw.AppendRow(table.Row{"Domain", providers.DashIfEmpty(result.Data.Domain)})
//	tw.AppendRow(table.Row{"Hostnames", providers.DashIfEmpty(strings.Join(result.Data.Hostnames, ", "))})
//	tw.AppendRow(table.Row{"TOR", result.Data.IsTor})
//	tw.AppendRow(table.Row{"Country", providers.DashIfEmpty(result.Data.CountryName)})
//	tw.AppendRow(table.Row{"Usage Type", providers.DashIfEmpty(result.Data.UsageType)})
//	tw.AppendRow(table.Row{"ISP", providers.DashIfEmpty(result.Data.Isp)})
//	tw.AppendRow(table.Row{"Reports", fmt.Sprintf("%d (%d days %d users)",
//		result.Data.TotalReports, "", result.Data.NumDistinctUsers)})
//
//	for x, dr := range result.Data.Reports {
//		tw.AppendRow(table.Row{"", color.CyanString("%s", dr.ReportedAt.Format(time.DateTime))})
//		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Comment: %s", IndentPipeHyphens, dr.Comment)})
//
//		if x == c.Global.MaxReports {
//			break
//		}
//	}
//
//	tw.SetColumnConfigs([]table.ColumnConfig{
//		{Number: 2, AutoMerge: true, WidthMax: MaxColumnWidth, WidthMin: 50},
//	})
//	tw.SetAutoIndex(false)
//	// tw.SetStyle(table.StyleColoredDark)
//	// tw.Style().Options.DrawBorder = true
//	tw.SetTitle("PTR | Host: %s", c.Host.String())
//	if c.UseTestData {
//		tw.SetTitle("PTR | Host: %s", result.Data.IPAddress)
//	}
//
//	c.Logger.Debug("PTR table created", "host", c.Host.String())
//
//	return &tw, nil
//}
//
//func loadResponse(ctx context.Context, c config.Config, apiKey string) (res *HostSearchResult, err error) {
//	target := "microsoft.com"
//	server := "8.8.8.8"
//
//	dc := dns.Client{}
//	m := dns.Msg{}
//	m.SetQuestion(target+".", dns.TypeA)
//	r, t, err := dc.Exchange(&m, server+":53")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if len(r.Answer) == 0 {
//		log.Fatal("No results")
//	}
//
//	return res, nil
//}
//
//func unmarshalResponse(data []byte) (*HostSearchResult, error) {
//	var res HostSearchResult
//
//	if err := json.Unmarshal(data, &res); err != nil {
//		return nil, err
//	}
//	res.Raw = data
//	return &res, nil
//}
//
//func loadResultsFile(path string) (res *HostSearchResult, err error) {
//	jf, err := os.Open(path)
//	if err != nil {
//		return nil, fmt.Errorf("error opening PTR file: %w", err)
//	}
//
//	defer jf.Close()
//
//	decoder := json.NewDecoder(jf)
//
//	err = decoder.Decode(&res)
//	if err != nil {
//		return res, err
//	}
//
//	return res, nil
//}
//
//func (ssr *HostSearchResult) CreateTable() *table.Writer {
//	tw := table.NewWriter()
//
//	return &tw
//}
//
//func fetchData(c config.Config) (*HostSearchResult, error) {
//	var result *HostSearchResult
//
//	var err error
//
//	if c.UseTestData {
//		result, err = loadResultsFile("providers/PTR/testdata/PTR_google_dns_resp.json")
//		if err != nil {
//			return nil, fmt.Errorf("error loading PTR test data: %w", err)
//		}
//
//		return result, nil
//	}
//
//	// load data from cache
//	cacheKey := fmt.Sprintf("PTR_%s_report.json", strings.ReplaceAll(c.Host.String(), ".", "_"))
//	var item *cache.Item
//	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
//		if item.Value != nil && len(item.Value) > 0 {
//			result, err = unmarshalResponse(item.Value)
//			if err != nil {
//				return nil, fmt.Errorf("error unmarshalling cached PTR response: %w", err)
//			}
//
//			c.Logger.Info("PTR response found in cache", "host", c.Host.String())
//
//			result.Raw = item.Value
//
//			c.Stats.Mu.Lock()
//			c.Stats.FindHostUsedCache[ProviderName] = true
//			c.Stats.Mu.Unlock()
//
//			return result, nil
//		}
//	}
//
//	result, err = loadResponse(context.Background(), c, "")
//	if err != nil {
//		return nil, fmt.Errorf("loading PTR api response: %w", err)
//	}
//
//	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
//		Key:     cacheKey,
//		Value:   result.Raw,
//		Created: time.Now(),
//	}, ResultTTL); err != nil {
//		return nil, err
//	}
//
//	return result, nil
//}
//
//type HostSearchResult struct {
//	Raw  []byte `json:"raw"`
//	Data struct {
//		IPAddress            string    `json:"ipAddress,omitempty"`
//		IsPublic             bool      `json:"isPublic,omitempty"`
//		IPVersion            int       `json:"ipVersion,omitempty"`
//		IsWhitelisted        bool      `json:"isWhitelisted,omitempty"`
//		AbuseConfidenceScore int       `json:"abuseConfidenceScore,omitempty"`
//		CountryCode          string    `json:"countryCode,omitempty"`
//		CountryName          string    `json:"countryName,omitempty"`
//		UsageType            string    `json:"usageType,omitempty"`
//		Isp                  string    `json:"isp,omitempty"`
//		Domain               string    `json:"domain,omitempty"`
//		Hostnames            []string  `json:"hostnames,omitempty"`
//		IsTor                bool      `json:"isTor,omitempty"`
//		TotalReports         int       `json:"totalReports,omitempty"`
//		NumDistinctUsers     int       `json:"numDistinctUsers,omitempty"`
//		LastReportedAt       time.Time `json:"lastReportedAt,omitempty"`
//		Reports              []struct {
//			ReportedAt          time.Time `json:"reportedAt,omitempty"`
//			Comment             string    `json:"comment,omitempty"`
//			Categories          []int     `json:"categories,omitempty"`
//			ReporterID          int       `json:"reporterId,omitempty"`
//			ReporterCountryCode string    `json:"reporterCountryCode,omitempty"`
//			ReporterCountryName string    `json:"reporterCountryName,omitempty"`
//		} `json:"reports,omitempty"`
//	} `json:"data,omitempty"`
//}