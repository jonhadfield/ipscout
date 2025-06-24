package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jonhadfield/ipscout/helpers"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName           = "abuseipdb"
	APIURL                 = "https://api.abuseipdb.com"
	HostIPPath             = "/api/v2/check"
	IndentPipeHyphens      = " |-----"
	portLastModifiedFormat = "2006-01-02T15:04:05+07:00"
	ResultTTL              = 12 * time.Hour
	OutputPriority         = 40
	veryHighScoreThreshold = 10
	highScoreThreshold     = 7
	mediumScoreThreshold   = 5
	lowScoreThreshold      = 3
	abuseScoreMultiplier   = 10
	APITimeout             = 10 * time.Second
)

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

func NewClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating abuseipdb client")

	tc := Client{
		c,
	}

	return &tc, nil
}

type Provider interface {
	LoadData() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}

func (c *Client) Enabled() bool {
	switch {
	case c.UseTestData:
		return true
	case c.Providers.AbuseIPDB.Enabled != nil && *c.Providers.AbuseIPDB.Enabled:
		if c.Providers.AbuseIPDB.APIKey != "" {
			return true
		}
	}

	return false
}

func (c *Client) Priority() *int32 {
	return c.Providers.AbuseIPDB.OutputPriority
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
}

func (c *Client) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	if doc.Data.IsTor {
		rateResult.Score += 8
		rateResult.Reasons = []string{"TOR node"}
	}

	rateResult.Score = doc.Data.AbuseConfidenceScore / abuseScoreMultiplier
	rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("confidence: %.2f", doc.Data.AbuseConfidenceScore))

	switch {
	case rateResult.Score >= veryHighScoreThreshold:
		rateResult.Threat = "very high"
		rateResult.Score = veryHighScoreThreshold
	case rateResult.Score >= highScoreThreshold:
		rateResult.Threat = "high"
	case rateResult.Score >= mediumScoreThreshold:
		rateResult.Threat = "medium"
	case rateResult.Score >= lowScoreThreshold:
		rateResult.Threat = "low"
	default:
		rateResult.Threat = "low"
		rateResult.Score = lowScoreThreshold
	}

	if doc.Data.IPAddress != "" {
		rateResult.Detected = true
	}

	return rateResult, nil
}

func (c *Client) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	threatIndicators := providers.ThreatIndicators{
		Provider: ProviderName,
	}

	indicators := make(map[string]string)

	if doc.Data.IsTor {
		indicators["TOR"] = "true"
	}

	indicators["AbuseConfidencePercentage"] = strconv.Itoa(int(doc.Data.AbuseConfidenceScore))

	threatIndicators.Indicators = indicators

	return &threatIndicators, nil
}

type Client struct {
	session.Session
}

func (c *Client) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising abuseipdb client")

	return nil
}

func (c *Client) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("abuseipdb host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (c *Client) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	rowEmphasisColor := providers.RowEmphasisColor(c.Session)

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

	lastReported := result.Data.LastReportedAt

	var lastReportedOutput string

	if lastReported.IsZero() {
		lastReportedOutput = "never"
	} else {
		lastReportedOutput = lastReported.UTC().Format(providers.TimeFormat)
	}

	tw.AppendRow(table.Row{"Last Reported", lastReportedOutput})
	tw.AppendRow(table.Row{"Confidence", providers.DashIfEmpty(result.Data.AbuseConfidenceScore)})
	tw.AppendRow(table.Row{"Public", result.Data.IsPublic})
	tw.AppendRow(table.Row{"Domain", providers.DashIfEmpty(result.Data.Domain)})
	tw.AppendRow(table.Row{"Hostnames", providers.DashIfEmpty(strings.Join(result.Data.Hostnames, ", "))})
	tw.AppendRow(table.Row{"TOR", result.Data.IsTor})
	tw.AppendRow(table.Row{"Country", providers.DashIfEmpty(result.Data.CountryName)})
	tw.AppendRow(table.Row{"Usage Type", providers.DashIfEmpty(result.Data.UsageType)})
	tw.AppendRow(table.Row{"ISP", providers.DashIfEmpty(result.Data.Isp)})

	reportsOutput := "0"
	if result.Data.TotalReports > 0 {
		reportsOutput = fmt.Sprintf("%d (%d days %d users)",
			result.Data.TotalReports,
			c.Providers.AbuseIPDB.MaxAge,
			result.Data.NumDistinctUsers)
	}

	tw.AppendRow(table.Row{"Reports", reportsOutput})

	for x, dr := range result.Data.Reports {
		tw.AppendRow(table.Row{"", rowEmphasisColor("%s", dr.ReportedAt.UTC().Format(providers.TimeFormat))})
		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Comment: %s", IndentPipeHyphens, dr.Comment)})

		if x == c.Config.Global.MaxReports {
			break
		}
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth, ColorsHeader: text.Colors{text.BgCyan}},
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

func loadAPIResponse(ctx context.Context, c session.Session, apiKey string) (*HostSearchResult, error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create abuseipdb api url path: %w", err)
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse abuseipdb api url: %w", err)
	}

	sURL.RawQuery = fmt.Sprintf("ipAddress=%s&verbose=false&maxAgeInDays=1", c.Host.String())

	ctx, cancel := context.WithTimeout(ctx, APITimeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, sURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Key", apiKey)
	req.Header.Add("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
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

	res, err := unmarshalResponse(rBody)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	res.Raw = rBody
	if res.Raw == nil {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	return res, nil
}

func unmarshalResponse(data []byte) (*HostSearchResult, error) {
	var res HostSearchResult

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling abuseipdb response: %w", err)
	}

	res.Raw = data

	return &res, nil
}

func loadResultsFile(path string) (*HostSearchResult, error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening abuseipdb file: %w", err)
	}

	defer jf.Close()

	var res HostSearchResult

	decoder := json.NewDecoder(jf)

	if err = decoder.Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding abuseipdb file: %w", err)
	}

	return &res, nil
}

func (ssr *HostSearchResult) CreateTable() *table.Writer {
	tw := table.NewWriter()

	return &tw
}

func fetchData(c session.Session) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if c.UseTestData {
		result, err = loadResultsFile("providers/abuseipdb/testdata/abuseipdb_194_169_175_35_report.json")
		if err != nil {
			return nil, fmt.Errorf("error loading abuseipdb test data: %w", err)
		}

		var raw json.RawMessage

		raw, err = json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("error marshalling abuseipdb test data: %w", err)
		}

		result.Raw = raw

		return result, nil
	}

	// load data from cache
	cacheKey := fmt.Sprintf("abuseipdb_%s_report.json", strings.ReplaceAll(c.Host.String(), ".", "_"))

	var item *cache.Item

	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		if item != nil && len(item.Value) > 0 {
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

	resultTTL := ResultTTL
	if c.Providers.AbuseIPDB.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(c.Providers.AbuseIPDB.ResultCacheTTL)
	}

	c.Logger.Debug("caching abuseipdb response", "duration", resultTTL.String())

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching abuseipdb response: %w", err)
	}

	return result, nil
}

type HostSearchResult struct {
	Raw  json.RawMessage `json:"raw"`
	Data struct {
		IPAddress            string    `json:"ipAddress,omitempty"`
		IsPublic             bool      `json:"isPublic,omitempty"`
		IPVersion            int       `json:"ipVersion,omitempty"`
		IsWhitelisted        bool      `json:"isWhitelisted,omitempty"`
		AbuseConfidenceScore float64   `json:"abuseConfidenceScore,omitempty"`
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
