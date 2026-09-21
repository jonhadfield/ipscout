package ipapicom

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "ipapicom"
	ResultTTL    = 1 * time.Hour
	// the free tier is only served over plain HTTP
	apiDomain = "http://ip-api.com"
	// fields limits the response to what is rendered and rated
	fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

	statusSuccess = "success"

	highThreatCountryScore   = 9
	mediumThreatCountryScore = 7
)

// failMessagesNoMatch are the failure messages ip-api.com gives for addresses
// it holds no data for, which are routine rather than errors.
var failMessagesNoMatch = []string{"private range", "reserved range"}

type Client struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating ipapicom client")

	tc := Client{
		c,
	}

	return &tc, nil
}

func (c *Client) Enabled() bool {
	if c.UseTestData || (c.Providers.IPAPICom.Enabled != nil && *c.Providers.IPAPICom.Enabled) {
		return true
	}

	return false
}

func (c *Client) Priority() *int32 {
	return c.Providers.IPAPICom.OutputPriority
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
}

func (c *Client) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	return &providers.ThreatIndicators{
		Provider: ProviderName,
		Indicators: map[string]string{
			"CountryCode": doc.CountryCode,
			"Proxy":       strconv.FormatBool(doc.Proxy),
			"Hosting":     strconv.FormatBool(doc.Hosting),
			"Mobile":      strconv.FormatBool(doc.Mobile),
		},
	}, nil
}

func (c *Client) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	var rateResult providers.RateResult

	switch {
	case doc.CountryCode == "":
	case slices.Contains(ratingConfig.Global.HighThreatCountryCodes, doc.CountryCode):
		rateResult.Detected = true
		rateResult.Score = highThreatCountryScore
		rateResult.Reasons = append(rateResult.Reasons, "High Threat Country: "+doc.CountryCode)
	case slices.Contains(ratingConfig.Global.MediumThreatCountryCodes, doc.CountryCode):
		rateResult.Detected = true
		rateResult.Score = mediumThreatCountryScore
		rateResult.Reasons = append(rateResult.Reasons, "Medium Threat Country: "+doc.CountryCode)
	}

	return rateResult, nil
}

func (c *Client) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising ipapicom client")

	return nil
}

func (c *Client) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("ipapicom host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (c *Client) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	if data == nil {
		return nil, nil
	}

	var doc HostSearchResult
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("error unmarshalling ipapicom data: %w", err)
	}

	if doc.Status != statusSuccess {
		return nil, nil
	}

	tw := table.NewWriter()
	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Country", providers.Column1MinWidth), providers.DashIfEmpty(doc.Country)})
	tw.AppendRow(table.Row{"Region", providers.DashIfEmpty(doc.RegionName)})
	tw.AppendRow(table.Row{"City", providers.DashIfEmpty(doc.City)})
	tw.AppendRow(table.Row{"Postal", providers.DashIfEmpty(doc.Zip)})
	tw.AppendRow(table.Row{"Timezone", providers.DashIfEmpty(doc.Timezone)})
	tw.AppendRow(table.Row{"ISP", providers.DashIfEmpty(doc.ISP)})
	tw.AppendRow(table.Row{"Organisation", providers.DashIfEmpty(doc.Org)})
	tw.AppendRow(table.Row{"AS", providers.DashIfEmpty(doc.AS)})
	tw.AppendRow(table.Row{"Reverse DNS", providers.DashIfEmpty(doc.Reverse)})
	tw.AppendRow(table.Row{"Proxy/VPN/Tor", yesNo(doc.Proxy)})
	tw.AppendRow(table.Row{"Hosting", yesNo(doc.Hosting)})
	tw.AppendRow(table.Row{"Mobile", yesNo(doc.Mobile)})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
		{Number: 1, AutoMerge: true},
	})

	tw.SetAutoIndex(false)
	tw.SetTitle("IP-API.COM | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("IP-API.COM | Host: %s", doc.Query)
	}

	c.Logger.Debug("ipapicom table created", "host", c.Host.String())

	return &tw, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}

	return "no"
}

type HostSearchResult struct {
	Raw         json.RawMessage `json:"raw,omitempty"`
	Status      string          `json:"status"`
	Message     string          `json:"message,omitempty"`
	Country     string          `json:"country"`
	CountryCode string          `json:"countryCode"`
	RegionName  string          `json:"regionName"`
	City        string          `json:"city"`
	Zip         string          `json:"zip"`
	Lat         float64         `json:"lat"`
	Lon         float64         `json:"lon"`
	Timezone    string          `json:"timezone"`
	ISP         string          `json:"isp"`
	Org         string          `json:"org"`
	AS          string          `json:"as"`
	ASName      string          `json:"asname"`
	Reverse     string          `json:"reverse"`
	Mobile      bool            `json:"mobile"`
	Proxy       bool            `json:"proxy"`
	Hosting     bool            `json:"hosting"`
	Query       string          `json:"query"`
}

func loadResponse(c session.Session) (*HostSearchResult, error) {
	req, err := retryablehttp.NewRequest("GET", fmt.Sprintf("%s/json/%s?fields=%s", apiDomain, c.Host.String(), fields), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating ipapicom request: %w", err)
	}

	req.Header.Set("User-Agent", providers.DefaultUA)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending ipapicom request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipapicom returned unexpected status: %d", resp.StatusCode)
	}

	var res HostSearchResult

	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding ipapicom response: %w", err)
	}

	if res.Status != statusSuccess {
		if slices.Contains(failMessagesNoMatch, res.Message) {
			return nil, fmt.Errorf("%s: %s: %w", ProviderName, res.Message, providers.ErrNoMatchFound)
		}

		return nil, fmt.Errorf("ipapicom lookup failed: %s", res.Message)
	}

	raw, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ipapicom response: %w", err)
	}

	res.Raw = raw

	return &res, nil
}

func loadResultsFile(path string) (*HostSearchResult, error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening ipapicom file: %w", err)
	}

	defer jf.Close()

	var res HostSearchResult

	if err = json.NewDecoder(jf).Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding ipapicom file: %w", err)
	}

	return &res, nil
}

func loadTestData(l *slog.Logger) (*HostSearchResult, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/ipapicom/testdata/ipapicom_8_8_4_4_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting ipapicom test data file path: %w", err)
	}

	tdf, err := loadResultsFile(resultsFile)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ipapicom test data: %w", err)
	}

	tdf.Raw = raw

	l.Info("ipapicom match returned from test data", "host", tdf.Query)

	return tdf, nil
}

func fetchData(c session.Session) (*HostSearchResult, error) {
	if c.UseTestData {
		result, err := loadTestData(c.Logger)
		if err != nil {
			return nil, fmt.Errorf("error loading ipapicom test data: %w", err)
		}

		return result, nil
	}

	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + strings.ReplaceAll(c.Host.String(), ".", "_")

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil && item != nil && len(item.Value) > 0 {
		var result HostSearchResult

		if err = json.Unmarshal(item.Value, &result); err != nil {
			return nil, fmt.Errorf("error unmarshalling cached ipapicom response: %w", err)
		}

		c.Logger.Debug("ipapicom response found in cache", "host", c.Host.String())

		result.Raw = item.Value

		c.Stats.Mu.Lock()
		c.Stats.FindHostUsedCache[ProviderName] = true
		c.Stats.Mu.Unlock()

		return &result, nil
	}

	result, err := loadResponse(c)
	if err != nil {
		if errors.Is(err, providers.ErrNoMatchFound) {
			return nil, err
		}

		return nil, fmt.Errorf("loading ipapicom api response: %w", err)
	}

	resultTTL := ResultTTL
	if c.Providers.IPAPICom.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(c.Providers.IPAPICom.ResultCacheTTL)
	}

	c.Logger.Debug("caching ipapicom response", "duration", resultTTL.String())

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching ipapicom response: %w", err)
	}

	return result, nil
}
