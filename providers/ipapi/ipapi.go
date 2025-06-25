package ipapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/jonhadfield/ipscout/providers"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "ipapi"
	ResultTTL    = 1 * time.Hour
	apiDomain    = "https://ipapi.co"
)

type Client struct {
	session.Session
}

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating ipapi client")

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
	if c.UseTestData || (c.Providers.IPAPI.Enabled != nil && *c.Providers.IPAPI.Enabled) {
		return true
	}

	return false
}

func (c *Client) Priority() *int32 {
	return c.Providers.IPAPI.OutputPriority
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
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

	indicators["CountryCodeISO3"] = doc.CountryCodeIso3

	threatIndicators.Indicators = indicators

	return &threatIndicators, nil
}

func (c *Client) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	rateResult.Score = 0
	rateResult.Detected = false

	if doc.CountryCode != "" {
		i := slices.Index(ratingConfig.Global.HighThreatCountryCodes, doc.CountryCode)
		if i != -1 {
			rateResult.Detected = true
			rateResult.Score += 9
			rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("High Threat Country: %s", doc.CountryCode))
		} else {
			i := slices.Index(ratingConfig.Global.MediumThreatCountryCodes, doc.CountryCode)
			if i != -1 {
				rateResult.Detected = true
				rateResult.Score += 7
				rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("Medium Threat Country: %s", doc.CountryCode))
			}
		}
	}

	return rateResult, nil
}

func (c *Client) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising ipapi client")

	return nil
}

func (c *Client) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("ipapi host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (c *Client) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	if data == nil {
		return nil, nil
	}

	var findHostData HostSearchResult
	if err := json.Unmarshal(data, &findHostData); err != nil {
		return nil, fmt.Errorf("error unmarshalling ipapi data: %w", err)
	}

	// don't render if no data found
	if findHostData.Region == "" && findHostData.Longitude == 0 && findHostData.Latitude == 0 {
		return nil, nil
	}

	tw := table.NewWriter()
	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Organisation", providers.Column1MinWidth), providers.DashIfEmpty(findHostData.Org)})
	tw.AppendRow(table.Row{"Hostname", providers.DashIfEmpty(findHostData.Hostname)})
	tw.AppendRow(table.Row{"Country", providers.DashIfEmpty(findHostData.CountryName)})
	tw.AppendRow(table.Row{"Region", providers.DashIfEmpty(findHostData.Region)})
	tw.AppendRow(table.Row{"City", providers.DashIfEmpty(findHostData.City)})
	tw.AppendRow(table.Row{"Postal", providers.DashIfEmpty(findHostData.Postal)})
	tw.AppendRow(table.Row{"ASN", providers.DashIfEmpty(findHostData.Asn)})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
		{Number: 1, AutoMerge: true},
	})

	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("IPAPI | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("IPAPI | Host: 8.8.4.4")
	}

	c.Logger.Debug("ipapi table created", "host", c.Host.String())

	return &tw, nil
}

type ipapiResp struct {
	IP                 string  `json:"ip"`
	Version            string  `json:"version"`
	City               string  `json:"city"`
	Region             string  `json:"region"`
	RegionCode         string  `json:"region_code"`
	CountryCode        string  `json:"country_code"`
	CountryCodeIso3    string  `json:"country_code_iso3"`
	CountryName        string  `json:"country_name"`
	CountryCapital     string  `json:"country_capital"`
	CountryTld         string  `json:"country_tld"`
	ContinentCode      string  `json:"continent_code"`
	InEu               bool    `json:"in_eu"`
	Postal             string  `json:"postal"`
	Latitude           float64 `json:"latitude"`
	Longitude          float64 `json:"longitude"`
	Timezone           string  `json:"timezone"`
	UtcOffset          string  `json:"utc_offset"`
	CountryCallingCode string  `json:"country_calling_code"`
	Currency           string  `json:"currency"`
	CurrencyName       string  `json:"currency_name"`
	Languages          string  `json:"languages"`
	CountryArea        float64 `json:"country_area"`
	CountryPopulation  int     `json:"country_population"`
	Asn                string  `json:"asn"`
	Org                string  `json:"org"`
	Hostname           string  `json:"hostname"`
}

func loadResponse(c session.Session) (*HostSearchResult, error) {
	res := &HostSearchResult{}

	req, err := retryablehttp.NewRequest("GET", fmt.Sprintf("%s/%s/json", apiDomain, c.Host.String()), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating ipapi request: %w", err)
	}

	req.Header.Set("User-Agent", providers.DefaultUA)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending ipapi request: %w", err)
	}

	defer resp.Body.Close()

	var apiResp ipapiResp

	if err = json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("error decoding ipapi response: %w", err)
	}

	raw, err := json.Marshal(apiResp)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ipapi response: %w", err)
	}

	res.Raw = raw

	return res, nil
}

func loadResultsFile(path string) (*HostSearchResult, error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening ipapi file: %w", err)
	}

	defer jf.Close()

	var res HostSearchResult

	decoder := json.NewDecoder(jf)

	if err = decoder.Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding ipapi file: %w", err)
	}

	return &res, nil
}

func loadTestData(l *slog.Logger) (*HostSearchResult, error) {
	tdf, err := loadResultsFile("providers/ipapi/testdata/ipapi_8_8_4_4_report.json")
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ipapi test data: %w", err)
	}

	tdf.Raw = raw

	l.Info("ipapi match returned from test data", "host", "8.8.4.4")

	return tdf, nil
}

func fetchData(c session.Session) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if c.UseTestData {
		result, err = loadTestData(c.Logger)
		if err != nil {
			return nil, fmt.Errorf("error loading ipapi test data: %w", err)
		}

		return result, nil
	}

	// load data from cache
	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + strings.ReplaceAll(c.Host.String(), ".", "_")

	var item *cache.Item
	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		if item != nil && len(item.Value) > 0 {
			err = json.Unmarshal(item.Value, &result)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling cached ipapi response: %w", err)
			}

			c.Logger.Info("ipapi response found in cache", "host", c.Host.String())

			result.Raw = item.Value

			c.Stats.Mu.Lock()
			c.Stats.FindHostUsedCache[ProviderName] = true
			c.Stats.Mu.Unlock()

			return result, nil
		}
	}

	result, err = loadResponse(c)
	if err != nil {
		return nil, fmt.Errorf("loading ipapi api response: %w", err)
	}

	resultTTL := ResultTTL
	if c.Providers.IPAPI.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(c.Providers.IPAPI.ResultCacheTTL)
	}

	c.Logger.Debug("caching ipapi response", "duration", resultTTL.String())

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching ipapi response: %w", err)
	}

	return result, nil
}

type HostSearchResult struct {
	Raw json.RawMessage `json:"raw,omitempty"`
	ipapiResp
}
