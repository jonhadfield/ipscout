package ipqs

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/jonhadfield/ipscout/providers"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName                         = "ipqs"
	ResultTTL                            = 1 * time.Hour
	APIURL                               = "https://ipqualityscore.com/api/json/ip"
	dataColumnNo                         = 2
	veryHighScoreThreshold               = 10
	highScoreThreshold                   = 7
	mediumScoreThreshold                 = 5
	lowScoreThreshold                    = 3
	ipqsScoreMultiplier                  = 10
	txtPremiumRequired                   = "Premium required."
	defaultMediumThreatCountryMatchScore = 6.0
	defaultHighThreatCountryMatchScore   = 9.0
	defaultVPNMatchScore                 = 7.0
	defaultTORMatchScore                 = 7.0
	defaultRecentAbuseMatchScore         = 9.0
	defaultBotMatchScore                 = 9.0
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
	c.Logger.Debug("creating IPQS client")

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
	if c.UseTestData || (c.Session.Providers.IPQS.Enabled != nil && *c.Session.Providers.IPQS.Enabled) {
		return true
	}

	return false
}

func higherOf(first, second float64) float64 {
	if first > second {
		return first
	}

	return second
}

// chooseScore returns the user defined score if provided and higher than the running total
func chooseScore(def, runningTotal float64, user *float64) float64 {
	if user != nil {
		if *user > runningTotal {
			return *user
		}

		return runningTotal
	}

	// return default if no user defined score
	return def
}

func (c *Client) Priority() *int32 {
	return c.Session.Providers.IPQS.OutputPriority
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
}

func loadRatingConfig(in []byte) (providers.RatingConfig, error) {
	var ratingConfig providers.RatingConfig

	if err := json.Unmarshal(in, &ratingConfig); err != nil {
		return providers.RatingConfig{}, fmt.Errorf("error unmarshalling rating config: %w", err)
	}

	return ratingConfig, nil
}

func loadFindHostResults(in []byte) (HostSearchResult, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(in, &doc); err != nil {
		return HostSearchResult{}, fmt.Errorf("error unmarshalling find result: %w", err)
	}

	return doc, nil
}

func rateHost(hostData ipqsResp, ratingConfig providers.RatingConfig) providers.RateResult {
	var rateResult providers.RateResult

	if !hostData.Success {
		return rateResult
	}

	rateResult.Detected = true

	if hostData.CountryCode != "" {
		if countryCodeInCodes(hostData.CountryCode, ratingConfig.Global.MediumThreatCountryCodes) {
			// if user provided score, then use that, otherwise use default
			rateResult.Score = chooseScore(defaultMediumThreatCountryMatchScore, rateResult.Score, ratingConfig.ProviderRatingsConfigs.IPQS.MediumThreatCountryMatchScore)
		}

		if countryCodeInCodes(hostData.CountryCode, ratingConfig.Global.HighThreatCountryCodes) {
			// if user provided score, then use that, otherwise use default
			rateResult.Score = chooseScore(defaultHighThreatCountryMatchScore, rateResult.Score, ratingConfig.ProviderRatingsConfigs.IPQS.HighThreatCountryMatchScore)
		}
	}

	if hostData.Tor {
		rateResult.Score = chooseScore(defaultTORMatchScore, rateResult.Score, ratingConfig.ProviderRatingsConfigs.IPQS.TORScore)
		rateResult.Reasons = append(rateResult.Reasons, "TOR")
	}

	if hostData.Vpn {
		rateResult.Score = chooseScore(defaultVPNMatchScore, rateResult.Score, ratingConfig.ProviderRatingsConfigs.IPQS.VPNScore)
		rateResult.Reasons = append(rateResult.Reasons, "VPN")
	}

	if hostData.RecentAbuse {
		rateResult.Score = chooseScore(defaultRecentAbuseMatchScore, rateResult.Score, ratingConfig.ProviderRatingsConfigs.IPQS.RecentAbuseScore)

		rateResult.Reasons = append(rateResult.Reasons, "Recent abuse")
	}

	if hostData.BotStatus {
		rateResult.Score = chooseScore(defaultBotMatchScore, rateResult.Score, ratingConfig.ProviderRatingsConfigs.IPQS.BotScore)
		rateResult.Reasons = append(rateResult.Reasons, "Bot")
	}

	rateResult.Score = higherOf(rateResult.Score, float64(hostData.FraudScore)/ipqsScoreMultiplier)
	rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("confidence: %.2f", float64(hostData.FraudScore)))

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

	return rateResult
}

func countryCodeInCodes(countryCode string, codes []string) bool {
	for _, c := range codes {
		if strings.EqualFold(countryCode, c) {
			return true
		}
	}

	return false
}

func (c *Client) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf("error unmarshalling find result: %w", err)
	}

	threatIndicators := providers.ThreatIndicators{
		Provider: ProviderName,
	}

	indicators := make(map[string]string)

	if doc.Proxy {
		indicators["IsProxy"] = "true"
	}

	if doc.BotStatus {
		indicators["IsBot"] = "true"
	}

	indicators["FraudScore"] = strconv.Itoa(doc.FraudScore)

	threatIndicators.Indicators = indicators

	return &threatIndicators, nil
}

func (c *Client) RateHostData(findResJSON []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	ratingConfig, err := loadRatingConfig(ratingConfigJSON)
	if err != nil {
		return providers.RateResult{}, fmt.Errorf("error loading rating config: %w", err)
	}

	hostData, err := loadFindHostResults(findResJSON)
	if err != nil {
		return providers.RateResult{}, fmt.Errorf("error loading find host results: %w", err)
	}

	rateResult := rateHost(hostData.ipqsResp, ratingConfig)

	return rateResult, nil
}

func (c *Client) Initialise() error {
	if c.Session.Cache == nil {
		return errors.New("cache not set")
	}

	start := time.Now()
	defer func() {
		c.Session.Stats.Mu.Lock()
		c.Session.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Session.Stats.Mu.Unlock()
	}()

	c.Session.Logger.Debug("initialising ipqs client")

	return nil
}

func (c *Client) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Session.Stats.Mu.Lock()
		c.Session.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Session.Stats.Mu.Unlock()
	}()

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Session.Logger.Debug("ipqs host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (c *Client) CreateTable(data []byte) (*table.Writer, error) {
	start := time.Now()
	defer func() {
		c.Session.Stats.Mu.Lock()
		c.Session.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Session.Stats.Mu.Unlock()
	}()

	if data == nil {
		return nil, nil
	}

	var findHostData HostSearchResult
	if err := json.Unmarshal(data, &findHostData); err != nil {
		return nil, fmt.Errorf("error unmarshalling ipqs data: %w", err)
	}

	// don't render if no data found
	if findHostData.Region == "" && findHostData.Longitude == 0 && findHostData.Latitude == 0 {
		return nil, nil
	}

	tw := table.NewWriter()
	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Organisation", providers.Column1MinWidth), providers.DashIfEmpty(findHostData.Organization)})
	tw.AppendRow(table.Row{"Hostname", providers.DashIfEmpty(findHostData.Host)})
	tw.AppendRow(table.Row{"ISP", providers.DashIfEmpty(findHostData.Isp)})
	tw.AppendRow(table.Row{"Country", providers.DashIfEmpty(findHostData.CountryCode)})
	tw.AppendRow(table.Row{"Region", providers.DashIfEmpty(findHostData.Region)})
	tw.AppendRow(table.Row{"Timezone", providers.DashIfEmpty(findHostData.Timezone)})
	// tw.AppendRow(table.Row{"Longitude", providers.DashIfEmpty(findHostData.Longitude)})
	// tw.AppendRow(table.Row{"Latitude", providers.DashIfEmpty(findHostData.Latitude)})
	tw.AppendRow(table.Row{"City", providers.DashIfEmpty(findHostData.City)})
	tw.AppendRow(table.Row{"Postal", providers.DashIfEmpty(findHostData.ZipCode)})
	tw.AppendRow(table.Row{"ASN", providers.DashIfEmpty(findHostData.Asn)})
	tw.AppendRow(table.Row{"Fraud Score", providers.DashIfEmpty(findHostData.FraudScore)})
	tw.AppendRow(table.Row{"Proxy", findHostData.Proxy})
	tw.AppendRow(table.Row{"Crawler", findHostData.IsCrawler})

	if findHostData.ConnectionType != txtPremiumRequired {
		tw.AppendRow(table.Row{"Connection Type", providers.DashIfEmpty(findHostData.ConnectionType)})
	}

	tw.AppendRow(table.Row{"Bot Status", findHostData.BotStatus})
	tw.AppendRow(table.Row{"VPN", findHostData.Vpn})
	tw.AppendRow(table.Row{"TOR", findHostData.Tor})
	tw.AppendRow(table.Row{"Active VPN", findHostData.ActiveVpn})
	tw.AppendRow(table.Row{"Active TOR", findHostData.ActiveTor})
	tw.AppendRow(table.Row{"High Risk Attacks", findHostData.HighRiskAttacks})
	tw.AppendRow(table.Row{"Shared Connection", findHostData.SharedConnection})
	tw.AppendRow(table.Row{"Dynamic Connection", findHostData.DynamicConnection})
	tw.AppendRow(table.Row{"Security Scanner", findHostData.SecurityScanner})
	tw.AppendRow(table.Row{"Trusted Network", findHostData.TrustedNetwork})
	tw.AppendRow(table.Row{"Recent Abuser", findHostData.RecentAbuse})
	tw.AppendRow(table.Row{"Frequent Abuser", findHostData.FrequentAbuser})

	if findHostData.AbuseVelocity != txtPremiumRequired {
		tw.AppendRow(table.Row{"Abuse Velocity", providers.DashIfEmpty(findHostData.AbuseVelocity)})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: dataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
		{Number: 1, AutoMerge: true},
	})

	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("IPQS | Host: %s", c.Session.Host.String())

	if c.UseTestData {
		tw.SetTitle("IPQS | Host: 74.125.219.32")
	}

	c.Session.Logger.Debug("ipqs table created", "host", c.Session.Host.String())

	return &tw, nil
}

type ipqsResp struct {
	Message            string             `json:"message,omitempty"`
	Success            bool               `json:"success,omitempty"`
	Proxy              bool               `json:"proxy,omitempty"`
	Isp                string             `json:"ISP,omitempty"`
	Organization       string             `json:"organization,omitempty"`
	Asn                int                `json:"ASN,omitempty"`
	Host               string             `json:"host,omitempty"`
	CountryCode        string             `json:"country_code,omitempty"`
	City               string             `json:"city,omitempty"`
	Region             string             `json:"region,omitempty"`
	IsCrawler          bool               `json:"is_crawler,omitempty"`
	ConnectionType     string             `json:"connection_type,omitempty"`
	Latitude           float64            `json:"latitude,omitempty"`
	Longitude          float64            `json:"longitude,omitempty"`
	ZipCode            string             `json:"zip_code,omitempty"`
	Timezone           string             `json:"timezone,omitempty"`
	Vpn                bool               `json:"vpn,omitempty"`
	Tor                bool               `json:"tor,omitempty"`
	ActiveVpn          bool               `json:"active_vpn,omitempty"`
	ActiveTor          bool               `json:"active_tor,omitempty"`
	RecentAbuse        bool               `json:"recent_abuse,omitempty"`
	FrequentAbuser     bool               `json:"frequent_abuser,omitempty"`
	HighRiskAttacks    bool               `json:"high_risk_attacks,omitempty"`
	AbuseVelocity      string             `json:"abuse_velocity,omitempty"`
	BotStatus          bool               `json:"bot_status,omitempty"`
	SharedConnection   bool               `json:"shared_connection,omitempty"`
	DynamicConnection  bool               `json:"dynamic_connection,omitempty"`
	SecurityScanner    bool               `json:"security_scanner,omitempty"`
	TrustedNetwork     bool               `json:"trusted_network,omitempty"`
	Mobile             bool               `json:"mobile,omitempty"`
	FraudScore         int                `json:"fraud_score,omitempty"`
	OperatingSystem    string             `json:"operating_system,omitempty"`
	Browser            string             `json:"browser,omitempty"`
	DeviceModel        string             `json:"device_model,omitempty"`
	DeviceBrand        string             `json:"device_brand,omitempty"`
	TransactionDetails TransactionDetails `json:"transaction_details,omitempty"`
	RequestID          string             `json:"request_id,omitempty"`
}
type TransactionDetails struct {
	ValidBillingAddress       bool     `json:"valid_billing_address,omitempty"`
	ValidShippingAddress      bool     `json:"valid_shipping_address,omitempty"`
	ValidBillingEmail         bool     `json:"valid_billing_email,omitempty"`
	ValidShippingEmail        bool     `json:"valid_shipping_email,omitempty"`
	RiskyBillingPhone         bool     `json:"risky_billing_phone,omitempty"`
	RiskyShippingPhone        bool     `json:"risky_shipping_phone,omitempty"`
	BillingPhoneCarrier       string   `json:"billing_phone_carrier,omitempty"`
	ShippingPhoneCarrier      string   `json:"shipping_phone_carrier,omitempty"`
	BillingPhoneLineType      string   `json:"billing_phone_line_type,omitempty"`
	ShippingPhoneLineType     string   `json:"shipping_phone_line_type,omitempty"`
	BillingPhoneCountry       string   `json:"billing_phone_country,omitempty"`
	BillingPhoneCountryCode   string   `json:"billing_phone_country_code,omitempty"`
	ShippingPhoneCountry      string   `json:"shipping_phone_country,omitempty"`
	ShippingPhoneCountryCode  string   `json:"shipping_phone_country_code,omitempty"`
	FraudulentBehavior        bool     `json:"fraudulent_behavior,omitempty"`
	BinCountry                string   `json:"bin_country,omitempty"`
	BinType                   string   `json:"bin_type,omitempty"`
	BinBankName               string   `json:"bin_bank_name,omitempty"`
	RiskScore                 int      `json:"risk_score,omitempty"`
	RiskFactors               []string `json:"risk_factors,omitempty"`
	IsPrepaidCard             bool     `json:"is_prepaid_card,omitempty"`
	RiskyUsername             bool     `json:"risky_username,omitempty"`
	ValidBillingPhone         bool     `json:"valid_billing_phone,omitempty"`
	ValidShippingPhone        bool     `json:"valid_shipping_phone,omitempty"`
	LeakedBillingEmail        bool     `json:"leaked_billing_email,omitempty"`
	LeakedShippingEmail       bool     `json:"leaked_shipping_email,omitempty"`
	LeakedUserData            bool     `json:"leaked_user_data,omitempty"`
	UserActivity              string   `json:"user_activity,omitempty"`
	PhoneNameIdentityMatch    string   `json:"phone_name_identity_match,omitempty"`
	PhoneEmailIdentityMatch   string   `json:"phone_email_identity_match,omitempty"`
	PhoneAddressIdentityMatch string   `json:"phone_address_identity_match,omitempty"`
	EmailNameIdentityMatch    string   `json:"email_name_identity_match,omitempty"`
	NameAddressIdentityMatch  string   `json:"name_address_identity_match,omitempty"`
	AddressEmailIdentityMatch string   `json:"address_email_identity_match,omitempty"`
}

func loadResponse(c session.Session) (res *HostSearchResult, err error) {
	if c.Providers.IPQS.APIKey == "" {
		return nil, errors.New("IPQS API key not set")
	}

	res = &HostSearchResult{}

	urlPath, err := url.JoinPath(APIURL, c.Providers.IPQS.APIKey, c.Host.String())
	if err != nil {
		return nil, fmt.Errorf("error joining ipqs url path: %w", err)
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		return nil, fmt.Errorf("error parsing ipqs url: %w", err)
	}

	q := sURL.Query()
	q.Add("allow_public_access_points", "true")
	q.Add("fast", "false")
	q.Add("strictness", "0")

	sURL.RawQuery = q.Encode()

	req, err := retryablehttp.NewRequest(http.MethodGet, sURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating ipqs request: %w", err)
	}

	req.Header.Set("User-Agent", providers.DefaultUA)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending ipqs request: %w", err)
	}

	defer resp.Body.Close()

	var apiResp ipqsResp

	if err = json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("error decoding ipqs response: %w", err)
	}

	raw, err := json.Marshal(apiResp)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ipqs response: %w", err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("IPQS response: %s", apiResp.Message)
	}

	res.Raw = raw

	return res, nil
}

func loadResultsFile(path string) (res *HostSearchResult, err error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening ipqs file: %w", err)
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, fmt.Errorf("error decoding ipqs file: %w", err)
	}

	return res, nil
}

func loadTestData(l *slog.Logger) (*HostSearchResult, error) {
	tdf, err := loadResultsFile("providers/ipqs/testdata/ipqs_74_125_219_32_report.json")
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ipqs test data: %w", err)
	}

	tdf.Raw = raw

	l.Info("ipqs match returned from test data", "host", "8.8.4.4")

	return tdf, nil
}

func fetchData(c session.Session) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if c.UseTestData {
		result, err = loadTestData(c.Logger)
		if err != nil {
			return nil, fmt.Errorf("error loading ipqs test data: %w", err)
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
				return nil, fmt.Errorf("error unmarshalling cached ipqs response: %w", err)
			}

			c.Logger.Info("ipqs response found in cache", "host", c.Host.String())

			result.Raw = item.Value

			c.Stats.Mu.Lock()
			c.Stats.FindHostUsedCache[ProviderName] = true
			c.Stats.Mu.Unlock()

			return result, nil
		}
	}

	result, err = loadResponse(c)
	if err != nil {
		return nil, err
	}

	resultTTL := ResultTTL
	if c.Providers.IPQS.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(c.Providers.IPQS.ResultCacheTTL)
	}

	c.Logger.Debug("caching ipqs response", "duration", resultTTL.String())

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching ipqs response: %w", err)
	}

	return result, nil
}

type HostSearchResult struct {
	Raw json.RawMessage `json:"raw,omitempty"`
	ipqsResp
}
