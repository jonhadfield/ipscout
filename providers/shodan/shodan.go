package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/fatih/color"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName           = "shodan"
	APIURL                 = "https://api.shodan.io"
	HostIPPath             = "/shodan/host"
	IndentPipeHyphens      = " |-----"
	portLastModifiedFormat = "2006-01-02T15:04:05.999999"
	ResultTTL              = 12 * time.Hour
	APITimeout             = 10 * time.Second
)

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

type Provider interface {
	LoadData() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}

type ProviderClient struct {
	session.Session
}

func (c *ProviderClient) Enabled() bool {
	switch {
	case c.UseTestData:
		return true
	case c.Providers.Shodan.Enabled != nil && *c.Providers.Shodan.Enabled:
		if c.Providers.Shodan.APIKey != "" {
			return true
		}
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Shodan.OutputPriority
}

func loadAPIResponse(ctx context.Context, c session.Session, apiKey string) (*HostSearchResult, error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath, c.Host.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create shodan api url path: %w", err)
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse shodan api url: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, APITimeout)
	defer cancel()

	q := sURL.Query()
	q.Add("key", apiKey)
	sURL.RawQuery = q.Encode()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, sURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	if resp.StatusCode != http.StatusOK {
		return nil,
			fmt.Errorf("shodan api request failed: %s", resp.Status)
	}

	// read response body
	rBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading shodan response: %w", err)
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
		return nil, fmt.Errorf("shodan: %w", providers.ErrNoMatchFound)
	}

	return res, nil
}

func unmarshalResponse(data []byte) (*HostSearchResult, error) {
	var res HostSearchResult

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling shodan data: %w", err)
	}

	res.Raw = data

	return &res, nil
}

func loadResultsFile(path string) (*HostSearchResult, error) {
	// get raw data
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading shodan file: %w", err)
	}

	// unmarshal data
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening shodan file: %w", err)
	}

	defer jf.Close()

	var res HostSearchResult

	decoder := json.NewDecoder(jf)

	if err = decoder.Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding shodan file: %w", err)
	}

	res.Raw = raw

	return &res, nil
}

func (ssr *HostSearchResult) CreateTable() *table.Writer {
	tw := table.NewWriter()

	return &tw
}

type Client struct {
	Config     Config
	HTTPClient *retryablehttp.Client
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func rateGeolocation(doc HostSearchResult, ratingConfig providers.RatingConfig) providers.RateResult {
	var score float64

	var detected bool

	var reasons []string

	if doc.CountryCode != "" {
		i := slices.Index(ratingConfig.Global.HighThreatCountryCodes, doc.CountryCode)
		if i != -1 {
			detected = true
			score += ratingConfig.ProviderRatingsConfigs.Shodan.HighThreatCountryMatchScore

			reasons = append(reasons, fmt.Sprintf("high Threat Country: %s", doc.CountryCode))
		} else {
			i = slices.Index(ratingConfig.Global.MediumThreatCountryCodes, doc.CountryCode)
			if i != -1 {
				detected = true
				score += ratingConfig.ProviderRatingsConfigs.Shodan.MediumThreatCountryMatchScore

				reasons = append(reasons, fmt.Sprintf("medium Threat Country: %s", doc.CountryCode))
			}
		}
	}

	return providers.RateResult{
		Detected: detected,
		Score:    score,
		Reasons:  reasons,
	}
}

func ratePorts(doc HostSearchResult, ratingConfig providers.RatingConfig) providers.RateResult {
	var score float64

	var detected bool

	var reasons []string

	if len(doc.Ports) > 0 {
		return providers.RateResult{
			Detected: true,
			Score:    ratingConfig.ProviderRatingsConfigs.Shodan.OpenPortsScore,
			Reasons:  []string{"has open ports"},
		}
	}

	return providers.RateResult{
		Detected: detected,
		Score:    score,
		Reasons:  reasons,
	}
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	threatIndicators := providers.ThreatIndicators{
		Provider: ProviderName,
	}

	indicators := make(map[string]string)

	indicators["ExposedPorts"] = strconv.Itoa(len(doc.Ports))

	threatIndicators.Indicators = indicators

	return &threatIndicators, nil
}

func (c *ProviderClient) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var doc HostSearchResult

	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	geoResult := rateGeolocation(doc, ratingConfig)
	portsResult := ratePorts(doc, ratingConfig)

	reasons := geoResult.Reasons
	reasons = append(reasons, portsResult.Reasons...)

	score := geoResult.Score

	if portsResult.Score > score {
		score = portsResult.Score
	}

	return providers.RateResult{
		Detected: score > 0,
		Score:    score,
		Reasons:  reasons,
	}, nil
}

func fetchData(c session.Session) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if c.UseTestData {
		result, err = loadResultsFile("providers/shodan/testdata/shodan_google_dns_resp.json")
		if err != nil {
			return nil, fmt.Errorf("error loading shodan test data: %w", err)
		}

		return result, nil
	}

	// load data from cache
	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + strings.ReplaceAll(c.Host.String(), ".", "_")

	var item *cache.Item

	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		if item != nil && len(item.Value) > 0 {
			result, err = unmarshalResponse(item.Value)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling cached shodan response: %w", err)
			}

			c.Logger.Info("shodan response found in cache", "host", c.Host.String())

			result.Raw = item.Value

			c.Stats.Mu.Lock()
			c.Stats.FindHostUsedCache[ProviderName] = true
			c.Stats.Mu.Unlock()

			return result, nil
		}
	}

	result, err = loadAPIResponse(context.Background(), c, c.Providers.Shodan.APIKey)
	if err != nil {
		return nil, fmt.Errorf("loading shodan api response: %w", err)
	}

	resultTTL := ResultTTL
	if c.Providers.Shodan.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(c.Providers.Shodan.ResultCacheTTL)
	}

	c.Logger.Debug("caching shodan response", "duration", resultTTL.String())

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching shodan response: %w", err)
	}

	return result, nil
}

func (c *ProviderClient) Initialise() error {
	c.Logger.Info("Initialising cache:", "provider", ProviderName, "host", c.Host.String(), "cache", c.Cache == nil)

	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	if c.Host == (netip.Addr{}) {
		return fmt.Errorf("shodan provider requires a host to be set")
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising shodan client")

	return nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("shodan host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func countFilteredPorts(in []HostSearchResultData, ports []string, maxAge string) (int, error) {
	var filteredPorts int

	for _, dr := range in {
		var ok bool

		_, ok, err := providers.PortMatchFilter(providers.PortMatchFilterInput{
			IncomingPort:        fmt.Sprintf("%d/%s", dr.Port, dr.Transport),
			MatchPorts:          ports,
			ConfirmedDate:       dr.Timestamp,
			ConfirmedDateFormat: portLastModifiedFormat,
			MaxAge:              maxAge,
		})
		if err != nil {
			return 0, fmt.Errorf("error checking port match filter: %w", err)
		}

		if !ok {
			filteredPorts++

			continue
		}
	}

	return filteredPorts, nil
}

func appendSSHRows(ssh SSH, globalIndentSpaces int, tw *table.Writer) {
	if ssh.Type != "" {
		twc := *tw

		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s  SSH",
				IndentPipeHyphens),
		})
		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s%sType: %s",
				IndentPipeHyphens, strings.Repeat(" ", providers.IndentSpaces*globalIndentSpaces), ssh.Type),
		})
		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s%sCipher: %s",
				IndentPipeHyphens, strings.Repeat(" ", providers.IndentSpaces*globalIndentSpaces), ssh.Cipher),
		})
	}
}

func appendHTTPRows(c *ProviderClient, http HTTP, tw *table.Writer) {
	if http.Status != 0 {
		twc := *tw
		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s  HTTP",
				IndentPipeHyphens),
		})

		if http.Location != "" {
			twc.AppendRow(table.Row{
				"",
				fmt.Sprintf("%s%sLocation: %s",
					IndentPipeHyphens,
					strings.Repeat(" ", providers.IndentSpaces*c.Config.Global.IndentSpaces), http.Location),
			})
		}

		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s%sStatus: %d",
				IndentPipeHyphens,
				strings.Repeat(" ", providers.IndentSpaces*c.Config.Global.IndentSpaces), http.Status),
		})

		if http.Title != "" {
			twc.AppendRow(table.Row{
				"",
				fmt.Sprintf("%s%sTitle: %s",
					IndentPipeHyphens, strings.Repeat(" ", providers.IndentSpaces*c.Config.Global.IndentSpaces), http.Title),
			})
		}

		if http.Server != "" {
			twc.AppendRow(table.Row{
				"",
				fmt.Sprintf("%s%sServer: %s",
					IndentPipeHyphens, strings.Repeat(" ", providers.IndentSpaces*c.Config.Global.IndentSpaces), http.Server),
			})
		}

		if http.HTML != "" {
			http.HTML = strings.TrimSuffix(http.HTML, "\n")
			twc.AppendRow(table.Row{
				"",
				fmt.Sprintf("%s%sHTML: %s",
					IndentPipeHyphens,
					strings.Repeat(" ", providers.IndentSpaces*c.Config.Global.IndentSpaces),
					providers.PreProcessValueOutput(&c.Session, http.HTML)),
			})
		}
	}
}

func appendDNSRows(dns DNS, globalIndentSpaces int, tw *table.Writer) {
	if dns.ResolverHostname != nil {
		twc := *tw
		twc.AppendRow(table.Row{"", fmt.Sprintf("%s  DNS", IndentPipeHyphens)})

		if dns.ResolverHostname != "" {
			twc.AppendRow(table.Row{
				"",
				fmt.Sprintf("%s%sResolver Hostname: %s",
					IndentPipeHyphens,
					strings.Repeat(" ", providers.IndentSpaces*globalIndentSpaces), dns.ResolverHostname),
			})
		}

		if dns.Software != nil {
			twc.AppendRow(table.Row{
				"",
				fmt.Sprintf("%s%sResolver Software: %s",
					IndentPipeHyphens,
					strings.Repeat(" ", providers.IndentSpaces*globalIndentSpaces), dns.Software),
			})
		}

		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s%sRecursive: %t", IndentPipeHyphens,
				strings.Repeat(" ", providers.IndentSpaces*globalIndentSpaces), dns.Recursive),
		})
	}
}

func appendSSLRows(ssl Ssl, globalIndentSpaces int, rowEmphasisColor func(format string, a ...interface{}) string, tw *table.Writer) {
	if len(ssl.Versions) > 0 {
		twc := *tw

		twc.AppendRow(table.Row{"", rowEmphasisColor("SSL")})
		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s%sIssuer: %s", IndentPipeHyphens,
				strings.Repeat(" ", providers.IndentSpaces*globalIndentSpaces), ssl.Cert.Issuer.Cn),
		})
		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s%sSubject: %s",
				IndentPipeHyphens, strings.Repeat(" ", providers.IndentSpaces*globalIndentSpaces),
				ssl.Cert.Subject.Cn),
		})
		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s%sVersions: %s",
				IndentPipeHyphens, strings.Repeat(" ",
					providers.IndentSpaces*globalIndentSpaces), strings.Join(ssl.Versions, ", ")),
		})
		twc.AppendRow(table.Row{
			"",
			fmt.Sprintf("%s%sExpires: %s",
				IndentPipeHyphens,
				strings.Repeat(" ", providers.IndentSpaces*globalIndentSpaces),
				ssl.Cert.Expires),
		})
	}
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	var result *HostSearchResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("error unmarshalling shodan data: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	tw := table.NewWriter()
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	rowEmphasisColor := providers.RowEmphasisColor(c.Session)

	var rows []table.Row

	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("WHOIS", providers.Column1MinWidth), providers.FormatTimeOrDash(result.LastUpdate, portLastModifiedFormat)})
	tw.AppendRow(table.Row{" - Org", providers.DashIfEmpty(result.Org)})
	tw.AppendRow(table.Row{
		" - Country",
		fmt.Sprintf("%s (%s)", providers.DashIfEmpty(result.CountryName),
			providers.DashIfEmpty(strings.ToUpper(result.CountryCode))),
	})
	tw.AppendRow(table.Row{" - Region", providers.DashIfEmpty(result.RegionCode)})
	tw.AppendRow(table.Row{" - City", providers.DashIfEmpty(result.City)})

	var portsDisplayed int

	filteredPorts, err := countFilteredPorts(result.Data, c.Config.Global.Ports, c.Config.Global.MaxAge)
	if err != nil {
		return nil, fmt.Errorf("error counting filtered ports: %w", err)
	}

	if filteredPorts > 0 {
		tw.AppendRow(table.Row{"Ports", fmt.Sprintf("%d (%d filtered)", len(result.Data), filteredPorts)})
	} else {
		tw.AppendRow(table.Row{"Ports", len(result.Data)})
	}

	if len(result.Data) > 0 { //nolint:nestif
		for _, dr := range result.Data {
			_, ok, err := providers.PortMatchFilter(providers.PortMatchFilterInput{
				IncomingPort:        fmt.Sprintf("%d/%s", dr.Port, dr.Transport),
				MatchPorts:          c.Config.Global.Ports,
				ConfirmedDate:       dr.Timestamp,
				ConfirmedDateFormat: portLastModifiedFormat,
				MaxAge:              c.Config.Global.MaxAge,
			})
			if err != nil {
				return nil, fmt.Errorf("error checking port match filter: %w", err)
			}

			if !ok {
				filteredPorts++

				continue
			}

			tw.AppendRow(table.Row{"", rowEmphasisColor(fmt.Sprintf("%d/%s", dr.Port, dr.Transport))})

			if len(dr.Domains) > 0 {
				tw.AppendRow(table.Row{
					"",
					fmt.Sprintf("%s  Domains: %s",
						IndentPipeHyphens, strings.Join(dr.Domains, ", ")),
				})
			}

			if dr.Timestamp != "" {
				tw.AppendRow(table.Row{
					"",
					fmt.Sprintf("%s  Timestamp: %s",
						IndentPipeHyphens, providers.FormatTimeOrDash(dr.Timestamp, portLastModifiedFormat)),
				})
			}

			if len(dr.Hostnames) > 0 {
				tw.AppendRow(table.Row{
					"",
					fmt.Sprintf("%s  HostNames: %s",
						IndentPipeHyphens, strings.Join(dr.Hostnames, ", ")),
				})
			}

			appendSSHRows(dr.SSH, c.Config.Global.IndentSpaces, &tw)
			appendHTTPRows(c, dr.HTTP, &tw)
			appendSSLRows(dr.Ssl, c.Config.Global.IndentSpaces, rowEmphasisColor, &tw)
			appendDNSRows(dr.DNS, c.Config.Global.IndentSpaces, &tw)

			portsDisplayed++

			if portsDisplayed == c.Config.Global.MaxReports {
				tw.AppendRow(table.Row{"", color.YellowString("--- Max reports reached ---")})

				break
			}
		}

		tw.AppendRows(rows)

		tw.SetColumnConfigs([]table.ColumnConfig{
			{Number: providers.DataColumnNo, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
		})
	}

	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("SHODAN | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("SHODAN | Host: %s", result.Data[0].IPStr)
	}

	c.Logger.Debug("shodan table created", "host", c.Host.String())

	return &tw, nil
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating shodan client")

	tc := &ProviderClient{
		c,
	}

	return tc, nil
}

func (c *Client) GetConfig() *session.Session {
	return &c.Config.Session
}

func (c *Client) GetData() (*HostSearchResult, error) {
	resultsFile, err := helpers.PrefixProjectRoot("shodan/testdata/shodan_google_dns_resp.json")
	if err != nil {
		return nil, fmt.Errorf("error getting shodan test data file path: %w", err)
	}

	result, err := loadResultsFile(resultsFile)
	if err != nil {
		return nil, err
	}

	return result, nil
}

type HostSearchResultData struct {
	Hash      int      `json:"hash"`
	Opts      struct{} `json:"opts,omitempty"`
	Timestamp string   `json:"timestamp"`
	Isp       string   `json:"isp"`
	Data      string   `json:"data"`
	Shodan    struct {
		Region  string   `json:"region"`
		Module  string   `json:"module"`
		Ptr     bool     `json:"ptr"`
		Options struct{} `json:"options"`
		ID      string   `json:"id"`
		Crawler string   `json:"crawler"`
	} `json:"_shodan,omitempty"`
	Port      int      `json:"port"`
	Hostnames []string `json:"hostnames"`
	Location  struct {
		City        string  `json:"city"`
		RegionCode  string  `json:"region_code"`
		AreaCode    any     `json:"area_code"`
		Longitude   float64 `json:"longitude"`
		CountryName string  `json:"country_name"`
		CountryCode string  `json:"country_code"`
		Latitude    float64 `json:"latitude"`
	} `json:"location"`
	DNS       DNS      `json:"dns,omitempty"`
	SSH       SSH      `json:"ssh"`
	HTTP      HTTP     `json:"http,omitempty"`
	IP        int      `json:"ip"`
	Domains   []string `json:"domains"`
	Org       string   `json:"org"`
	Os        any      `json:"os"`
	Asn       string   `json:"asn"`
	Transport string   `json:"transport"`
	IPStr     string   `json:"ip_str"`
	Ssl       Ssl      `json:"ssl,omitempty"`
}

type DNS struct {
	ResolverHostname any  `json:"resolver_hostname"`
	Recursive        bool `json:"recursive"`
	ResolverID       any  `json:"resolver_id"`
	Software         any  `json:"software"`
}

type HTTP struct {
	Status     int `json:"status"`
	RobotsHash int `json:"robots_hash"`
	Redirects  []struct {
		Host     string `json:"host"`
		Data     string `json:"data"`
		Location string `json:"location"`
	}
	SecurityTxt string `json:"security_txt"`
	Title       string `json:"title"`
	SitemapHash int    `json:"sitemap_hash"`
	HTMLHash    int    `json:"html_hash"`
	Robots      string `json:"robots"`
	Favicon     struct {
		Hash     int    `json:"hash"`
		Data     string `json:"data"`
		Location string `json:"location"`
	} `json:"favicon"`
	HeadersHash     int      `json:"headers_hash"`
	Host            string   `json:"host"`
	HTML            string   `json:"html"`
	Location        string   `json:"location"`
	Components      struct{} `json:"components"`
	Server          string   `json:"server"`
	Sitemap         string   `json:"sitemap"`
	SecurityTxtHash int      `json:"securitytxt_hash"`
}

type SSH struct {
	Hassh       string `json:"hassh"`
	Fingerprint string `json:"fingerprint"`
	Mac         string `json:"mac"`
	Cipher      string `json:"cipher"`
	Key         string `json:"key"`
	Kex         struct {
		Languages               []string `json:"languages"`
		ServerHostKeyAlgorithms []string `json:"server_host_key_algorithms"`
		EncryptionAlgorithms    []string `json:"encryption_algorithms"`
		KexFollows              bool     `json:"kex_follows"`
		Unused                  int      `json:"unused"`
		KexAlgorithms           []string `json:"kex_algorithms"`
		CompressionAlgorithms   []string `json:"compression_algorithms"`
		MacAlgorithms           []string `json:"mac_algorithms"`
	} `json:"kex"`
	Type string `json:"type"`
}

type Ssl struct {
	ChainSha256   []string `json:"chain_sha256"`
	Jarm          string   `json:"jarm"`
	Chain         []string `json:"chain"`
	Dhparams      any      `json:"dhparams"`
	Versions      []string `json:"versions"`
	AcceptableCas []any    `json:"acceptable_cas"`
	Tlsext        []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"tlsext"`
	Ja3S string `json:"ja3s"`
	Cert struct {
		SigAlg     string `json:"sig_alg"`
		Issued     string `json:"issued"`
		Expires    string `json:"expires"`
		Expired    bool   `json:"expired"`
		Version    int    `json:"version"`
		Extensions []struct {
			Critical bool   `json:"critical,omitempty"`
			Data     string `json:"data"`
			Name     string `json:"name"`
		} `json:"extensions"`
		Fingerprint struct {
			Sha256 string `json:"sha256"`
			Sha1   string `json:"sha1"`
		} `json:"fingerprint"`
		Serial  json.RawMessage `json:"serial"`
		Subject struct {
			Cn string `json:"CN"`
		} `json:"subject"`
		Pubkey struct {
			Type string `json:"type"`
			Bits int    `json:"bits"`
		} `json:"pubkey"`
		Issuer struct {
			C  string `json:"C"`
			Cn string `json:"CN"`
			O  string `json:"O"`
		} `json:"issuer"`
	} `json:"cert"`
	Cipher struct {
		Version string `json:"version"`
		Bits    int    `json:"bits"`
		Name    string `json:"name"`
	} `json:"cipher"`
	Trust struct {
		Revoked bool `json:"revoked"`
		Browser any  `json:"browser"`
	} `json:"trust"`
	HandshakeStates []string `json:"handshake_states"`
	Alpn            []any    `json:"alpn"`
	Ocsp            struct{} `json:"ocsp"`
}

type HostSearchResult struct {
	Raw         []byte   `json:"raw"`
	City        string   `json:"city"`
	RegionCode  string   `json:"region_code"`
	Os          any      `json:"os"`
	Tags        []any    `json:"tags"`
	IP          int      `json:"ip"`
	Isp         string   `json:"isp"`
	AreaCode    any      `json:"area_code"`
	Longitude   float64  `json:"longitude"`
	LastUpdate  string   `json:"last_update"`
	Ports       []int    `json:"ports"`
	Latitude    float64  `json:"latitude"`
	Hostnames   []string `json:"hostnames"`
	CountryCode string   `json:"country_code"`
	CountryName string   `json:"country_name"`
	Domains     []string `json:"domains"`
	Org         string   `json:"org"`
	Data        []HostSearchResultData
	Asn         string `json:"asn"`
	IPStr       string `json:"ip_str"`
	Error       string `json:"error"`
}
