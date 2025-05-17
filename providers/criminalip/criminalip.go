package criminalip

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
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName      = "criminalip"
	APIURL            = "https://api.criminalip.io"
	HostIPPath        = "/v1/asset/ip/report"
	IndentPipeHyphens = " |-----"
	ResultTTL         = 24 * time.Hour
	APITimeout        = 30 * time.Second
	dataColumnNo      = 2
)

type Client struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating criminalip client")

	tc := &Client{
		Session: c,
	}

	return tc, nil
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
}

func (c *Client) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	return nil, nil
}

func (c *Client) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var doc HostSearchResult

	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf("error unmarshalling rating config: %w", err)
	}

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf("error unmarshalling find result: %w", err)
	}

	var reasons []string

	var detected bool

	var score float64

	if len(doc.Honeypot.Data) > 0 {
		detected = true

		providers.UpdateScoreIfLarger(&score, ratingConfig.ProviderRatingsConfigs.CriminalIP.HoneypotAttackedScore)

		reasons = append(reasons, "honeypot attacked")
	}

	if doc.Issues.IsScanner {
		detected = true

		providers.UpdateScoreIfLarger(&score, ratingConfig.ProviderRatingsConfigs.CriminalIP.ScannerMatchScore)

		reasons = append(reasons, "scanner")
	}

	if doc.Issues.IsVpn {
		detected = true

		providers.UpdateScoreIfLarger(&score, ratingConfig.ProviderRatingsConfigs.CriminalIP.VPNMatchScore)

		reasons = append(reasons, "VPN")
	}

	if doc.Issues.IsCloud {
		detected = true

		providers.UpdateScoreIfLarger(&score, ratingConfig.ProviderRatingsConfigs.CriminalIP.CloudMatchScore)

		reasons = append(reasons, "cloud")
	}

	if doc.Issues.IsTor {
		detected = true

		providers.UpdateScoreIfLarger(&score, ratingConfig.ProviderRatingsConfigs.CriminalIP.TORMatchScore)

		reasons = append(reasons, "TOR")
	}

	if doc.Issues.IsProxy {
		detected = true

		providers.UpdateScoreIfLarger(&score, ratingConfig.ProviderRatingsConfigs.CriminalIP.ProxyMatchScore)

		reasons = append(reasons, "proxy")
	}

	if doc.Issues.IsHosting {
		detected = true

		providers.UpdateScoreIfLarger(&score, ratingConfig.ProviderRatingsConfigs.CriminalIP.HostingMatchScore)

		reasons = append(reasons, "hosting")
	}
	// if doc.Issues.IsMobile {
	// 	detected = true
	// 	providers.UpdateScoreIfLarger(&score, 9)
	// 	reasons = append(reasons, "Mobile")
	// }
	if doc.Issues.IsDarkweb {
		detected = true

		providers.UpdateScoreIfLarger(&score, ratingConfig.ProviderRatingsConfigs.CriminalIP.DarkwebMatchScore)

		reasons = append(reasons, "darkweb")
	}

	return providers.RateResult{
		Detected: detected,
		Score:    score,
		Reasons:  reasons,
	}, nil
}

func (c *Client) Enabled() bool {
	cip := c.Providers.CriminalIP
	if c.UseTestData || (cip.APIKey != "" && cip.Enabled != nil && *cip.Enabled) {
		return true
	}

	return false
}

func (c *Client) Priority() *int32 {
	return c.Providers.CriminalIP.OutputPriority
}

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

func loadAPIResponse(ctx context.Context, conf *session.Session, apiKey string) (res *HostSearchResult, err error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath)
	if err != nil {
		return nil, fmt.Errorf("error joining criminal ip api url: %w", err)
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		return nil, fmt.Errorf("error parsing criminal ip api url: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, APITimeout)
	defer cancel()

	q := sURL.Query()
	q.Add("ip", conf.Host.String())
	sURL.RawQuery = q.Encode()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, sURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating criminal ip request: %w", err)
	}

	conf.HTTPClient.HTTPClient.Timeout = APITimeout

	req.Header.Add("x-api-key", apiKey) //nolint:canonicalheader

	resp, err := conf.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending criminal ip request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s request failed: %s", ProviderName, resp.Status)
	}

	// read response body
	rBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading criminal ip response body: %w", err)
	}

	defer resp.Body.Close()

	res, err = unmarshalResponse(rBody)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling criminal ip response: %w", err)
	}

	// check if response contains an error, despite a 200 status code
	if res.Status == http.StatusForbidden {
		return nil, fmt.Errorf("criminal ip api error: %s: %w", res.Message, providers.ErrForbiddenByProvider)
	}

	res.Raw = rBody

	return res, nil
}

func unmarshalResponse(rBody []byte) (*HostSearchResult, error) {
	var res *HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling criminal ip response: %w", err)
	}

	return res, nil
}

func loadTestData(c *Client) ([]byte, error) {
	tdf, err := loadResultsFile("providers/criminalip/testdata/criminalip_9_9_9_9_report.json")
	if err != nil {
		return nil, err
	}

	c.Logger.Info("criminalip match returned from test data", "host", "9.9.9.9")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

func fetchData(client session.Session) (*HostSearchResult, error) {
	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + strings.ReplaceAll(client.Host.String(), ".", "_")
	if item, err := cache.Read(client.Logger, client.Cache, cacheKey); err == nil {
		if item != nil {
			result, uErr := unmarshalResponse(item.Value)
			if uErr != nil {
				return nil, uErr
			}

			client.Logger.Info("criminal ip response found in cache", "host", client.Host.String())

			result.Raw = item.Value

			client.Stats.Mu.Lock()
			client.Stats.FindHostUsedCache[ProviderName] = true
			client.Stats.Mu.Unlock()

			return result, nil
		}
	}

	result, err := loadAPIResponse(context.Background(), &client, client.Providers.CriminalIP.APIKey)
	if err != nil {
		client.Messages.AddError(err.Error())

		return nil, err
	}

	resultTTL := ResultTTL
	if client.Providers.CriminalIP.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(client.Providers.CriminalIP.ResultCacheTTL)
	}

	client.Logger.Debug("caching criminal ip response", "duration", resultTTL.String())

	if err = cache.UpsertWithTTL(client.Logger, client.Cache, cache.Item{
		AppVersion: client.App.Version,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching criminal ip response: %w", err)
	}

	return result, nil
}

func tidyBanner(banner string) string {
	// remove empty lines using regex match
	var lines []string

	r := regexp.MustCompile(`^(\s*$|$)`)
	for x, line := range strings.Split(banner, "\n") {
		if r.MatchString(line) {
			continue
		}

		if x > 0 {
			line = strings.TrimSpace(line)
			line = fmt.Sprintf("%s %s", strings.Repeat(" ", len(IndentPipeHyphens)+1), line)
		}

		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

func getDomains(domain HostSearchResultDomain) []string {
	var domains []string

	for _, d := range domain.Data {
		domains = append(domains, d.Domain)
	}

	return domains
}

func (c *Client) Initialise() error {
	if c.Cache == nil {
		return errors.New("cache not set")
	}

	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	c.Logger.Debug("initialising criminalip client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking criminalip cache: %w", err)
	}

	if ok {
		c.Logger.Info("criminalip provider data found in cache")

		return nil
	}

	return nil
}

func (c *Client) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	if c.UseTestData {
		return loadTestData(c)
	}

	if c.Host.Is6() {
		return nil, fmt.Errorf("ipv6 not supported by criminalip: %w", providers.ErrNoMatchFound)
	}

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	return result.Raw, nil
}

type GeneratePortDataForTableInput struct{}

type GeneratePortDataForTableOutput struct {
	entries []WrappedPortDataEntry
	skips   int
	matches int
}

func (c *Client) GenPortDataForTable(in []PortDataEntry) (GeneratePortDataForTableOutput, error) {
	var err error

	var out GeneratePortDataForTableOutput

	out.entries = make([]WrappedPortDataEntry, len(in))

	for _, entry := range in {
		var ageMatch, netMatch bool

		ageMatch, netMatch, err = providers.PortMatchFilter(providers.PortMatchFilterInput{
			IncomingPort:        fmt.Sprintf("%d/%s", entry.OpenPortNo, entry.Socket),
			MatchPorts:          c.Config.Global.Ports,
			ConfirmedDate:       entry.ConfirmedTime,
			ConfirmedDateFormat: time.DateTime,
			MaxAge:              c.Config.Global.MaxAge,
		})
		if err != nil {
			return GeneratePortDataForTableOutput{}, fmt.Errorf("error checking port match filter: %w", err)
		}

		wrappedEntry := WrappedPortDataEntry{
			AgeMatch:      ageMatch,
			NetworkMatch:  netMatch,
			PortDataEntry: entry,
		}

		out.entries = append(out.entries, wrappedEntry)

		if ageMatch && netMatch {
			out.matches++
		} else {
			out.skips++
		}
	}

	return out, nil
}

func GenIssuesOutputForTable(in Issues) string {
	var matchedIssues []string

	if in.IsScanner {
		matchedIssues = append(matchedIssues, "scanner")
	}

	if in.IsVpn {
		matchedIssues = append(matchedIssues, "VPN")
	}

	if in.IsCloud {
		matchedIssues = append(matchedIssues, "cloud")
	}

	if in.IsTor {
		matchedIssues = append(matchedIssues, "TOR")
	}

	if in.IsProxy {
		matchedIssues = append(matchedIssues, "proxy")
	}

	if in.IsHosting {
		matchedIssues = append(matchedIssues, "hosting")
	}

	if in.IsMobile {
		matchedIssues = append(matchedIssues, "mobile")
	}

	if in.IsDarkweb {
		matchedIssues = append(matchedIssues, "darkweb")
	}

	output := "none"

	if len(matchedIssues) > 0 {
		output = strings.Join(matchedIssues, ", ")
	}

	return output
}

func (c *Client) CreateTable(data []byte) (*table.Writer, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	result, err := unmarshalResponse(data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling criminalip api response: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	tw := table.NewWriter()
	// tw.SetStyle(myInnerStyle)
	var rows []table.Row

	if result.Whois.Count > 0 {
		for _, whois := range result.Whois.Data {
			tw.AppendRow(table.Row{"WHOIS", providers.DashIfEmpty(whois.ConfirmedTime)})
			tw.AppendRow(table.Row{" - Org", providers.DashIfEmpty(whois.OrgName)})
			tw.AppendRow(table.Row{" - Country", providers.DashIfEmpty(strings.ToUpper(whois.OrgCountryCode))})
			tw.AppendRow(table.Row{" - Region", providers.DashIfEmpty(whois.Region)})
			tw.AppendRow(table.Row{" - City", providers.DashIfEmpty(whois.City)})
		}
	}

	if domains := getDomains(result.Domain); domains != nil {
		tw.AppendRow(table.Row{"Domains", strings.Join(getDomains(result.Domain), ", ")})
	}

	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Score Inbound", providers.Column1MinWidth), result.Score.Inbound})
	tw.AppendRow(table.Row{"Score Outbound", result.Score.Outbound})

	portDataForTable, err := c.GenPortDataForTable(result.Port.Data)
	if err != nil {
		return nil, fmt.Errorf("error generating port data for table: %w", err)
	}

	tw.AppendRow(table.Row{"Issues", GenIssuesOutputForTable(result.Issues)})

	if portDataForTable.skips > 0 {
		tw.AppendRow(table.Row{"Ports", fmt.Sprintf("%d (%d filtered)", len(result.Port.Data), portDataForTable.skips)})
	} else {
		tw.AppendRow(table.Row{"Ports", len(result.Port.Data)})
	}

	var portsDisplayed int

	for x, port := range portDataForTable.entries {
		if !port.AgeMatch || !port.NetworkMatch {
			continue
		}

		tw.AppendRow(table.Row{"", color.CyanString("%d/%s", port.OpenPortNo, port.Socket)})
		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Protocol: %s", IndentPipeHyphens, providers.DashIfEmpty(port.Protocol))})
		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Confirmed Time: %s", IndentPipeHyphens, port.ConfirmedTime)})

		// vary output based on protocol
		switch strings.ToLower(port.Protocol) {
		case "https":
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  SDN Common Name: %s", IndentPipeHyphens, port.SdnCommonName)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  DNS Names: %s", IndentPipeHyphens, providers.PreProcessValueOutput(&c.Session, port.DNSNames))})
		case "dns":
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  App Name (Version): %s (%s)", IndentPipeHyphens, port.AppName, port.AppVersion)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Banner: %s",
				IndentPipeHyphens, tidyBanner(providers.PreProcessValueOutput(&c.Session, port.Banner)))})
		default:
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  App Name (Version): %s (%s)", IndentPipeHyphens, port.AppName, port.AppVersion)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Banner: %s",
				IndentPipeHyphens, tidyBanner(providers.PreProcessValueOutput(&c.Session, port.Banner)))})
		}

		// always include if detected as vulnerability
		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Is Vulnerability: %t", IndentPipeHyphens, port.IsVulnerability)})

		if x+1 < len(result.Port.Data) {
			// add a blank row between ports
			tw.AppendRow(table.Row{"", ""})
		}

		portsDisplayed++

		if portsDisplayed == c.Config.Global.MaxReports {
			tw.AppendRow(table.Row{"", color.YellowString("--- Max reports reached ---")})

			break
		}
	}

	tw.AppendRow(table.Row{"Honeypot Hits", result.Honeypot.Count})

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: dataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("CRIMINAL IP | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("CRIMINAL IP | Host: %s", result.IP)
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
		return res, fmt.Errorf("error decoding criminalip data: %w", err)
	}

	return res, nil
}

type HostSearchResultData struct {
	Hash       int      `json:"hash"`
	Opts       struct{} `json:"opts,omitempty"`
	Timestamp  string   `json:"timestamp"`
	Isp        string   `json:"isp"`
	Data       string   `json:"data"`
	CriminalIP struct {
		Region  string   `json:"region"`
		Module  string   `json:"module"`
		Ptr     bool     `json:"ptr"`
		Options struct{} `json:"options"`
		ID      string   `json:"id"`
		Crawler string   `json:"crawler"`
	} `json:"_criminalip,omitempty"`
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
	DNS struct {
		ResolverHostname any  `json:"resolver_hostname"`
		Recursive        bool `json:"recursive"`
		ResolverID       any  `json:"resolver_id"`
		Software         any  `json:"software"`
	} `json:"dns,omitempty"`
	HTTP struct {
		Status     int    `json:"status"`
		RobotsHash string `json:"robots_hash"`
		Redirects  []struct {
			Host     string `json:"host"`
			Data     string `json:"data"`
			Location string `json:"location"`
		}
		SecurityTxt string `json:"security_txt"`
		Title       string `json:"title"`
		SitemapHash string `json:"sitemap_hash"`
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
		SecurityTxtHash string   `json:"securitytxt_hash"`
	} `json:"http,omitempty"`
	IP        string   `json:"ip"`
	Domains   []string `json:"domains"`
	Org       string   `json:"org"`
	Os        any      `json:"os"`
	Asn       string   `json:"asn"`
	Transport string   `json:"transport"`
	IPStr     string   `json:"ip_str"`
	Ssl       struct {
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
	} `json:"ssl,omitempty"`
}

type HostSearchResultDomain struct {
	Count int `json:"count"`
	Data  []struct {
		Domain        string `json:"domain"`
		IPType        string `json:"ip_type"`
		Registrar     string `json:"registrar"`
		CreateDate    string `json:"create_date"`
		ConfirmedTime string `json:"confirmed_time"`
		Email         string `json:"email"`
	} `json:"data"`
}

type WrappedPortDataEntry struct {
	AgeMatch     bool
	NetworkMatch bool
	PortDataEntry
}

type PortDataEntry struct {
	AppName       string   `json:"app_name"`
	ConfirmedTime string   `json:"confirmed_time"`
	Banner        string   `json:"banner"`
	AppVersion    string   `json:"app_version"`
	OpenPortNo    int      `json:"open_port_no"`
	PortStatus    string   `json:"port_status"`
	Protocol      string   `json:"protocol"`
	Socket        string   `json:"socket"`
	Tags          []string `json:"tags"`
	DNSNames      string   `json:"dns_names"`
	SdnCommonName string   `json:"sdn_common_name"`
	JarmHash      string   `json:"jarm_hash"`
	SslInfoRaw    string   `json:"ssl_info_raw"`
	Technologies  []struct {
		TechName    string `json:"tech_name"`
		TechVersion string `json:"tech_version"`
		TechLogoURL string `json:"tech_logo_url"`
	} `json:"technologies"`
	IsVulnerability bool `json:"is_vulnerability"`
}

type HoneypotDataEntry struct {
	IPAddress     string `json:"ip_address"`
	LogDate       string `json:"log_date"`
	DstPort       int    `json:"dst_port"`
	Message       string `json:"message"`
	UserAgent     string `json:"user_agent"`
	ProtocolType  string `json:"protocol_type"`
	ConfirmedTime string `json:"confirmed_time"`
}

type Issues struct {
	IsVpn          bool `json:"is_vpn"`
	IsCloud        bool `json:"is_cloud"`
	IsTor          bool `json:"is_tor"`
	IsProxy        bool `json:"is_proxy"`
	IsHosting      bool `json:"is_hosting"`
	IsMobile       bool `json:"is_mobile"`
	IsDarkweb      bool `json:"is_darkweb"`
	IsScanner      bool `json:"is_scanner"`
	IsSnort        bool `json:"is_snort"`
	IsAnonymousVpn bool `json:"is_anonymous_vpn"`
}

type HostSearchResult struct {
	Raw    []byte
	IP     string `json:"ip"`
	Issues Issues `json:"issues"`
	Score  struct {
		Inbound  string `json:"inbound"`
		Outbound string `json:"outbound"`
	} `json:"score"`
	UserSearchCount int `json:"user_search_count"`
	ProtectedIP     struct {
		Count int `json:"count"`
		Data  []struct {
			IPAddress     string `json:"ip_address"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"protected_ip"`
	Domain HostSearchResultDomain `json:"domain"`
	Whois  struct {
		Count int `json:"count"`
		Data  []struct {
			AsName         string  `json:"as_name"`
			AsNo           int     `json:"as_no"`
			City           string  `json:"city"`
			Region         string  `json:"region"`
			OrgName        string  `json:"org_name"`
			PostalCode     string  `json:"postal_code"`
			Longitude      float64 `json:"longitude"`
			Latitude       float64 `json:"latitude"`
			OrgCountryCode string  `json:"org_country_code"`
			ConfirmedTime  string  `json:"confirmed_time"`
		} `json:"data"`
	} `json:"ipapi"`
	Hostname struct {
		Count int `json:"count"`
		Data  []struct {
			DomainNameRep  string `json:"domain_name_rep"`
			DomainNameFull string `json:"domain_name_full"`
			ConfirmedTime  string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"hostname"`
	IDs struct {
		Count int `json:"count"`
		Data  []struct {
			Classification string `json:"classification"`
			URL            string `json:"url"`
			Message        string `json:"message"`
			ConfirmedTime  string `json:"confirmed_time"`
			SourceSystem   string `json:"source_system"`
		} `json:"data"`
	} `json:"ids"`
	Vpn struct {
		Count int `json:"count"`
		Data  []struct {
			VpnName       string `json:"vpn_name"`
			VpnURL        string `json:"vpn_url"`
			VpnSourceURL  string `json:"vpn_source_url"`
			SocketType    string `json:"socket_type"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"vpn"`
	AnonymousVpn struct {
		Count int `json:"count"`
		Data  []struct {
			VpnName       string `json:"vpn_name"`
			VpnURL        string `json:"vpn_url"`
			VpnSourceURL  string `json:"vpn_source_url"`
			SocketType    string `json:"socket_type"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"anonymous_vpn"`
	Webcam struct {
		Count int `json:"count"`
		Data  []struct {
			ImagePath     string `json:"image_path"`
			CamURL        string `json:"cam_url"`
			Country       string `json:"country"`
			City          string `json:"city"`
			OpenPortNo    int    `json:"open_port_no"`
			Manufacturer  string `json:"manufacturer"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"webcam"`
	Honeypot struct {
		Count int                 `json:"count"`
		Data  []HoneypotDataEntry `json:"data"`
	} `json:"honeypot"`
	IPCategory struct {
		Count int `json:"count"`
		Data  []struct {
			DetectSource  string   `json:"detect_source"`
			Type          string   `json:"type"`
			DetectInfo    struct{} `json:"detect_info,omitempty"`
			ConfirmedTime string   `json:"confirmed_time"`
			DetectInfo0   struct { //nolint:govet
				Md5    string `json:"md5"`
				Domain string `json:"domain"`
			} `json:"detect_info,omitempty"`
		} `json:"data"`
	} `json:"ip_category"`
	Port struct {
		Count int             `json:"count"`
		Data  []PortDataEntry `json:"data"`
	} `json:"port"`
	Vulnerability struct {
		Count int `json:"count"`
		Data  []struct {
			CveID          string  `json:"cve_id"`
			CveDescription string  `json:"cve_description"`
			Cvssv2Vector   string  `json:"cvssv2_vector"`
			Cvssv2Score    float64 `json:"cvssv2_score"`
			Cvssv3Vector   string  `json:"cvssv3_vector"`
			Cvssv3Score    float64 `json:"cvssv3_score"`
			ListCwe        []struct {
				CveID          string `json:"cve_id"`
				CweID          int    `json:"cwe_id"`
				CweName        string `json:"cwe_name"`
				CweDescription string `json:"cwe_description"`
			} `json:"list_cwe"`
			ListEdb []struct {
				CveID         string `json:"cve_id"`
				EdbID         int    `json:"edb_id"`
				Type          string `json:"type"`
				Platform      string `json:"platform"`
				VerifyCode    int    `json:"verify_code"`
				Title         string `json:"title"`
				ConfirmedTime string `json:"confirmed_time"`
			} `json:"list_edb"`
			AppName        string `json:"app_name"`
			AppVersion     string `json:"app_version"`
			OpenPortNoList struct {
				TCP []int `json:"TCP"`
				UDP []any `json:"UDP"`
			} `json:"open_port_no_list"`
			HaveMorePorts bool `json:"have_more_ports"`
			OpenPortNo    []struct {
				Port   int    `json:"port"`
				Socket string `json:"socket"`
			} `json:"open_port_no"`
			ListChild []struct {
				AppName    string `json:"app_name"`
				AppVersion string `json:"app_version"`
				Vendor     string `json:"vendor"`
				Type       string `json:"type"`
				IsVuln     string `json:"is_vuln"`
				TargetHw   string `json:"target_hw"`
				TargetSw   string `json:"target_sw"`
				Update     string `json:"update"`
				Edition    string `json:"edition"`
			} `json:"list_child"`
			Vendor   string `json:"vendor"`
			Type     string `json:"type"`
			IsVuln   string `json:"is_vuln"`
			TargetHw string `json:"target_hw"`
			TargetSw string `json:"target_sw"`
			Update   string `json:"update"`
			Edition  string `json:"edition"`
		} `json:"data"`
	} `json:"vulnerability"`
	Mobile struct {
		Count int `json:"count"`
		Data  []struct {
			Broadband    string `json:"broadband"`
			Organization string `json:"organization"`
		} `json:"data"`
	} `json:"mobile"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}
