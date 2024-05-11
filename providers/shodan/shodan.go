package shodan

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
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName           = "shodan"
	APIURL                 = "https://api.shodan.io"
	HostIPPath             = "/shodan/host"
	MaxColumnWidth         = 120
	IndentPipeHyphens      = " |-----"
	portLastModifiedFormat = "2006-01-02T15:04:05.999999"
	ResultTTL              = time.Duration(12 * time.Hour)
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
	if c.Session.Providers.Shodan.Enabled != nil && *c.Session.Providers.Shodan.Enabled {
		return true
	}

	return false
}

func loadAPIResponse(ctx context.Context, c session.Session, apiKey string) (res *HostSearchResult, err error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath, c.Host.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create shodan api url path: %w", err)
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
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
		return nil, fmt.Errorf("shodan api request failed: %s", resp.Status)
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

	res, err = unmarshalResponse(rBody)
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

func loadResultsFile(path string) (res *HostSearchResult, err error) {
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

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, fmt.Errorf("error decoding shodan file: %w", err)
	}

	res.Raw = raw

	return res, nil
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
	cacheKey := fmt.Sprintf("shodan_%s_report.json", strings.ReplaceAll(c.Host.String(), ".", "_"))

	var item *cache.Item

	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		if item.Value != nil && len(item.Value) > 0 {
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
	if c.Cache == nil {
		return errors.New("cache not set")
	}

	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	c.Logger.Debug("initialising shodan client")

	if c.Providers.Shodan.APIKey == "" && !c.UseTestData {
		return fmt.Errorf("shodan provider api key not set")
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

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("shodan host match data", "size", len(result.Raw))

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
		return nil, fmt.Errorf("error unmarshalling shodan data: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	tw := table.NewWriter()
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	var rows []table.Row

	tw.AppendRow(table.Row{"WHOIS", providers.DashIfEmpty(result.LastUpdate)})
	tw.AppendRow(table.Row{" - Org", providers.DashIfEmpty(result.Org)})
	tw.AppendRow(table.Row{" - Country", fmt.Sprintf("%s (%s)", providers.DashIfEmpty(result.CountryName), providers.DashIfEmpty(strings.ToUpper(result.CountryCode)))})
	tw.AppendRow(table.Row{" - Region", providers.DashIfEmpty(result.RegionCode)})
	tw.AppendRow(table.Row{" - City", providers.DashIfEmpty(result.City)})

	var filteredPorts int

	var portsDisplayed int

	for _, dr := range result.Data {
		var ok bool

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
	}

	if filteredPorts > 0 {
		tw.AppendRow(table.Row{"Ports", fmt.Sprintf("%d (%d filtered)", len(result.Data), filteredPorts)})
	} else {
		tw.AppendRow(table.Row{"Ports", len(result.Data)})
	}

	if len(result.Data) > 0 {
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

			tw.AppendRow(table.Row{"", color.CyanString("%d/%s", dr.Port, dr.Transport)})

			if len(dr.Domains) > 0 {
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Domains: %s", IndentPipeHyphens, strings.Join(dr.Domains, ", "))})
			}

			if dr.Timestamp != "" {
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Timestamp: %s", IndentPipeHyphens, dr.Timestamp)})
			}

			if len(dr.Hostnames) > 0 {
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s  HostNames: %s", IndentPipeHyphens, strings.Join(dr.Hostnames, ", "))})
			}

			if dr.SSH.Type != "" {
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s  SSH", IndentPipeHyphens)})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sType: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.SSH.Type)})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sCipher: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.SSH.Cipher)})
			}

			if dr.HTTP.Status != 0 {
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s  HTTP", IndentPipeHyphens)})

				if dr.HTTP.Location != "" {
					tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sLocation: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.HTTP.Location)})
				}

				tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sStatus: %d", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.HTTP.Status)})

				if dr.HTTP.Title != "" {
					tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sTitle: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.HTTP.Title)})
				}

				if dr.HTTP.Server != "" {
					tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sServer: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.HTTP.Server)})
				}

				if dr.HTTP.HTML != "" {
					dr.HTTP.HTML = strings.TrimSuffix(dr.HTTP.HTML, "\n")
					tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sHTML: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.HTTP.HTML)})
				}
			}

			if len(dr.Ssl.Versions) > 0 {
				tw.AppendRow(table.Row{"", color.CyanString("SSL")})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sIssuer: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.Ssl.Cert.Issuer.Cn)})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sSubject: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.Ssl.Cert.Subject.Cn)})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sVersions: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), strings.Join(dr.Ssl.Versions, ", "))})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sExpires: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.Ssl.Cert.Expires)})
			}

			if dr.DNS.ResolverHostname != nil {
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s  DNS", IndentPipeHyphens)})

				if dr.DNS.ResolverHostname != "" {
					tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sResolver Hostname: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.DNS.ResolverHostname)})
				}

				if dr.DNS.Software != nil {
					tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sResolver Software: %s", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.DNS.Software)})
				}

				tw.AppendRow(table.Row{"", fmt.Sprintf("%s%sRecursive: %t", IndentPipeHyphens, strings.Repeat(" ", 2*c.Config.Global.IndentSpaces), dr.DNS.Recursive)})
			}

			portsDisplayed++

			if portsDisplayed == c.Config.Global.MaxReports {
				tw.AppendRow(table.Row{"", color.YellowString("--- Max reports reached ---")})

				break
			}
		}

		tw.AppendRows(rows)

		tw.SetColumnConfigs([]table.ColumnConfig{
			{Number: 2, AutoMerge: true, WidthMax: MaxColumnWidth, WidthMin: 50},
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

func (c *Client) GetData() (result *HostSearchResult, err error) {
	result, err = loadResultsFile("shodan/testdata/shodan_google_dns_resp.json")
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
	DNS struct {
		ResolverHostname any  `json:"resolver_hostname"`
		Recursive        bool `json:"recursive"`
		ResolverID       any  `json:"resolver_id"`
		Software         any  `json:"software"`
	} `json:"dns,omitempty"`
	SSH struct {
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
	} `json:"ssh"`
	HTTP struct {
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
	} `json:"http,omitempty"`
	IP        int      `json:"ip"`
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
