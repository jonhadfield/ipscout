package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/noodle/config"
	"github.com/jonhadfield/noodle/providers"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	APIURL               = "https://api.shodan.io"
	HostIPPath           = "/shodan/host"
	MaxColumnWidth       = 120
	IndentPipeHyphens    = " |-----"
	ShodanNoDataResponse = "No information available for that IP."
)

func Load(client *retryablehttp.Client, apiKey string) (res ShodanHostSearchResult, err error) {
	jf, err := os.Open("testdata/shodan_google_dns_resp.json")
	if err != nil {
		return ShodanHostSearchResult{}, err
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func loadShodanAPIResponse(ctx context.Context, host netip.Addr, client *retryablehttp.Client, apiKey string) (res *ShodanHostSearchResult, err error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath, host.String())
	if err != nil {
		return nil, err
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	q := sURL.Query()
	q.Add("key", apiKey)
	sURL.RawQuery = q.Encode()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, sURL.String(), nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// read response body
	rBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	os.WriteFile(fmt.Sprintf("backups/shodan_%s_report.json",
		strings.ReplaceAll(host.String(), ".", "_")), rBody, 0644)

	defer resp.Body.Close()

	if err = json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling shodan response: %w", err)
	}

	return res, nil
}

func loadShodanFile(path string) (res *ShodanHostSearchResult, err error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening shodan file: %w", err)

	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func (ssr *ShodanHostSearchResult) CreateTable() *table.Writer {
	tw := table.NewWriter()

	return &tw
}

type Client struct {
	Config     Config
	HTTPClient *retryablehttp.Client
}

type Config struct {
	_ struct{}
	config.Default
	Host   netip.Addr
	APIKey string
}

type Clienter interface {
	CreateTable() (*table.Writer, error)
}

type TableCreatorClient struct {
	config.Default
	Client Config
}

func fetchData(client Config) (*ShodanHostSearchResult, error) {
	var result *ShodanHostSearchResult

	var err error

	if client.UseTestData {
		result, err = loadShodanFile("shodan/testdata/shodan_google_dns_resp.json")
		if err != nil {
			return nil, err
		}

		return result, nil
	}

	result, err = loadShodanAPIResponse(context.Background(), client.Host, client.Default.HttpClient, client.APIKey)
	if err != nil {
		return nil, fmt.Errorf("error loading shodan api response: %w", err)
	}

	switch result.Error {
	case ShodanNoDataResponse:
		return nil, providers.ErrNoDataFound
	case "":
		break
	default:
		return nil, fmt.Errorf("%s: %w", result.Error, providers.ErrDataProviderFailure)
	}

	return result, nil
}

func (c *TableCreatorClient) CreateTable() (*table.Writer, error) {
	result, err := fetchData(c.Client)
	if err != nil {
		return nil, fmt.Errorf("error fetching data: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("no data returned")
	}

	tw := table.NewWriter()

	var rows []table.Row

	rows = append(rows, table.Row{"Updated", result.LastUpdate})
	rows = append(rows, table.Row{"Name", strings.Join(result.Hostnames, ", ")})
	rows = append(rows, table.Row{"City", result.City})
	rows = append(rows, table.Row{"Country", result.CountryName})
	rows = append(rows, table.Row{"AS", result.Asn})
	rows = append(rows, table.Row{"Ports"})
	// TODO: add ports
	for _, dr := range result.Data {
		if len(c.LimitPorts) > 0 && !slices.Contains(c.LimitPorts, fmt.Sprintf("%d/%s", dr.Port, dr.Transport)) {
			continue
		}

		rows = append(rows, table.Row{"", color.CyanString("%d/%s", dr.Port, dr.Transport)})
		rows = append(rows, table.Row{"", fmt.Sprintf("%s  Domains: %s", IndentPipeHyphens, strings.Join(dr.Domains, ", "))})
		rows = append(rows, table.Row{"", fmt.Sprintf("%s  HostNames: %s", IndentPipeHyphens, strings.Join(dr.Hostnames, ", "))})
		if dr.HTTP.Status != 0 {
			rows = append(rows, table.Row{"", fmt.Sprintf("%s  HTTP", IndentPipeHyphens)})
			rows = append(rows, table.Row{"", fmt.Sprintf("%s    Status: %d", IndentPipeHyphens, dr.HTTP.Status)})
			rows = append(rows, table.Row{"", fmt.Sprintf("%s    Title: %s", IndentPipeHyphens, dr.HTTP.Title)})
			rows = append(rows, table.Row{"", fmt.Sprintf("%s    Server: %s", IndentPipeHyphens, dr.HTTP.Server)})
		}
		if dr.DNS.ResolverHostname != nil {
			rows = append(rows, table.Row{"", fmt.Sprintf("%s  DNS", IndentPipeHyphens)})
			if dr.DNS.ResolverHostname != "" {
				rows = append(rows, table.Row{"", fmt.Sprintf("%s    Resolver Hostname: %s", IndentPipeHyphens, dr.DNS.ResolverHostname)})
			}
			if dr.DNS.Software != nil {
				rows = append(rows, table.Row{"", fmt.Sprintf("%s    Resolver Software: %s", IndentPipeHyphens, dr.DNS.Software)})
			}
			rows = append(rows, table.Row{"", fmt.Sprintf("%s    Recursive: %t", IndentPipeHyphens, dr.DNS.Recursive)})
		}
	}
	// rows = append(rows, table.Row{"", "53/tcp"})
	// rows = append(rows, table.Row{"", "53/udp"})
	// rows = append(rows, table.Row{"", "443/tcp"})
	// rows = append(rows, table.Row{"", "|----- HTTP title: Google Public DNS"})
	// rows = append(rows, table.Row{"", "|----- Cert issuer: C=US, CN=GTS CA 1C3, O=Google Trust Services LLC"})
	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: true, WidthMax: MaxColumnWidth},
	})

	// result.Data[0].Data = strings.ReplaceAll(result.Data[0].Domains[0], "\n", " ")
	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("SHODAN | Host: %s", c.Client.Host.String())
	if c.UseTestData {
		tw.SetTitle("SHODAN | Host: %s", result.Data[0].IPStr)
	}

	return &tw, nil
}

func NewTableClient(config Config) (*TableCreatorClient, error) {
	tc := &TableCreatorClient{
		Client: config,
	}

	tc.Default = config.Default

	return tc, nil
}

func (c *Client) GetData() (result *ShodanHostSearchResult, err error) {
	result, err = loadShodanFile("shodan/testdata/shodan_google_dns_resp.json")
	if err != nil {
		return nil, err
	}

	return result, nil
}

type ShodanHostSearchResultData struct {
	Hash int `json:"hash"`
	Opts struct {
	} `json:"opts,omitempty"`
	Timestamp string `json:"timestamp"`
	Isp       string `json:"isp"`
	Data      string `json:"data"`
	Shodan    struct {
		Region  string `json:"region"`
		Module  string `json:"module"`
		Ptr     bool   `json:"ptr"`
		Options struct {
		} `json:"options"`
		ID      string `json:"id"`
		Crawler string `json:"crawler"`
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
		HeadersHash int    `json:"headers_hash"`
		Host        string `json:"host"`
		HTML        string `json:"html"`
		Location    string `json:"location"`
		Components  struct {
		} `json:"components"`
		Server          string `json:"server"`
		Sitemap         string `json:"sitemap"`
		SecurityTxtHash string `json:"securitytxt_hash"`
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
		Ocsp            struct {
		} `json:"ocsp"`
	} `json:"ssl,omitempty"`
}

type ShodanHostSearchResult struct {
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
	Data        []ShodanHostSearchResultData
	Asn         string `json:"asn"`
	IPStr       string `json:"ip_str"`
	Error       string `json:"error"`
}
