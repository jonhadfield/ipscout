package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/crosscheck-ip/cache"
	"github.com/jonhadfield/crosscheck-ip/config"
	"github.com/jonhadfield/crosscheck-ip/providers"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	ProviderName      = "shodan"
	APIURL            = "https://api.shodan.io"
	HostIPPath        = "/shodan/host"
	MaxColumnWidth    = 120
	IndentPipeHyphens = " |-----"
	NoDataResponse    = "No information available for that IP."
)

func Load(client *retryablehttp.Client, apiKey string) (res HostSearchResult, err error) {
	jf, err := os.Open("testdata/shodan_google_dns_resp.json")
	if err != nil {
		return HostSearchResult{}, err
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func loadAPIResponse(ctx context.Context, host netip.Addr, client *retryablehttp.Client, apiKey string) (res *HostSearchResult, err error) {
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
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	// read response body
	rBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		if err = os.WriteFile(fmt.Sprintf("backups/shodan_%s_report.json",
			strings.ReplaceAll(host.String(), ".", "_")), rBody, 0644); err != nil {
			panic(err)
		}
	}

	defer resp.Body.Close()

	res, err = unmarshalResponse(rBody)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	res.Raw = rBody

	return res, nil
}

func unmarshalResponse(data []byte) (*HostSearchResult, error) {
	var res HostSearchResult

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

func loadResultsFile(path string) (res *HostSearchResult, err error) {
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

func (ssr *HostSearchResult) CreateTable() *table.Writer {
	tw := table.NewWriter()

	return &tw
}

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

type Clienter interface {
	CreateTable() (*table.Writer, error)
}

type TableCreatorClient struct {
	config.Config
}

func fetchData(client config.Config) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if client.UseTestData {
		result, err = loadResultsFile("providers/shodan/testdata/shodan_google_dns_resp.json")
		if err != nil {
			return nil, fmt.Errorf("error loading shodan test data: %w", err)
		}

		return result, nil
	}

	// load data from cache
	cacheKey := fmt.Sprintf("shodan_%s_report.json", strings.ReplaceAll(client.Host.String(), ".", "_"))
	var item *cache.Item
	if item, err = cache.Read(client.Cache, cacheKey); err == nil {
		result, err = unmarshalResponse(item.Value)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling cached shodan response: %w", err)
		}

		// fmt.Printf("cache hit: %s\n", cacheKey)

		// if err = json.Unmarshal(item.Value, &result); err != nil {
		// 	return nil, err
		// }

		return result, nil
	}

	result, err = loadAPIResponse(context.Background(), client.Host, client.HttpClient, client.Providers.Shodan.APIKey)
	if err != nil {
		return nil, fmt.Errorf("error loading shodan api response: %w", err)
	}

	switch result.Error {
	case NoDataResponse:
		return nil, providers.ErrNoDataFound
	case "":
		break
	default:
		return nil, fmt.Errorf("%s: %w", result.Error, providers.ErrFailedToFetchData)
	}

	if err = cache.Upsert(client.Cache, cache.Item{
		Key:     cacheKey,
		Value:   result.Raw,
		Created: time.Now(),
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *TableCreatorClient) CreateTable() (*table.Writer, error) {
	result, err := fetchData(c.Config)
	if err != nil {
		if errors.Is(err, providers.ErrNoDataFound) {
			return nil, nil
		}

		return nil, fmt.Errorf("error fetching shodan data: %w", err)
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

	var filteredPorts int

	for _, dr := range result.Data {
		if !providers.PortMatch(fmt.Sprintf("%d/%s", dr.Port, dr.Transport), c.Global.Ports) {
			filteredPorts++
		}
	}

	if filteredPorts > 0 {
		rows = append(rows, table.Row{"Ports", fmt.Sprintf("%d (%d filtered)", len(result.Data), filteredPorts)})
	} else {
		rows = append(rows, table.Row{"Ports", len(result.Data)})
	}

	if len(result.Data) > 0 {
		for _, dr := range result.Data {
			if !providers.PortMatch(fmt.Sprintf("%d/%s", dr.Port, dr.Transport), c.Global.Ports) {
				continue
			}

			rows = append(rows, table.Row{"", color.CyanString("%d/%s", dr.Port, dr.Transport)})
			rows = append(rows, table.Row{"",
				fmt.Sprintf("%s  Domains: %s", IndentPipeHyphens, strings.Join(dr.Domains, ", "))})
			rows = append(rows, table.Row{"", fmt.Sprintf("%s  HostNames: %s", IndentPipeHyphens, strings.Join(dr.Hostnames, ", "))})
			if dr.HTTP.Status != 0 {
				rows = append(rows, table.Row{"", fmt.Sprintf("%s  HTTP", IndentPipeHyphens)})
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s%sStatus: %d",
						IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.HTTP.Status)})
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s%sTitle: %s",
						IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.HTTP.Title)})
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s%sServer: %s",
						IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.HTTP.Server)})
			}
			if len(dr.Ssl.Versions) > 0 {
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s  SSL", IndentPipeHyphens)})
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s%sIssuer: %s",
						IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.Ssl.Cert.Issuer.Cn)})
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s%sSubject: %s",
						IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.Ssl.Cert.Subject.Cn)})
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s%sVersions: %s",
						IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), strings.Join(dr.Ssl.Versions, ", "))})
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s%sExpires: %s",
						IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.Ssl.Cert.Expires)})
			}
			if dr.DNS.ResolverHostname != nil {
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s  DNS",
						IndentPipeHyphens)})
				if dr.DNS.ResolverHostname != "" {
					rows = append(rows, table.Row{"",
						fmt.Sprintf("%s%sResolver Hostname: %s",
							IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.DNS.ResolverHostname)})
				}
				if dr.DNS.Software != nil {
					rows = append(rows, table.Row{"",
						fmt.Sprintf("%s%sResolver Software: %s",
							IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.DNS.Software)})
				}
				rows = append(rows, table.Row{"",
					fmt.Sprintf("%s%sRecursive: %t",
						IndentPipeHyphens, strings.Repeat(" ", 2*c.Global.IndentSpaces), dr.DNS.Recursive)})
			}
		}

		tw.AppendRows(rows)
		tw.SetColumnConfigs([]table.ColumnConfig{
			{Number: 2, AutoMerge: true, WidthMax: MaxColumnWidth, WidthMin: 50},
		})
	}
	// result.Data[0].Data = strings.ReplaceAll(result.Data[0].Domains[0], "\n", " ")
	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("SHODAN | Host: %s", c.Host.String())
	if c.UseTestData {
		tw.SetTitle("SHODAN | Host: %s", result.Data[0].IPStr)
	}

	return &tw, nil
}

func NewTableClient(config config.Config) (*TableCreatorClient, error) {
	tc := &TableCreatorClient{
		config,
	}

	return tc, nil
}

func (c *Client) GetData() (result *HostSearchResult, err error) {
	result, err = loadResultsFile("shodan/testdata/shodan_google_dns_resp.json")
	if err != nil {
		return nil, err
	}

	return result, nil
}

type HostSearchResultData struct {
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
		Status     int `json:"status"`
		RobotsHash int `json:"robots_hash"`
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
		SecurityTxtHash int    `json:"securitytxt_hash"`
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
