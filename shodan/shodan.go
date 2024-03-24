package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	APIURL     = "https://api.shodan.io"
	HostIPPath = "/shodan/host"
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

func loadShodanAPIResponse(ctx context.Context, client *retryablehttp.Client, apiKey string) (res ShodanHostSearchResult, err error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath, "8.8.8.8")
	if err != nil {
		return ShodanHostSearchResult{}, err
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

	fmt.Printf("request url: %s\n", req.URL.String())
	fmt.Println(req)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// read response body
	rBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	if err = json.Unmarshal(rBody, &res); err != nil {
		return ShodanHostSearchResult{}, err
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
	_      struct{}
	Host   netip.Addr
	APIKey string
}

type Clienter interface {
	CreateTable() (*table.Writer, error)
}

type TableCreatorClient struct {
	Client Config
}

func (c *TableCreatorClient) CreateTable() (*table.Writer, error) {
	result, err := loadShodanFile("shodan/testdata/shodan_google_dns_resp.json")
	if err != nil {
		return nil, fmt.Errorf("error loading shodan file: %w", err)
	}

	tw := table.NewWriter()
	row1 := table.Row{"Name", strings.Join(result.Hostnames, ", ")}
	row2 := table.Row{"City", result.City}
	row3 := table.Row{"Country", result.CountryName}
	row4 := table.Row{"AS", result.Asn}
	row5 := table.Row{"Ports"}
	row6 := table.Row{"", "53/tcp"}
	row7 := table.Row{"", "53/udp"}
	row8 := table.Row{"", "443/tcp"}
	row9 := table.Row{"", "|----- HTTP title: Google Public DNS"}
	row10 := table.Row{"", "|----- Cert issuer: C=US, CN=GTS CA 1C3, O=Google Trust Services LLC"}
	tw.AppendRows([]table.Row{row1, row2, row3, row4, row5, row6, row7, row8, row9, row10})
	result.Data[0].Data = strings.ReplaceAll(result.Data[0].Domains[0], "\n", " ")
	tw.SetAutoIndex(false)
	tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("SHODAN | Host: %s", c.Client.Host.String())

	return &tw, nil
}

func NewTableClient(config Config) (*TableCreatorClient, error) {
	tc := &TableCreatorClient{
		Client: config,
	}

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
}
