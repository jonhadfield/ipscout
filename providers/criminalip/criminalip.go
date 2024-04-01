package criminalip

import (
	"context"
	"encoding/json"
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
	"regexp"
	"strings"
	"time"
)

const (
	ProviderName      = "criminalip"
	APIURL            = "https://api.criminalip.io"
	HostIPPath        = "/v1/asset/ip/report"
	IndentPipeHyphens = " |-----"
)

type Config struct {
	_ struct{}
	config.Config
	Host   netip.Addr
	APIKey string
}

func loadAPIResponse(ctx context.Context, host netip.Addr, client *retryablehttp.Client, apiKey string) (res *HostSearchResult, err error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath)
	if err != nil {
		return nil, err
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	q := sURL.Query()
	q.Add("ip", host.String())
	sURL.RawQuery = q.Encode()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, sURL.String(), nil)
	if err != nil {
		panic(err)
	}

	req.Header.Add("x-api-key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// read response body
	rBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		if err = os.WriteFile(fmt.Sprintf("backups/criminalip_%s_report.json",
			strings.ReplaceAll(host.String(), ".", "_")), rBody, 0644); err != nil {
			panic(err)
		}
	}

	// do something with the response
	defer resp.Body.Close()

	// if err = json.Unmarshal(rBody, &res); err != nil {
	// 	return nil, err
	// }
	res, err = unmarshalResponse(rBody)
	if err != nil {
		return nil, err
	}

	res.Raw = rBody

	return res, nil
}

func unmarshalResponse(rBody []byte) (*HostSearchResult, error) {
	var res *HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ProviderClient struct {
	config.Config
}

func NewProviderClient(config config.Config) (*ProviderClient, error) {
	tc := &ProviderClient{
		Config: config,
	}

	return tc, nil
}

func fetchData(client config.Config) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if client.UseTestData {
		result, err = loadResultsFile("providers/criminalip/testdata/criminalip_9_9_9_9_report.json")
		if err != nil {
			return nil, err
		}

		client.Logger.Info("loaded criminal ip test data", "host", client.Host.String())

		return result, nil
	}

	cacheKey := fmt.Sprintf("criminalip_%s_report.json", strings.ReplaceAll(client.Host.String(), ".", "_"))
	var item *cache.Item
	if item, err = cache.Read(client.Cache, cacheKey); err == nil {
		result, err = unmarshalResponse(item.Value)
		if err != nil {
			return nil, err
		}

		client.Logger.Info("criminal ip response found in cache", "host", client.Host.String())

		// fmt.Printf("cache hit: %s\n", cacheKey)

		// if err = json.Unmarshal(item.Value, &result); err != nil {
		// 	return nil, err
		// }
		// fmt.Println("0cache hit with bytes: ", result.Raw)
		result.Raw = item.Value
		// fmt.Println("1cache hit with bytes: ", result.Raw)
		return result, nil
	}

	result, err = loadAPIResponse(context.Background(), client.Host, client.HttpClient, client.Providers.CriminalIP.APIKey)
	if err != nil {
		return nil, fmt.Errorf("error loading criminal ip api response: %w", err)
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

const (
	MaxColumnWidth = 120
)

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

func (c *ProviderClient) Initialise() error {
	// fmt.Println("initialising criminalip client")
	// TODO: anything to initialise?

	return nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	result, err := fetchData(c.Config)
	if err != nil {
		fmt.Printf("error loading criminalip api response: %v\n", err)
		return nil, fmt.Errorf("error loading criminalip api response: %w", err)
	}

	return result.Raw, nil
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	result, err := unmarshalResponse(data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling criminalip api response: %w", err)
	}

	tw := table.NewWriter()
	// tw.SetStyle(myInnerStyle)
	var rows []table.Row
	if result.Hostname.Count > 0 {
		tw.AppendRow(table.Row{"Name", dashIfEmpty(result.Hostname.Data[0].DomainNameFull)})
		tw.AppendRow(table.Row{"City", dashIfEmpty(result.Whois.Data[0].City)})
		tw.AppendRow(table.Row{"Country", dashIfEmpty(result.Whois.Data[0].OrgCountryCode)})
		tw.AppendRow(table.Row{"AS", dashIfEmpty(result.Whois.Data[0].AsNo)})
	} else {
		tw.AppendRow(table.Row{"Name", "-"})
		tw.AppendRow(table.Row{"City", "-"})
		tw.AppendRow(table.Row{"Country", "-"})
		tw.AppendRow(table.Row{"AS", "-"})
	}

	if domains := getDomains(result.Domain); domains != nil {
		tw.AppendRow(table.Row{"Domains", strings.Join(getDomains(result.Domain), ", ")})
	}

	tw.AppendRow(table.Row{"Score Inbound", result.Score.Inbound})
	tw.AppendRow(table.Row{"Score Outbound", result.Score.Outbound})

	var filteredPorts int

	for _, port := range result.Port.Data {
		if !providers.PortMatch(fmt.Sprintf("%d/%s", port.OpenPortNo, port.Socket), c.Global.Ports) {
			filteredPorts++
		}
	}

	if filteredPorts > 0 {
		tw.AppendRow(table.Row{"Ports", fmt.Sprintf("%d (%d filtered)", len(result.Port.Data), filteredPorts)})
	} else {
		tw.AppendRow(table.Row{"Ports", len(result.Port.Data)})
	}

	for x, port := range result.Port.Data {
		if !providers.PortMatch(fmt.Sprintf("%d/%s", port.OpenPortNo, port.Socket), c.Global.Ports) {
			continue
		}

		tw.AppendRow(table.Row{"", color.CyanString("%d/%s", port.OpenPortNo, port.Socket)})
		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Protocol: %s", IndentPipeHyphens, port.Protocol)})
		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Confirmed Time: %s", IndentPipeHyphens, port.ConfirmedTime)})

		// vary output based on protocol
		switch strings.ToLower(port.Protocol) {
		case "https":
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  SDN Common Name: %s", IndentPipeHyphens, port.SdnCommonName)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  DNS Names: %s", IndentPipeHyphens, providers.PreProcessValueOutput(&c.Config, ProviderName, port.DNSNames))})
		case "dns":
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  App Name (Version): %s (%s)", IndentPipeHyphens, port.AppName, port.AppVersion)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Banner: %s",
				IndentPipeHyphens, tidyBanner(providers.PreProcessValueOutput(&c.Config, ProviderName, port.Banner)))})
		default:
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  App Name (Version): %s (%s)", IndentPipeHyphens, port.AppName, port.AppVersion)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Banner: %s",
				IndentPipeHyphens, tidyBanner(providers.PreProcessValueOutput(&c.Config, ProviderName, port.Banner)))})
		}

		// always include if detected as vulnerability
		tw.AppendRow(table.Row{"", fmt.Sprintf("%s  Is Vulnerability: %t", IndentPipeHyphens, port.IsVulnerability)})
		if x+1 < len(result.Port.Data) {
			// add a blank row between ports
			tw.AppendRow(table.Row{"", ""})
		}
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
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
		return nil, err
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

type HostSearchResultData struct {
	Hash int `json:"hash"`
	Opts struct {
	} `json:"opts,omitempty"`
	Timestamp  string `json:"timestamp"`
	Isp        string `json:"isp"`
	Data       string `json:"data"`
	CriminalIP struct {
		Region  string `json:"region"`
		Module  string `json:"module"`
		Ptr     bool   `json:"ptr"`
		Options struct {
		} `json:"options"`
		ID      string `json:"id"`
		Crawler string `json:"crawler"`
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
		Ocsp            struct {
		} `json:"ocsp"`
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

type HostSearchResult struct {
	Raw    []byte
	IP     string `json:"ip"`
	Issues struct {
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
	} `json:"issues"`
	Score struct {
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
	} `json:"whois"`
	Hostname struct {
		Count int `json:"count"`
		Data  []struct {
			DomainNameRep  string `json:"domain_name_rep"`
			DomainNameFull string `json:"domain_name_full"`
			ConfirmedTime  string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"hostname"`
	Ids struct {
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
		Count int `json:"count"`
		Data  []struct {
			IPAddress     string `json:"ip_address"`
			LogDate       string `json:"log_date"`
			DstPort       int    `json:"dst_port"`
			Message       string `json:"message"`
			UserAgent     string `json:"user_agent"`
			ProtocolType  string `json:"protocol_type"`
			ConfirmedTime string `json:"confirmed_time"`
		} `json:"data"`
	} `json:"honeypot"`
	IPCategory struct {
		Count int `json:"count"`
		Data  []struct {
			DetectSource string `json:"detect_source"`
			Type         string `json:"type"`
			DetectInfo   struct {
			} `json:"detect_info,omitempty"`
			ConfirmedTime string `json:"confirmed_time"`
			DetectInfo0   struct {
				Md5    string `json:"md5"`
				Domain string `json:"domain"`
			} `json:"detect_info,omitempty"`
		} `json:"data"`
	} `json:"ip_category"`
	Port struct {
		Count int `json:"count"`
		Data  []struct {
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
		} `json:"data"`
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
	Status int `json:"status"`
}

// type HostSearchResult struct {
// 	City        string   `json:"city"`
// 	RegionCode  string   `json:"region_code"`
// 	Os          any      `json:"os"`
// 	Tags        []any    `json:"tags"`
// 	IP          string   `json:"ip"`
// 	Isp         string   `json:"isp"`
// 	AreaCode    any      `json:"area_code"`
// 	Longitude   float64  `json:"longitude"`
// 	LastUpdate  string   `json:"last_update"`
// 	Ports       []int    `json:"ports"`
// 	Latitude    float64  `json:"latitude"`
// 	Hostnames   []string `json:"hostnames"`
// 	CountryCode string   `json:"country_code"`
// 	CountryName string   `json:"country_name"`
// 	Domains     []string `json:"domains"`
// 	Org         string   `json:"org"`
// 	Data        []HostSearchResultData
// 	//
// 	// 	// ////
// 	// 	CriminalIP0 struct {
// 	// 		ID      string `json:"id"`
// 	// 		Region  string `json:"region"`
// 	// 		Options struct {
// 	// 		} `json:"options"`
// 	// 		Module  string `json:"module"`
// 	// 		Crawler string `json:"crawler"`
// 	// 	} `json:"_criminalip,omitempty"`
// 	//
// 	// 	Ssl struct {
// 	// 		ChainSha256   []string `json:"chain_sha256"`
// 	// 		Jarm          string   `json:"jarm"`
// 	// 		Chain         []string `json:"chain"`
// 	// 		Dhparams      any      `json:"dhparams"`
// 	// 		Versions      []string `json:"versions"`
// 	// 		AcceptableCas []any    `json:"acceptable_cas"`
// 	// 		Tlsext        []struct {
// 	// 			ID   int    `json:"id"`
// 	// 			Name string `json:"name"`
// 	// 		} `json:"tlsext"`
// 	// 		Ja3S string `json:"ja3s"`
// 	// 		Cert struct {
// 	// 			SigAlg     string `json:"sig_alg"`
// 	// 			Issued     string `json:"issued"`
// 	// 			Expires    string `json:"expires"`
// 	// 			Expired    bool   `json:"expired"`
// 	// 			Version    int    `json:"version"`
// 	// 			Extensions []struct {
// 	// 				Critical bool   `json:"critical,omitempty"`
// 	// 				Data     string `json:"data"`
// 	// 				Name     string `json:"name"`
// 	// 			} `json:"extensions"`
// 	// 			Fingerprint struct {
// 	// 				Sha256 string `json:"sha256"`
// 	// 				Sha1   string `json:"sha1"`
// 	// 			} `json:"fingerprint"`
// 	// 			Serial  int64 `json:"serial"`
// 	// 			Subject struct {
// 	// 				Cn string `json:"CN"`
// 	// 			} `json:"subject"`
// 	// 			Pubkey struct {
// 	// 				Type string `json:"type"`
// 	// 				Bits int    `json:"bits"`
// 	// 			} `json:"pubkey"`
// 	// 			Issuer struct {
// 	// 				C  string `json:"C"`
// 	// 				Cn string `json:"CN"`
// 	// 				O  string `json:"O"`
// 	// 			} `json:"issuer"`
// 	// 		} `json:"cert"`
// 	// 		Cipher struct {
// 	// 			Version string `json:"version"`
// 	// 			Bits    int    `json:"bits"`
// 	// 			Name    string `json:"name"`
// 	// 		} `json:"cipher"`
// 	// 		Trust struct {
// 	// 			Revoked bool `json:"revoked"`
// 	// 			Browser any  `json:"browser"`
// 	// 		} `json:"trust"`
// 	// 		HandshakeStates []string `json:"handshake_states"`
// 	// 		Alpn            []any    `json:"alpn"`
// 	// 		Ocsp            struct {
// 	// 		} `json:"ocsp"`
// 	// 	} `json:"ssl,omitempty"`
// 	// } `json:"data"`
// 	Asn   string `json:"asn"`
// 	IPStr string `json:"ip_str"`
// }

func NilOrOriginal[T comparable](value *T, replacement string) interface{} {
	if value == nil {
		return replacement
	}
	return *value
}

func dashIfEmpty(value interface{}) string {
	switch v := value.(type) {
	case string:
		if len(v) == 0 {
			return "-"
		}
		return v
	case *string:
		if v == nil || len(*v) == 0 {
			return "-"
		}
		return *v
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return "-"
	}
}
