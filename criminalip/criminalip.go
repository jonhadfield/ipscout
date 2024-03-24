package criminalip

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/noodle/config"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"
)

const (
	APIURL     = "https://api.criminalip.io"
	HostIPPath = "/v1/asset/ip/report"
)

type Config struct {
	_ struct{}
	config.Default
	Host   netip.Addr
	APIKey string
}

func Load(client *retryablehttp.Client, apiKey string) (res CriminalIPHostSearchResult, err error) {
	ctx := context.Background()

	apiResponse, err := loadCriminalIPAPIResponse(ctx, client, apiKey)
	if err != nil {
		return CriminalIPHostSearchResult{}, err
	}
	fmt.Println(apiResponse.IP)

	jf, err := os.Open("testdata/shodan_google_dns_resp.json")
	if err != nil {
		return CriminalIPHostSearchResult{}, err
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func loadCriminalIPAPIResponse(ctx context.Context, client *retryablehttp.Client, apiKey string) (res CriminalIPHostSearchResult, err error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath, "8.8.8.8")
	if err != nil {
		return CriminalIPHostSearchResult{}, err
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

	// do something with the response
	defer resp.Body.Close()

	if err = json.Unmarshal(rBody, &res); err != nil {
		return CriminalIPHostSearchResult{}, err
	}

	return res, nil
}

type TableCreatorClient struct {
	config.Default
	Client Config
}

func NewTableClient(config Config) (*TableCreatorClient, error) {
	tc := &TableCreatorClient{
		Client: config,
	}

	tc.Default = config.Default

	return tc, nil
}

func (c *TableCreatorClient) CreateTable() (*table.Writer, error) {
	result, err := loadCriminalIPFile("criminalip/testdata/criminalip_1_1_1_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error loading criminalip file: %w", err)
	}

	tw := table.NewWriter()
	row1 := table.Row{"Name", result.Domain.Data[0].Domain}
	row2 := table.Row{"City", result.Whois.Data[0].City}
	row3 := table.Row{"Country", result.Whois.Data[0].OrgCountryCode}
	row4 := table.Row{"AS", result.Whois.Data[0].AsNo}
	row5 := table.Row{"Ports"}
	row6 := table.Row{"", "53/tcp"}
	row7 := table.Row{"", "53/udp"}
	row8 := table.Row{"", "443/tcp"}
	row9 := table.Row{"", "|----- HTTP title: Google Public DNS"}
	row10 := table.Row{"", "|----- Cert issuer: C=US, CN=GTS CA 1C3, O=Google Trust Services LLC"}
	tw.AppendRows([]table.Row{row1, row2, row3, row4, row5, row6, row7, row8, row9, row10})
	// result.Data[0].Data = strings.ReplaceAll(result.Data[0].Domains[0], "\n", " ")
	tw.SetAutoIndex(false)
	tw.SetStyle(table.StyleColoredMagentaWhiteOnBlack)
	tw.SetTitle("CRIMINAL IP | Host: %s", c.Client.Host.String())

	return &tw, nil
}

func loadCriminalIPFile(path string) (res CriminalIPHostSearchResult, err error) {
	jf, err := os.Open(path)
	if err != nil {
		return CriminalIPHostSearchResult{}, err
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func Run() (result CriminalIPHostSearchResult, err error) {
	result, err = loadCriminalIPFile("criminalip/testdata/criminalip_1_1_1_1_report.json")
	if err != nil {
		return CriminalIPHostSearchResult{}, err
	}

	// httpClient := getHTTPClient()
	// res, err = Load(httpClient, os.Getenv("SHODAN_API_KEY"))
	// if err != nil {
	// 	panic(err)
	// }

	return result, nil
}

type CriminalIPHostSearchResultData struct {
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

type CriminalIPHostSearchResult struct {
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
	Domain struct {
		Count int `json:"count"`
		Data  []struct {
			Domain        string `json:"domain"`
			IPType        string `json:"ip_type"`
			Registrar     string `json:"registrar"`
			CreateDate    string `json:"create_date"`
			ConfirmedTime string `json:"confirmed_time"`
			Email         string `json:"email"`
		} `json:"data"`
	} `json:"domain"`
	Whois struct {
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

// type CriminalIPHostSearchResult struct {
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
// 	Data        []CriminalIPHostSearchResultData
// 	//
// 	// 	// ////
// 	// 	CriminalIP0 struct {
// 	// 		ID      string `json:"id"`
// 	// 		Region  string `json:"region"`
// 	// 		Options struct {
// 	// 		} `json:"options"`
// 	// 		Module  string `json:"module"`
// 	// 		Crawler string `json:"crawler"`
// 	// 	} `json:"_shodan,omitempty"`
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
