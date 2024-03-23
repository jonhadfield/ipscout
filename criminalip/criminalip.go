package criminalip

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	CriminalIPAPIURL     = "https://api.shodan.io"
	CriminalIPHostIPPath = "/shodan/host"
)

func getHTTPClient() *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.RetryWaitMin = 1
	hc.RetryWaitMax = 1
	hc.RetryMax = 1
	hc.Logger = nil

	return hc
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
	urlPath, err := url.JoinPath(CriminalIPAPIURL, CriminalIPHostIPPath, "8.8.8.8")
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

	fmt.Printf("request url: %s\n", req.URL.String())
	fmt.Println(req)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	fmt.Printf("response status code: %d\n", resp.StatusCode)

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

func loadCriminalIPFile(path string) (res CriminalIPHostSearchResult, err error) {
	jf, err := os.Open(path)
	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func Run() (result CriminalIPHostSearchResult, err error) {
	result, err = loadCriminalIPFile("testdata/shodan_google_dns_resp.json")
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

type CriminalIPHostSearchResult struct {
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
	Data        []CriminalIPHostSearchResultData
	//
	// 	// ////
	// 	CriminalIP0 struct {
	// 		ID      string `json:"id"`
	// 		Region  string `json:"region"`
	// 		Options struct {
	// 		} `json:"options"`
	// 		Module  string `json:"module"`
	// 		Crawler string `json:"crawler"`
	// 	} `json:"_shodan,omitempty"`
	//
	// 	Ssl struct {
	// 		ChainSha256   []string `json:"chain_sha256"`
	// 		Jarm          string   `json:"jarm"`
	// 		Chain         []string `json:"chain"`
	// 		Dhparams      any      `json:"dhparams"`
	// 		Versions      []string `json:"versions"`
	// 		AcceptableCas []any    `json:"acceptable_cas"`
	// 		Tlsext        []struct {
	// 			ID   int    `json:"id"`
	// 			Name string `json:"name"`
	// 		} `json:"tlsext"`
	// 		Ja3S string `json:"ja3s"`
	// 		Cert struct {
	// 			SigAlg     string `json:"sig_alg"`
	// 			Issued     string `json:"issued"`
	// 			Expires    string `json:"expires"`
	// 			Expired    bool   `json:"expired"`
	// 			Version    int    `json:"version"`
	// 			Extensions []struct {
	// 				Critical bool   `json:"critical,omitempty"`
	// 				Data     string `json:"data"`
	// 				Name     string `json:"name"`
	// 			} `json:"extensions"`
	// 			Fingerprint struct {
	// 				Sha256 string `json:"sha256"`
	// 				Sha1   string `json:"sha1"`
	// 			} `json:"fingerprint"`
	// 			Serial  int64 `json:"serial"`
	// 			Subject struct {
	// 				Cn string `json:"CN"`
	// 			} `json:"subject"`
	// 			Pubkey struct {
	// 				Type string `json:"type"`
	// 				Bits int    `json:"bits"`
	// 			} `json:"pubkey"`
	// 			Issuer struct {
	// 				C  string `json:"C"`
	// 				Cn string `json:"CN"`
	// 				O  string `json:"O"`
	// 			} `json:"issuer"`
	// 		} `json:"cert"`
	// 		Cipher struct {
	// 			Version string `json:"version"`
	// 			Bits    int    `json:"bits"`
	// 			Name    string `json:"name"`
	// 		} `json:"cipher"`
	// 		Trust struct {
	// 			Revoked bool `json:"revoked"`
	// 			Browser any  `json:"browser"`
	// 		} `json:"trust"`
	// 		HandshakeStates []string `json:"handshake_states"`
	// 		Alpn            []any    `json:"alpn"`
	// 		Ocsp            struct {
	// 		} `json:"ocsp"`
	// 	} `json:"ssl,omitempty"`
	// } `json:"data"`
	Asn   string `json:"asn"`
	IPStr string `json:"ip_str"`
}
