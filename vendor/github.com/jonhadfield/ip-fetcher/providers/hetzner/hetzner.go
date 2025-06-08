package hetzner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ip-fetcher/internal/pflog"
	"github.com/jonhadfield/ip-fetcher/internal/web"
	"github.com/sirupsen/logrus"
)

const (
	ShortName   = "hetzner"
	FullName    = "Hetzner"
	HostType    = "hosting"
	SourceURL   = "https://www.hetzner.com/"
	DownloadURL = "https://api.bgpview.io/asn/%s/prefixes"
)

var ASNs = []string{"24940", "213230", "212317", "215859"} //nolint:nolintlint,gochecknoglobals

type Hetzner struct {
	Client      *retryablehttp.Client
	DownloadURL string
	ASNs        []string
}

type BGPViewResponse struct {
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
	Data          struct {
		Ipv4Prefixes []struct {
			Prefix      string `json:"prefix"`
			IP          string `json:"ip"`
			Cidr        int    `json:"cidr"`
			RoaStatus   string `json:"roa_status"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
			Parent      struct {
				Prefix           string `json:"prefix"`
				IP               string `json:"ip"`
				Cidr             int    `json:"cidr"`
				RirName          string `json:"rir_name"`
				AllocationStatus string `json:"allocation_status"`
			} `json:"parent"`
		} `json:"ipv4_prefixes"`
		Ipv6Prefixes []struct {
			Prefix      string `json:"prefix"`
			IP          string `json:"ip"`
			Cidr        int    `json:"cidr"`
			RoaStatus   string `json:"roa_status"`
			Name        any    `json:"name"`
			Description any    `json:"description"`
			CountryCode any    `json:"country_code"`
			Parent      struct {
				Prefix           any    `json:"prefix"`
				IP               any    `json:"ip"`
				Cidr             any    `json:"cidr"`
				RirName          any    `json:"rir_name"`
				AllocationStatus string `json:"allocation_status"`
			} `json:"parent"`
		} `json:"ipv6_prefixes"`
	} `json:"data"`
	Meta struct {
		TimeZone      string `json:"time_zone"`
		APIVersion    int    `json:"api_version"`
		ExecutionTime string `json:"execution_time"`
	} `json:"@meta"`
}

func New() Hetzner {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()
	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return Hetzner{
		DownloadURL: DownloadURL,
		ASNs:        ASNs,
		Client:      c,
	}
}

func (h *Hetzner) FetchData() ([]byte, http.Header, int, error) {
	var (
		headers http.Header
		status  int
		err     error
	)
	if h.DownloadURL == "" {
		h.DownloadURL = DownloadURL
	}

	var bgpViewResponses []BGPViewResponse
	for _, asn := range h.ASNs {
		url := h.DownloadURL
		if !strings.Contains(url, "%s") {
			url = strings.TrimSuffix(url, "/") + "/%s"
		}

		url = fmt.Sprintf(url, asn)

		var body []byte
		body, headers, status, err = web.Request(h.Client, url, http.MethodGet, nil, nil, web.DefaultRequestTimeout)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("error fetching ASN %s: %w", asn, err)
		}

		if status != http.StatusOK {
			return nil, nil, status, fmt.Errorf("error: ASN %s returned status %d", asn, status)
		}

		var bgpViewResponse BGPViewResponse
		err = json.Unmarshal(body, &bgpViewResponse)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("error unmarshalling ASN %s response: %w", asn, err)
		}

		bgpViewResponses = append(bgpViewResponses, bgpViewResponse)
	}

	var doc Doc
	for _, response := range bgpViewResponses {
		for _, prefix := range response.Data.Ipv4Prefixes {
			var p netip.Prefix
			p, err = netip.ParsePrefix(prefix.Prefix)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("error parsing IPv4 prefix %s: %w", prefix.Prefix, err)
			}

			doc.IPv4Prefixes = append(doc.IPv4Prefixes, p)
		}

		for _, prefix := range response.Data.Ipv6Prefixes {
			var p netip.Prefix

			p, err = netip.ParsePrefix(prefix.Prefix)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("error parsing IPv6 prefix %s: %w", prefix.Prefix, err)
			}

			doc.IPv6Prefixes = append(doc.IPv6Prefixes, p)
		}
	}

	var jRaw json.RawMessage

	jRaw, err = json.Marshal(doc)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("error marshalling doc: %w", err)
	}

	return jRaw, headers, status, nil
}

type Doc struct {
	IPv4Prefixes []netip.Prefix `json:"IPv4Prefixes"`
	IPv6Prefixes []netip.Prefix `json:"IPv6Prefixes"`
}

func (h *Hetzner) Fetch() (Doc, error) {
	data, _, _, err := h.FetchData()
	if err != nil {
		return Doc{}, err
	}

	return ProcessData(data)
}

func ProcessData(data []byte) (Doc, error) {
	var doc Doc
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return Doc{}, fmt.Errorf("error unmarshalling Hetzner doc: %w", err)
	}

	return doc, nil
}
