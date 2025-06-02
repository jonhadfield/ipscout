package gcp

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/jonhadfield/ip-fetcher/internal/pflog"
	"github.com/sirupsen/logrus"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ip-fetcher/internal/web"
)

const (
	ShortName                = "gcp"
	FullName                 = "Google Cloud Platform"
	HostType                 = "cloud"
	SourceURL                = "https://cloud.google.com/compute/docs/faq#find_ip_range"
	DownloadURL              = "https://www.gstatic.com/ipranges/cloud.json"
	downloadedFileTimeFormat = "2006-01-02T15:04:05.999999"
)

func New() GCP {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()

	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return GCP{
		DownloadURL: DownloadURL,
		Client:      c,
	}
}

type GCP struct {
	Client      *retryablehttp.Client
	DownloadURL string
}

type RawDoc struct {
	SyncToken     string `json:"syncToken"`
	CreationTime  string `json:"creationTime"`
	LastRequested time.Time
	Entries       []json.RawMessage `json:"prefixes"`
}

func (gc *GCP) FetchData() (data []byte, headers http.Header, status int, err error) {
	if gc.DownloadURL == "" {
		gc.DownloadURL = DownloadURL
	}

	return web.Request(gc.Client, gc.DownloadURL, http.MethodGet, nil, nil, 10*time.Second)
}

func (gc *GCP) Fetch() (doc Doc, err error) {
	data, _, _, err := gc.FetchData()
	if err != nil {
		return
	}

	return ProcessData(data)
}

func ProcessData(data []byte) (doc Doc, err error) {
	var rawDoc RawDoc
	err = json.Unmarshal(data, &rawDoc)
	if err != nil {
		return
	}

	doc.IPv4Prefixes, doc.IPv6Prefixes, err = castEntries(rawDoc.Entries)
	if err != nil {
		return
	}

	ct, err := time.Parse(downloadedFileTimeFormat, rawDoc.CreationTime)
	if err != nil {
		return
	}

	doc.CreationTime = ct
	doc.SyncToken = rawDoc.SyncToken

	return
}

func castEntries(prefixes []json.RawMessage) (ipv4 []IPv4Entry, ipv6 []IPv6Entry, err error) {
	for _, pr := range prefixes {
		var ipv4entry RawIPv4Entry

		var ipv6entry RawIPv6Entry

		// try 4
		err = json.Unmarshal(pr, &ipv4entry)
		if err == nil {
			ipv4Prefix, parseError := netip.ParsePrefix(ipv4entry.IPv4Prefix)
			if parseError == nil {
				ipv4 = append(ipv4, IPv4Entry{
					IPv4Prefix: ipv4Prefix,
					Service:    ipv4entry.Service,
					Scope:      ipv4entry.Scope,
				})

				continue
			}
		}

		// try 6
		err = json.Unmarshal(pr, &ipv6entry)
		if err == nil {
			ipv6Prefix, parseError := netip.ParsePrefix(ipv6entry.IPv6Prefix)
			if parseError != nil {
				return ipv4, ipv6, parseError
			}

			ipv6 = append(ipv6, IPv6Entry{
				IPv6Prefix: ipv6Prefix,
				Service:    ipv6entry.Service,
				Scope:      ipv6entry.Scope,
			})

			continue
		}

		if err != nil {
			return
		}
	}

	return
}

type RawIPv4Entry struct {
	IPv4Prefix string `json:"ipv4Prefix"`
	Service    string `json:"service"`
	Scope      string `json:"scope"`
}

type RawIPv6Entry struct {
	IPv6Prefix string `json:"ipv6Prefix"`
	Service    string `json:"service"`
	Scope      string `json:"scope"`
}

type IPv4Entry struct {
	IPv4Prefix netip.Prefix `json:"ipv4Prefix"`
	Service    string       `json:"service"`
	Scope      string       `json:"scope"`
}

type IPv6Entry struct {
	IPv6Prefix netip.Prefix `json:"ipv6Prefix"`
	Service    string       `json:"service"`
	Scope      string       `json:"scope"`
}

type Doc struct {
	SyncToken    string
	CreationTime time.Time
	IPv4Prefixes []IPv4Entry
	IPv6Prefixes []IPv6Entry
}
