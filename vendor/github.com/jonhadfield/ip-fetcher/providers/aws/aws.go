package aws

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/jonhadfield/ip-fetcher/internal/pflog"
	"github.com/sirupsen/logrus"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ip-fetcher/internal/web"
)

const (
	ShortName   = "aws"
	FullName    = "Amazon Web Services"
	HostType    = "cloud"
	SourceURL   = "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"
	DownloadURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
)

type AWS struct {
	Client      *retryablehttp.Client
	InitialURL  string
	DownloadURL string
}

func (a *AWS) ShortName() string {
	return ShortName
}

func (a *AWS) FullName() string {
	return FullName
}

func (a *AWS) HostType() string {
	return HostType
}

func (a *AWS) SourceURL() string {
	return SourceURL
}

func New() AWS {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()

	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return AWS{
		InitialURL: DownloadURL,
		Client:     c,
	}
}

func (a *AWS) FetchETag() (etag string, err error) {
	// get download url if not specified
	if a.DownloadURL == "" {
		a.DownloadURL = DownloadURL
		if err != nil {
			return
		}
	}

	inHeaders := http.Header{}
	inHeaders.Add("Accept", "application/json")

	var reqUrl *url.URL
	if reqUrl, err = url.Parse(a.DownloadURL); err != nil {
		return
	}

	var outHeaders http.Header

	var statusCode int

	_, outHeaders, statusCode, err = web.Request(a.Client, reqUrl.String(), http.MethodHead, inHeaders, []string{}, 5*time.Second)
	if err != nil {
		return
	}

	if statusCode != 200 {
		// err = fmt.Errorf("%s - request for aws etag resulted in status code: %d", funcName, statusCode)
		return
	}

	etag = outHeaders.Get("Etag")
	if etag != "" && len(etag) > 2 {
		TrimQuotes(&etag)
	}

	return etag, err
}

func (a *AWS) FetchData() (data []byte, headers http.Header, status int, err error) {
	// get download url if not specified
	if a.DownloadURL == "" {
		a.DownloadURL = DownloadURL
		if err != nil {
			return
		}
	}

	inHeaders := http.Header{}
	inHeaders.Add("Accept", "application/json")

	return web.Request(a.Client, a.DownloadURL, http.MethodGet, inHeaders, nil, 5*time.Second)
}

func (a *AWS) Fetch() (doc Doc, etag string, err error) {
	data, headers, _, err := a.FetchData()
	if err != nil {
		return
	}

	etag = headers.Get("Etag")
	if etag != "" && len(etag) > 2 {
		TrimQuotes(&etag)
	}

	doc, err = ProcessData(data)

	return
}

func ProcessData(data []byte) (doc Doc, err error) {
	var rawDoc RawDoc
	err = json.Unmarshal(data, &rawDoc)
	if err != nil {
		return
	}

	doc.Prefixes, err = castV4Entries(rawDoc.Prefixes)
	if err != nil {
		return
	}

	doc.IPv6Prefixes, err = castV6Entries(rawDoc.IPv6Prefixes)
	if err != nil {
		return
	}

	doc.CreateDate = rawDoc.CreateDate
	doc.SyncToken = rawDoc.SyncToken

	return
}

func castV4Entries(entries []RawPrefix) (res []Prefix, err error) {
	for _, entry := range entries {
		var p netip.Prefix
		p, err = netip.ParsePrefix(entry.IPPrefix)
		if err != nil {
			return
		}

		res = append(res, Prefix{
			IPPrefix: p,
			Region:   entry.Region,
			Service:  entry.Service,
		})
	}

	return
}

func castV6Entries(entries []RawIPv6Prefix) (res []IPv6Prefix, err error) {
	for _, entry := range entries {
		var p netip.Prefix
		p, err = netip.ParsePrefix(entry.IPv6Prefix)
		if err != nil {
			return
		}

		res = append(res, IPv6Prefix{
			IPv6Prefix: p,
			Region:     entry.Region,
			Service:    entry.Service,
		})
	}

	return
}

func TrimQuotes(in *string) {
	*in = strings.TrimPrefix(strings.TrimSuffix(*in, "\""), "\"")
}

type RawPrefix struct {
	IPPrefix string `json:"ip_prefix" yaml:"ip_prefix"`
	Region   string `json:"region" yaml:"region"`
	Service  string `json:"service" yaml:"service"`
}

type RawIPv6Prefix struct {
	IPv6Prefix string `json:"ipv6_prefix" yaml:"ipv6_prefix"`
	Region     string `json:"region" yaml:"region"`
	Service    string `json:"service" yaml:"service"`
}

type RawDoc struct {
	SyncToken    string          `json:"syncToken"`
	CreateDate   string          `json:"createDate"`
	Prefixes     []RawPrefix     `json:"prefixes" yaml:"prefixes"`
	IPv6Prefixes []RawIPv6Prefix `json:"ipv6_prefixes" yaml:"ipv6_prefixes"`
}

type Doc struct {
	SyncToken    string       `json:"syncToken"`
	CreateDate   string       `json:"createDate"`
	Prefixes     []Prefix     `json:"prefixes" yaml:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes" yaml:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix netip.Prefix `json:"ip_prefix" yaml:"ip_prefix"`
	Region   string       `json:"region" yaml:"region"`
	Service  string       `json:"service" yaml:"service"`
}

type IPv6Prefix struct {
	IPv6Prefix netip.Prefix `json:"ipv6_prefix" yaml:"ipv6_prefix"`
	Region     string       `json:"region" yaml:"region"`
	Service    string       `json:"service" yaml:"service"`
}
