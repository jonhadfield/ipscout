package aws

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

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

func (a *AWS) FetchETag() (string, error) {
	var err error
	// get download url if not specified
	if a.DownloadURL == "" {
		a.DownloadURL = DownloadURL
	}

	inHeaders := http.Header{}
	inHeaders.Add("Accept", "application/json")

	var reqUrl *url.URL
	if reqUrl, err = url.Parse(a.DownloadURL); err != nil {
		return "", err
	}

	var outHeaders http.Header

	var statusCode int

	_, outHeaders, statusCode, err = web.Request(a.Client, reqUrl.String(), http.MethodHead, inHeaders, []string{}, web.ShortRequestTimeout)
	if err != nil {
		return "", err
	}

	if statusCode != http.StatusOK {
		// err = fmt.Errorf("%s - request for aws etag resulted in status code: %d", funcName, statusCode)
		return "", nil
	}

	etag := outHeaders.Get("Etag")
	if etag != "" && len(etag) > 2 {
		TrimQuotes(&etag)
	}

	return etag, nil
}

func (a *AWS) FetchData() ([]byte, http.Header, int, error) {
	// get download url if not specified
	if a.DownloadURL == "" {
		a.DownloadURL = DownloadURL
	}

	inHeaders := http.Header{}
	inHeaders.Add("Accept", "application/json")

	return web.Request(a.Client, a.DownloadURL, http.MethodGet, inHeaders, nil, web.ShortRequestTimeout)
}

func (a *AWS) Fetch() (Doc, string, error) {
	data, headers, _, err := a.FetchData()
	if err != nil {
		return Doc{}, "", err
	}

	etag := headers.Get("Etag")
	if etag != "" && len(etag) > 2 {
		TrimQuotes(&etag)
	}

	doc, err := ProcessData(data)

	return doc, etag, err
}

func ProcessData(data []byte) (Doc, error) {
	var rawDoc RawDoc
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		return Doc{}, err
	}

	prefixes, err := castV4Entries(rawDoc.Prefixes)
	if err != nil {
		return Doc{}, err
	}

	ipv6Prefixes, err := castV6Entries(rawDoc.IPv6Prefixes)
	if err != nil {
		return Doc{}, err
	}

	return Doc{
		Prefixes:     prefixes,
		IPv6Prefixes: ipv6Prefixes,
		CreateDate:   rawDoc.CreateDate,
		SyncToken:    rawDoc.SyncToken,
	}, nil
}

func castV4Entries(entries []RawPrefix) ([]Prefix, error) {
	var res []Prefix
	for _, entry := range entries {
		p, err := netip.ParsePrefix(entry.IPPrefix)
		if err != nil {
			return res, err
		}

		res = append(res, Prefix{
			IPPrefix: p,
			Region:   entry.Region,
			Service:  entry.Service,
		})
	}

	return res, nil
}

func castV6Entries(entries []RawIPv6Prefix) ([]IPv6Prefix, error) {
	var res []IPv6Prefix
	for _, entry := range entries {
		p, err := netip.ParsePrefix(entry.IPv6Prefix)
		if err != nil {
			return res, err
		}

		res = append(res, IPv6Prefix{
			IPv6Prefix: p,
			Region:     entry.Region,
			Service:    entry.Service,
		})
	}

	return res, nil
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
