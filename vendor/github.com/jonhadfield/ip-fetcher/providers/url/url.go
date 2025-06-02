package url

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jonhadfield/ip-fetcher/internal/pflog"

	"github.com/sirupsen/logrus"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ip-fetcher/internal/web"
)

func NewList() HttpFiles {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()

	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return HttpFiles{
		Urls:   []string{},
		Client: c,
	}
}

type Option func(*Client)

type Client struct {
	Debug bool
	// URLs       []url.URL
	HttpClient *retryablehttp.Client
}

func New(opt ...Option) *Client {
	pflog.SetLogLevel()

	c := new(Client)

	for _, o := range opt {
		o(c)
	}

	if c.HttpClient == nil {
		c.HttpClient = web.NewHTTPClient()
	}

	return c
}

func WithHttpClient(rc *retryablehttp.Client) Option {
	return func(c *Client) {
		c.HttpClient = rc
	}
}

type HttpFiles struct {
	Client *retryablehttp.Client
	Urls   []string
	Debug  bool
}

type HttpFile struct {
	Client *retryablehttp.Client
	Url    string
	Debug  bool
}

func (c *Client) FetchPrefixesAsText(requests []Request) (prefixes []string, err error) {
	if c.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	var responses []UrlResponse

	for _, req := range requests {
		var response UrlResponse

		if response, err = c.get(req.Url, req.Header); err != nil {
			logrus.Debugf("%s | %s", pflog.GetFunctionName(), err.Error())

			continue
		}

		responses = append(responses, response)
	}

	pum, err := GetPrefixURLMapFromUrlResponses(&responses)

	for k := range pum {
		prefixes = append(prefixes, k.String())
	}

	return
}

func (hf *HttpFiles) Add(urls []string) {
	if hf.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	for _, u := range urls {
		if _, err := url.Parse(u); err != nil {
			logrus.Infof("%s | failed to parse %s", pflog.GetFunctionName(), u)

			continue
		}

		hf.Urls = append(hf.Urls, u)
	}
}

type RawDoc struct {
	SyncToken     string `json:"syncToken"`
	CreationTime  string `json:"creationTime"`
	LastRequested time.Time
	Entries       []json.RawMessage `json:"prefixes"`
}

type (
	Responses         []UrlResponse
	PrefixesWithPaths map[netip.Prefix][]string
)

func (c *Client) FetchPrefixes(requests []Request) (prefixes map[netip.Prefix][]string, err error) {
	if c.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	var responses []UrlResponse

	for _, req := range requests {
		var response UrlResponse

		if response, err = c.get(req.Url, req.Header); err != nil {
			logrus.Debugf("%s | %s", pflog.GetFunctionName(), err.Error())

			continue
		}

		responses = append(responses, response)
	}

	prefixes, err = GetPrefixURLMapFromUrlResponses(&responses)
	if err != nil {
		return
	}
	//
	// for k := range pum {
	// 	prefixes = append(prefixes, k)
	// }

	return prefixes, nil
}

func (hf *HttpFile) FetchPrefixes() (prefixes []netip.Prefix, err error) {
	if hf.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	urlResponse, err := hf.FetchUrl()
	if err != nil {
		return
	}

	prefixes, err = ReadRawPrefixesFromUrlResponse(urlResponse)
	if err != nil {
		return
	}

	return prefixes, nil
}

func (hf *HttpFile) FetchUrl() (result UrlResponse, err error) {
	if hf.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if result, err = fetchUrlResponse(hf.Client, hf.Url); err != nil {
		logrus.Debugf("%s | %s", pflog.GetFunctionName(), err.Error())
	}

	return
}

func extractNetFromString(in string) netip.Prefix {
	funcName := pflog.GetFunctionName()

	r := regexp.MustCompile(`^[0-9a-fA-F](\S+)`)

	s := r.FindString(in)

	// ignore empty strings
	if s == "" {
		return netip.Prefix{}
	}

	if !strings.Contains(s, "/") {
		s += "/32"
	}

	p, err := netip.ParsePrefix(s)
	if err != nil {
		logrus.Tracef("%s | failed to parse %s", funcName, s)
	}

	return p
}

// ReadRawPrefixesFromFileData reads the IPs as strings from the given path
func ReadRawPrefixesFromFileData(data []byte) (ipnets []netip.Prefix, err error) {
	text := strings.Split(string(data), "\n")

	// create regex to check for lines without IPs
	var r *regexp.Regexp
	if len(text) > 0 {
		r = regexp.MustCompile(`^\s*#`)
	}

	var invalidCount int64
	var commentedCount int64
	for _, line := range text {
		// exclude comments
		if r.MatchString(line) {
			commentedCount++

			continue
		}

		if o := extractNetFromString(line); o.IsValid() {
			ipnets = append(ipnets, o)

			continue
		}

		invalidCount++
	}

	logrus.Debugf("%s | loaded %d prefixes from %d lines with %d commented and %d invalid", pflog.GetFunctionName(),
		len(ipnets), len(text), commentedCount, invalidCount)

	return
}

func ReadRawPrefixesFromUrlResponse(response UrlResponse) (prefixes []netip.Prefix, err error) {
	prefixes, err = ReadRawPrefixesFromFileData(response.data)

	return
}

func GetPrefixURLMapFromUrlResponses(responses *[]UrlResponse) (prefixesWithPaths map[netip.Prefix][]string, err error) {
	funcName := pflog.GetFunctionName()

	if responses == nil || len(*responses) == 0 {
		return nil, fmt.Errorf("%s | no responses", funcName)
	}

	prefixesWithPaths = make(map[netip.Prefix][]string)

	var responseCount int

	for _, response := range *responses {
		var ps []netip.Prefix
		ps, err = ReadRawPrefixesFromUrlResponse(response)
		if err != nil {
			logrus.Errorf("%s | %s", funcName, err.Error())
		}

		responseCount++

		logrus.Debugf("loaded %d prefixes from response %s", len(ps), response.url)

		var loadCount int64

		for _, prefix := range ps {
			prefixesWithPaths[prefix] = append(prefixesWithPaths[prefix], response.url)
			loadCount++
		}
	}

	logrus.Debugf("%s | loaded %d unique prefixes from %d response(s)", funcName, len(prefixesWithPaths), responseCount)

	return
}

type DataMap map[string][]string

type UrlResponse struct {
	url    string
	data   []byte
	status int
}

func (c *Client) get(url *url.URL, header http.Header) (result UrlResponse, err error) {
	var data []byte
	var status int

	data, _, status, err = web.Request(c.HttpClient, url.String(), http.MethodGet, header, nil, 10*time.Second)
	if err != nil {
		logrus.Debug(err.Error())
	}

	if !(status >= 200 && status <= 299) {
		return result, fmt.Errorf("failed to get: %s status: %d", url.String(), status)
	}

	return UrlResponse{
		url:    url.String(),
		data:   data,
		status: status,
	}, err
}

func fetchUrlResponse(client *retryablehttp.Client, url string) (result UrlResponse, err error) {
	var data []byte
	var status int

	data, _, status, err = web.Request(client, url, http.MethodGet, nil, nil, 10*time.Second)
	if err != nil {
		logrus.Debug(err.Error())
	}
	if !(status >= 200 && status <= 299) {
		return result, fmt.Errorf("failed to fetch: %s status: %d", url, status)
	}

	return UrlResponse{
		url:    url,
		data:   data,
		status: status,
	}, err
}

type GetInput struct {
	Url    url.URL
	Header http.Header
}

type Request struct {
	Method string
	Url    *url.URL
	Header http.Header
}

func (c *Client) Get(requests []Request) (*[]UrlResponse, error) {
	if c.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if len(requests) == 0 {
		return nil, fmt.Errorf("no URLs to fetch")
	}

	var err error

	var responses []UrlResponse

	for _, req := range requests {
		var response UrlResponse

		if response, err = c.get(req.Url, req.Header); err != nil {
			logrus.Debugf("%s | %s", pflog.GetFunctionName(), err.Error())

			return nil, fmt.Errorf("%w", err)
		}

		responses = append(responses, response)
	}

	return &responses, nil
}

func (hf *HttpFiles) FetchUrls() (results []UrlResponse, err error) {
	if hf.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if len(hf.Urls) == 0 {
		err = fmt.Errorf("no URLs to fetch")

		return
	}

	for _, hfUrl := range hf.Urls {
		var result UrlResponse
		if result, err = fetchUrlResponse(hf.Client, hfUrl); err != nil {
			logrus.Debugf("%s | %s", pflog.GetFunctionName(), err.Error())
		}

		results = append(results, result)
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
