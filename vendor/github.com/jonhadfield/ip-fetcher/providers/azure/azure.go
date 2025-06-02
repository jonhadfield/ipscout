package azure

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"

	"github.com/jonhadfield/ip-fetcher/internal/pflog"
	"github.com/sirupsen/logrus"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ip-fetcher/internal/web"
)

const (
	ShortName             = "azure"
	FullName              = "Microsoft Azure"
	HostType              = "cloud"
	InitialURL            = "https://www.microsoft.com/en-gb/download/details.aspx?id=56519"
	WorkaroundDownloadURL = "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20250519.json"

	errFailedToDownload = "failed to retrieve azure prefixes initial page"
)

type Azure struct {
	Client      *retryablehttp.Client
	InitialURL  string
	DownloadURL string
}

func (a *Azure) ShortName() string {
	return ShortName
}

func (a *Azure) FullName() string {
	return FullName
}

func (a *Azure) HostType() string {
	return HostType
}

func (a *Azure) SourceURL() string {
	return InitialURL
}

func New() Azure {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()

	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return Azure{
		InitialURL: InitialURL,
		Client:     c,
	}
}

func (a *Azure) GetDownloadURL() (string, error) {
	if a.InitialURL == "" {
		a.InitialURL = InitialURL
	}

	client := cycletls.Init()

	var url string

	response, err := client.Do(a.InitialURL, cycletls.Options{
		Body:      "",
		Ja3:       "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0",
		UserAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
	}, "GET")
	if err != nil {
		return "", errors.New(errFailedToDownload)
	}

	if response.Status >= 400 {
		return url, errors.New(errFailedToDownload)
	}

	body := response.Body

	reATags := regexp.MustCompile("<a [^>]+>")

	aTags := reATags.FindAllString(string(body), -1)

	reHRefs := regexp.MustCompile("href=\"[^\"]+\"")

	var hrefs []string

	for _, href := range aTags {
		hrefMatches := reHRefs.FindAllString(href, -1)
		for _, hrefMatch := range hrefMatches {
			if strings.Contains(hrefMatch, "download.microsoft.com/download/") {
				hrefs = append(hrefs, hrefMatch)
			}
		}
	}

	reDownloadURL := regexp.MustCompile("(http|https)://[^\"]+")

	for _, href := range hrefs {
		url = reDownloadURL.FindString(href)
		if url != "" {
			break
		}
	}

	return url, nil
}

func (a *Azure) FetchData() (data []byte, headers http.Header, status int, err error) {
	// get download url if not specified
	if a.DownloadURL == "" {
		a.DownloadURL = WorkaroundDownloadURL
		// a.DownloadURL, err = a.GetDownloadURL()
		// if err != nil {
		// 	return
		// }
	}

	// if a.DownloadURL == "" {
	// 	a.DownloadURL = WorkaroundDownloadURL
	// }

	data, headers, status, err = web.Request(a.Client, a.DownloadURL, http.MethodGet, nil, nil, 5*time.Second)
	if status >= http.StatusBadRequest {
		return nil, nil, status, fmt.Errorf("failed to download prefixes. http status code: %d", status)
	}

	return data, headers, status, err
}

func (a *Azure) Fetch() (doc Doc, md5 string, err error) {
	data, headers, _, err := a.FetchData()
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &doc)
	if err != nil {
		return
	}

	md5 = headers.Get("Content-MD5")

	return
}

type Doc struct {
	ChangeNumber int     `json:"changeNumber"`
	Cloud        string  `json:"cloud"`
	Values       []Value `json:"values"`
}

type Value struct {
	Name       string     `json:"name"`
	ID         string     `json:"id"`
	Properties Properties `json:"properties"`
}

type Properties struct {
	ChangeNumber    int      `json:"changeNumber"`
	Region          string   `json:"region"`
	RegionID        int      `json:"regionId"`
	Platform        string   `json:"platform"`
	SystemService   string   `json:"systemService"`
	AddressPrefixes []string `json:"addressPrefixes"`
	NetworkFeatures []string `json:"networkFeatures"`
}
