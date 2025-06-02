package icloudpr

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ip-fetcher/internal/pflog"
	"github.com/jonhadfield/ip-fetcher/internal/web"
	"github.com/jszwec/csvutil"
	"github.com/sirupsen/logrus"
)

const (
	ShortName           = "icloudpr"
	FullName            = "iCloud Private Relay"
	HostType            = "anonymiser"
	SourceURL           = "-"
	DownloadURL         = "https://mask-api.icloud.com/egress-ip-ranges.csv"
	errFailedToDownload = "failed to download iCloud Private Relay prefixes document "
)

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func extractNetFromString(in string) string {
	r := regexp.MustCompile(`^[0-9a-fA-F]([^\s]+)`)

	s := r.FindString(in)

	if !strings.Contains(s, "/") {
		switch {
		case IsIPv4(s):
			s += "/32"
		case IsIPv6(s):
			s += "/128"
		default:
			slog.Debug("failed to parse file line", "line", s)
			return ""
		}
	}

	if _, _, err := net.ParseCIDR(s); err != nil {
		slog.Debug("failed to parse file line", "line", s, "error", err)
		return ""
	}

	return s
}

type ICloudPrivateRelay struct {
	Client      *retryablehttp.Client
	DownloadURL string
}

func New() ICloudPrivateRelay {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()

	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return ICloudPrivateRelay{
		DownloadURL: DownloadURL,
		Client:      c,
	}
}

func (a *ICloudPrivateRelay) FetchData() (data []byte, headers http.Header, status int, err error) {
	// get download url if not specified
	if a.DownloadURL == "" {
		a.DownloadURL = DownloadURL
	}

	data, headers, status, err = web.Request(a.Client, a.DownloadURL, http.MethodGet, nil, nil, 5*time.Second)
	if status >= 400 {
		return nil, nil, status, fmt.Errorf("failed to download prefixes. http status code: %d", status)
	}

	return data, headers, status, err
}

type Doc struct {
	LastModified time.Time
	ETag         string
	Records      []Record
}

func (a *ICloudPrivateRelay) Fetch() (doc Doc, err error) {
	data, headers, _, err := a.FetchData()
	if err != nil {
		return
	}

	records, err := Parse(data)
	if err != nil {
		return
	}

	doc.Records = records

	var etag string

	etags := headers.Values("etag")
	if len(etags) != 0 {
		etag = etags[0]
	}

	doc.ETag = etag

	var lastModifiedTime time.Time

	lastModifiedRaw := headers.Values(web.LastModifiedHeader)
	if len(lastModifiedRaw) != 0 {
		if lastModifiedTime, err = time.Parse(time.RFC1123, lastModifiedRaw[0]); err != nil {
			return
		}
	}

	doc.LastModified = lastModifiedTime

	return doc, err
}

type Entry struct {
	Prefix     string `csv:"ip_prefix,omitempty"`
	Alpha2Code string `csv:"alpha2code,omitempty"`
	Region     string `csv:"region,omitempty"`
	City       string `csv:"city,omitempty"`
	PostalCode string `csv:"postal_code,omitempty"`
}

func Parse(data []byte) (records []Record, err error) {
	reader := bytes.NewReader(data)

	csvReader := csv.NewReader(reader)
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	doHeader, err := csvutil.Header(Entry{}, "csv")
	if err != nil {
		log.Fatal(err)
	}

	dec, err := csvutil.NewDecoder(csvReader, doHeader...)
	if err != nil {
		log.Fatal(err)
	}

Loop:
	for {
		var c Record
		err = dec.Decode(&c)

		switch err {
		case io.EOF:
			err = nil

			break Loop
		case nil:
			var pcn netip.Prefix
			if c.PrefixText == "" {
				continue
			}
			pcn, err = netip.ParsePrefix(extractNetFromString(c.PrefixText))
			if err != nil {
				return records, err
			}
			c.Prefix = pcn
			records = append(records, c)
		default:
			return
		}
	}

	return
}

// prefix, alpha2code, region, city, postal_code
type Record struct {
	Prefix     netip.Prefix
	PrefixText string `csv:"ip_prefix,omitempty"`
	Alpha2Code string `csv:"alpha2code,omitempty"`
	Region     string `csv:"region,omitempty"`
	City       string `csv:"city,omitempty"`
	PostalCode string `csv:"postal_code,omitempty"`
}

type CSVEntry struct {
	Prefix     string `csv:"ip_prefix,omitempty"`
	Alpha2Code string `csv:"alpha2code,omitempty"`
	Region     string `csv:"region,omitempty"`
	City       string `csv:"city,omitempty"`
	PostalCode string `csv:"postal_code,omitempty"`
}
