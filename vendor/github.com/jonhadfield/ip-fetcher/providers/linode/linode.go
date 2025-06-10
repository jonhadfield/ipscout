package linode

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
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
	ShortName           = "linode"
	FullName            = "Linode"
	HostType            = "hosting"
	SourceURL           = "-"
	DownloadURL         = "https://geoip.linode.com/"
	errFailedToDownload = "failed to download Linode prefixes document "
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

type Linode struct {
	Client      *retryablehttp.Client
	DownloadURL string
}

func New() Linode {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()

	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return Linode{
		DownloadURL: DownloadURL,
		Client:      c,
	}
}

func (a *Linode) FetchData() ([]byte, http.Header, int, error) {
	var (
		data    []byte
		headers http.Header
		status  int
		err     error
	)
	// get download url if not specified
	if a.DownloadURL == "" {
		a.DownloadURL = DownloadURL
	}

	data, headers, status, err = web.Request(a.Client, a.DownloadURL, http.MethodGet, nil, nil, web.ShortRequestTimeout)
	if status >= http.StatusBadRequest {
		return nil, nil, status, fmt.Errorf("failed to download prefixes. http status code: %d", status)
	}

	return data, headers, status, err
}

type Doc struct {
	LastModified time.Time
	ETag         string
	Records      []Record
}

func (a *Linode) Fetch() (Doc, error) {
	data, headers, _, err := a.FetchData()
	if err != nil {
		return Doc{}, err
	}

	records, err := Parse(data)
	if err != nil {
		return Doc{}, err
	}

	var doc Doc
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
			return Doc{}, err
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

func Parse(data []byte) ([]Record, error) {
	var (
		records []Record
		err     error
	)

	reader := bytes.NewReader(data)

	csvReader := csv.NewReader(reader)
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	doHeader, err := csvutil.Header(Entry{}, "csv")
	if err != nil {
		return records, err
	}

	dec, err := csvutil.NewDecoder(csvReader, doHeader...)
	if err != nil {
		return records, err
	}

Loop:
	for {
		var c Record
		err = dec.Decode(&c)

		switch {
		case errors.Is(err, io.EOF):
			err = nil
			break Loop
		case err == nil:
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
			return records, err
		}
	}

	return records, nil
}

// Record holds prefix, alpha2code, region, city and postal_code.
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
