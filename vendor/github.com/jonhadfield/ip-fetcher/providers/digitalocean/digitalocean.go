package digitalocean

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ip-fetcher/internal/pflog"
	"github.com/jonhadfield/ip-fetcher/internal/web"
	"github.com/jszwec/csvutil"
	"github.com/sirupsen/logrus"
)

const (
	DigitaloceanDownloadURL = "https://www.digitalocean.com/geo/google.csv"
	errFailedToDownload     = "failed to download digital ocean prefixes document "
)

type DigitalOcean struct {
	Client      *retryablehttp.Client
	DownloadURL string
}

func New() DigitalOcean {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()

	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return DigitalOcean{
		DownloadURL: DigitaloceanDownloadURL,
		Client:      c,
	}
}

func (a *DigitalOcean) FetchData() ([]byte, http.Header, int, error) {
	// get download url if not specified
	if a.DownloadURL == "" {
		a.DownloadURL = DigitaloceanDownloadURL
	}

	data, headers, status, err := web.Request(
		a.Client,
		a.DownloadURL,
		http.MethodGet,
		nil,
		nil,
		web.ShortRequestTimeout,
	)
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

func (a *DigitalOcean) Fetch() (Doc, error) {
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

	return doc, nil
}

type Entry struct {
	Network     string `csv:"network,omitempty"`
	CountryCode string `csv:"countrycode,omitempty"`
	CityCode    string `csv:"citycode,omitempty"`
	CityName    string `csv:"cityname,omitempty"`
	ZipCode     string `csv:"zipcode,omitempty"`
}

func Parse(data []byte) ([]Record, error) {
	r := csv.NewReader(bytes.NewReader(data))

	header, err := csvutil.Header(Entry{}, "csv")
	if err != nil {
		return nil, err
	}

	dec, err := csvutil.NewDecoder(r, header...)
	if err != nil {
		return nil, err
	}

	var records []Record
	for {
		var rec Record
		if err = dec.Decode(&rec); err != nil {
			if errors.Is(err, io.EOF) {
				return records, nil
			}
			// skip invalid records
			continue
		}

		p, perr := netip.ParsePrefix(rec.NetworkText)
		if perr != nil {
			return records, perr
		}
		rec.Network = p
		records = append(records, rec)
	}
}

type Record struct {
	Network     netip.Prefix
	NetworkText string `csv:"network,omitempty"`
	CountryCode string `csv:"countrycode,omitempty"`
	CityCode    string `csv:"citycode,omitempty"`
	CityName    string `csv:"cityname,omitempty"`
	ZipCode     string `csv:"zipcode,omitempty"`
}

type CSVEntry struct {
	Network     string `csv:"network,omitempty"`
	CountryCode string `csv:"countrycode,omitempty"`
	CityCode    string `csv:"citycode,omitempty"`
	CityName    string `csv:"cityname,omitempty"`
	ZipCode     string `csv:"zipcode,omitempty"`
}
