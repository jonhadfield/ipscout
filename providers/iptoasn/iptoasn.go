package iptoasn

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/jonhadfield/ipscout/providers"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "iptoasn"
	DocTTL       = 24 * time.Hour
	// DownloadURL is the combined IPv4+IPv6 ip-to-ASN dataset published by
	// iptoasn.com; the JSON API is not used as it sits behind bot protection.
	DownloadURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

	notRoutedDescription = "Not routed"
	tsvFieldCount        = 5
)

type Client struct {
	session.Session
}

type Config struct {
	_ struct{}
	session.Session
	Host netip.Addr
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating iptoasn client")

	tc := Client{
		c,
	}

	return &tc, nil
}

type Provider interface {
	LoadData() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}

func (c *Client) Enabled() bool {
	if c.UseTestData || (c.Providers.IPToASN.Enabled != nil && *c.Providers.IPToASN.Enabled) {
		return true
	}

	return false
}

func (c *Client) Priority() *int32 {
	return c.Providers.IPToASN.OutputPriority
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
}

func (c *Client) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	threatIndicators := providers.ThreatIndicators{
		Provider: ProviderName,
	}

	indicators := make(map[string]string)

	indicators["CountryCode"] = doc.ASCountryCode

	threatIndicators.Indicators = indicators

	return &threatIndicators, nil
}

func (c *Client) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	rateResult.Score = 0
	rateResult.Detected = false

	if doc.ASCountryCode != "" {
		i := slices.Index(ratingConfig.Global.HighThreatCountryCodes, doc.ASCountryCode)
		if i != -1 {
			rateResult.Detected = true
			rateResult.Score += 9
			rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("High Threat Country: %s", doc.ASCountryCode))
		} else {
			i := slices.Index(ratingConfig.Global.MediumThreatCountryCodes, doc.ASCountryCode)
			if i != -1 {
				rateResult.Detected = true
				rateResult.Score += 7
				rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("Medium Threat Country: %s", doc.ASCountryCode))
			}
		}
	}

	return rateResult, nil
}

func (c *Client) loadProviderDataFromSource() error {
	downloadURL := DownloadURL
	if c.Providers.IPToASN.URL != "" {
		downloadURL = c.Providers.IPToASN.URL
		c.Logger.Debug("overriding iptoasn source", "url", downloadURL)
	}

	req, err := retryablehttp.NewRequest(http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("error creating iptoasn request: %w", err)
	}

	req.Header.Set("User-Agent", providers.DefaultUA)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("error fetching iptoasn data: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("iptoasn download failed: %s: %w", resp.Status, providers.ErrFailedToFetchData)
	}

	// store the gzipped TSV as-is; FindHost decompresses when scanning
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading iptoasn data: %w", err)
	}

	c.Logger.Debug("writing iptoasn provider data to cache", "size", len(data))

	docCacheTTL := DocTTL
	if c.Providers.IPToASN.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.IPToASN.DocumentCacheTTL)
	}

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL); err != nil {
		return fmt.Errorf("error writing iptoasn provider data to cache: %w", err)
	}

	return nil
}

func (c *Client) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising iptoasn client")

	if c.UseTestData {
		return nil
	}

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("error checking cache for iptoasn provider data: %w", err)
	}

	if ok {
		c.Logger.Debug("iptoasn provider data found in cache")

		return nil
	}

	return c.loadProviderDataFromSource()
}

func (c *Client) loadProviderDataFromCache() ([]byte, error) {
	c.Logger.Debug("loading iptoasn provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	item, err := cache.Read(c.Logger, c.Cache, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("error reading iptoasn provider data from cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return item.Value, nil
}

func (c *Client) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	if c.UseTestData {
		result, err := loadTestData(c.Logger)
		if err != nil {
			return nil, fmt.Errorf("error loading iptoasn test data: %w", err)
		}

		return result.Raw, nil
	}

	data, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, err
	}

	result, err := matchHost(data, c.Host)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("error marshalling iptoasn result: %w", err)
	}

	c.Logger.Debug("iptoasn host match data", "size", len(raw))

	return raw, nil
}

// matchHost scans the gzipped ip2asn TSV for the range containing host. Lines
// are `first_ip<tab>last_ip<tab>as_number<tab>country_code<tab>description`,
// sorted ascending within each address family (IPv4 ranges before IPv6), so
// scanning stops as soon as the host's position is passed.
func matchHost(gzData []byte, host netip.Addr) (*iptoasnResp, error) {
	gz, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		return nil, fmt.Errorf("error decompressing iptoasn data: %w", err)
	}

	defer gz.Close()

	host = host.Unmap()

	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "\t", tsvFieldCount)
		if len(fields) < tsvFieldCount {
			continue
		}

		firstIP, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}

		if firstIP.Is4() != host.Is4() {
			if host.Is4() && !firstIP.Is4() {
				// passed the end of the IPv4 section
				break
			}

			continue
		}

		if firstIP.Compare(host) > 0 {
			// ranges are sorted, so the host cannot appear later
			break
		}

		lastIP, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}

		if lastIP.Compare(host) < 0 {
			continue
		}

		asNumber, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || asNumber == 0 || fields[4] == notRoutedDescription {
			// hosts in unrouted ranges have no ASN details
			break
		}

		return &iptoasnResp{
			Announced:     true,
			ASNumber:      uint32(asNumber),
			ASCountryCode: fields[3],
			ASDescription: fields[4],
			FirstIP:       fields[0],
			LastIP:        fields[1],
			IP:            host.String(),
		}, nil
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning iptoasn data: %w", err)
	}

	return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
}

func (c *Client) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	if data == nil {
		return nil, nil
	}

	var findHostData HostSearchResult
	if err := json.Unmarshal(data, &findHostData); err != nil {
		return nil, fmt.Errorf("error unmarshalling iptoasn data: %w", err)
	}

	// don't render if the host isn't announced by any AS
	if !findHostData.Announced {
		return nil, nil
	}

	tw := table.NewWriter()
	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("ASN", providers.Column1MinWidth), providers.DashIfEmpty(fmt.Sprintf("AS%d", findHostData.ASNumber))})
	tw.AppendRow(table.Row{"AS Name", providers.DashIfEmpty(findHostData.ASDescription)})
	tw.AppendRow(table.Row{"Country", providers.DashIfEmpty(findHostData.ASCountryCode)})
	tw.AppendRow(table.Row{"Range", providers.DashIfEmpty(findHostData.FirstIP + " - " + findHostData.LastIP)})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
		{Number: 1, AutoMerge: true},
	})

	tw.SetAutoIndex(false)
	tw.SetTitle("IPtoASN | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("IPtoASN | Host: 8.8.8.8")
	}

	c.Logger.Debug("iptoasn table created", "host", c.Host.String())

	return &tw, nil
}

type iptoasnResp struct {
	Announced     bool   `json:"announced"`
	ASNumber      uint32 `json:"as_number"`
	ASCountryCode string `json:"as_country_code"`
	ASDescription string `json:"as_description"`
	FirstIP       string `json:"first_ip"`
	LastIP        string `json:"last_ip"`
	IP            string `json:"ip"`
}

func loadResultsFile(path string) (*HostSearchResult, error) {
	jf, err := os.Open(path) // #nosec G304 -- path is the provider's own test data file
	if err != nil {
		return nil, fmt.Errorf("error opening iptoasn file: %w", err)
	}

	defer jf.Close()

	var res HostSearchResult

	decoder := json.NewDecoder(jf)

	if err = decoder.Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding iptoasn file: %w", err)
	}

	return &res, nil
}

func loadTestData(l *slog.Logger) (*HostSearchResult, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/iptoasn/testdata/iptoasn_8_8_8_8_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting iptoasn test data file path: %w", err)
	}

	tdf, err := loadResultsFile(resultsFile)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling iptoasn test data: %w", err)
	}

	tdf.Raw = raw

	l.Debug("iptoasn match returned from test data", "host", "8.8.8.8")

	return tdf, nil
}

type HostSearchResult struct {
	Raw json.RawMessage `json:"raw,omitempty"`
	iptoasnResp
}
