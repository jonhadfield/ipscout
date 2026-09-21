package internetdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "internetdb"
	ResultTTL    = 12 * time.Hour
	apiDomain    = "https://internetdb.shodan.io"
)

type Client struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating internetdb client")

	tc := Client{
		c,
	}

	return &tc, nil
}

func (c *Client) Enabled() bool {
	if c.UseTestData || (c.Providers.InternetDB.Enabled != nil && *c.Providers.InternetDB.Enabled) {
		return true
	}

	return false
}

func (c *Client) Priority() *int32 {
	return c.Providers.InternetDB.OutputPriority
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
}

func (c *Client) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	return &providers.ThreatIndicators{
		Provider: ProviderName,
		Indicators: map[string]string{
			"OpenPorts": strconv.Itoa(len(doc.Ports)),
			"Vulns":     strconv.Itoa(len(doc.Vulns)),
			"Tags":      strings.Join(doc.Tags, ","),
		},
	}, nil
}

func (c *Client) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	scores := ratingConfig.ProviderRatingsConfigs.InternetDB

	var rateResult providers.RateResult

	if len(doc.Ports) > 0 {
		rateResult.Detected = true
		rateResult.Score = scores.OpenPortsScore
		rateResult.Reasons = append(rateResult.Reasons, "has open ports")
	}

	if len(doc.Vulns) > 0 {
		rateResult.Detected = true
		rateResult.Score = max(rateResult.Score, scores.VulnsScore)
		rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("has %d known vulnerabilities", len(doc.Vulns)))
	}

	return rateResult, nil
}

func (c *Client) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising internetdb client")

	return nil
}

func (c *Client) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("internetdb host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (c *Client) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	if data == nil {
		return nil, nil
	}

	var doc HostSearchResult
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("error unmarshalling internetdb data: %w", err)
	}

	if doc.empty() {
		return nil, nil
	}

	ports := make([]string, 0, len(doc.Ports))
	for _, p := range doc.Ports {
		ports = append(ports, strconv.Itoa(p))
	}

	vulns := slices.Clone(doc.Vulns)
	slices.Sort(vulns)

	tw := table.NewWriter()
	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Open Ports", providers.Column1MinWidth), providers.DashIfEmpty(strings.Join(ports, ", "))})
	tw.AppendRow(table.Row{"Hostnames", providers.DashIfEmpty(strings.Join(doc.Hostnames, ", "))})
	tw.AppendRow(table.Row{"Tags", providers.DashIfEmpty(strings.Join(doc.Tags, ", "))})
	tw.AppendRow(table.Row{"Software", providers.DashIfEmpty(strings.Join(doc.CPEs, ", "))})
	tw.AppendRow(table.Row{"Vulns", providers.DashIfEmpty(strings.Join(vulns, ", "))})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
		{Number: 1, AutoMerge: true},
	})

	tw.SetAutoIndex(false)
	tw.SetTitle("INTERNETDB | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("INTERNETDB | Host: %s", doc.IP)
	}

	c.Logger.Debug("internetdb table created", "host", c.Host.String())

	return &tw, nil
}

type HostSearchResult struct {
	Raw       json.RawMessage `json:"raw,omitempty"`
	IP        string          `json:"ip"`
	Ports     []int           `json:"ports"`
	Hostnames []string        `json:"hostnames"`
	Tags      []string        `json:"tags"`
	CPEs      []string        `json:"cpes"`
	Vulns     []string        `json:"vulns"`
}

func (r HostSearchResult) empty() bool {
	return len(r.Ports) == 0 && len(r.Hostnames) == 0 && len(r.Tags) == 0 && len(r.CPEs) == 0 && len(r.Vulns) == 0
}

func loadResponse(c session.Session) (*HostSearchResult, error) {
	req, err := retryablehttp.NewRequest("GET", fmt.Sprintf("%s/%s", apiDomain, c.Host.String()), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating internetdb request: %w", err)
	}

	req.Header.Set("User-Agent", providers.DefaultUA)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending internetdb request: %w", err)
	}

	defer resp.Body.Close()

	// InternetDB answers 404 for an address it has no data on
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("internetdb returned unexpected status: %d", resp.StatusCode)
	}

	var res HostSearchResult

	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding internetdb response: %w", err)
	}

	raw, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("error marshalling internetdb response: %w", err)
	}

	res.Raw = raw

	return &res, nil
}

func loadResultsFile(path string) (*HostSearchResult, error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening internetdb file: %w", err)
	}

	defer jf.Close()

	var res HostSearchResult

	if err = json.NewDecoder(jf).Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding internetdb file: %w", err)
	}

	return &res, nil
}

func loadTestData(l *slog.Logger) (*HostSearchResult, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/internetdb/testdata/internetdb_8_8_4_4_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting internetdb test data file path: %w", err)
	}

	tdf, err := loadResultsFile(resultsFile)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling internetdb test data: %w", err)
	}

	tdf.Raw = raw

	l.Info("internetdb match returned from test data", "host", tdf.IP)

	return tdf, nil
}

func fetchData(c session.Session) (*HostSearchResult, error) {
	if c.UseTestData {
		result, err := loadTestData(c.Logger)
		if err != nil {
			return nil, fmt.Errorf("error loading internetdb test data: %w", err)
		}

		return result, nil
	}

	// InternetDB returns scan results for private addresses too, which say
	// nothing about the host being looked up
	if !c.Host.IsGlobalUnicast() || c.Host.IsPrivate() {
		return nil, fmt.Errorf("%s: %s is not a public address: %w", ProviderName, c.Host, providers.ErrNoMatchFound)
	}

	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + strings.ReplaceAll(c.Host.String(), ".", "_")

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil && item != nil && len(item.Value) > 0 {
		var result HostSearchResult

		if err = json.Unmarshal(item.Value, &result); err != nil {
			return nil, fmt.Errorf("error unmarshalling cached internetdb response: %w", err)
		}

		c.Logger.Debug("internetdb response found in cache", "host", c.Host.String())

		result.Raw = item.Value

		c.Stats.Mu.Lock()
		c.Stats.FindHostUsedCache[ProviderName] = true
		c.Stats.Mu.Unlock()

		return &result, nil
	}

	result, err := loadResponse(c)
	if err != nil {
		if errors.Is(err, providers.ErrNoMatchFound) {
			return nil, err
		}

		return nil, fmt.Errorf("loading internetdb api response: %w", err)
	}

	resultTTL := ResultTTL
	if c.Providers.InternetDB.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(c.Providers.InternetDB.ResultCacheTTL)
	}

	c.Logger.Debug("caching internetdb response", "duration", resultTTL.String())

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching internetdb response: %w", err)
	}

	return result, nil
}
