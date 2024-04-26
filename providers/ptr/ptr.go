package ptr

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/config"
)

const (
	ProviderName           = "ptr"
	MaxColumnWidth         = 120
	IndentPipeHyphens      = " |-----"
	portLastModifiedFormat = "2006-01-02T15:04:05+07:00"
	ResultTTL              = time.Duration(30 * time.Minute)
	DefaultNameserver      = "9.9.9.9"
)

type Client struct {
	Config     Config
	HTTPClient *retryablehttp.Client
}

type Config struct {
	_ struct{}
	config.Config
	Host   netip.Addr
	APIKey string
}

func NewProviderClient(c config.Config) (*ProviderClient, error) {
	c.Logger.Debug("creating ptr client")

	tc := &ProviderClient{
		c,
	}

	return tc, nil
}

func (c *Client) GetConfig() *config.Config {
	return &c.Config.Config
}

type Provider interface {
	LoadData() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}

func (c *ProviderClient) Enabled() bool {
	return c.Config.Providers.PTR.Enabled
}

func (c *ProviderClient) GetConfig() *config.Config {
	return &c.Config
}

type ProviderClient struct {
	config.Config
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return errors.New("cache not set")
	}

	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	c.Logger.Debug("initialising ptr client")

	return nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	result, err := fetchData(c.Config)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("ptr host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	var findHostData *Data
	if err := json.Unmarshal(data, &findHostData); err != nil {
		return nil, fmt.Errorf("error unmarshalling ptr data: %w", err)
	}

	if findHostData == nil {
		return nil, errors.New("no ptr data")
	}

	tw := table.NewWriter()
	for x, ptr := range findHostData.PTR {
		tw.AppendRow(table.Row{fmt.Sprintf("RR[%d]", x+1), ptr})
	}
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: true, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("PTR | Host: %s", c.Host.String())

	c.Logger.Debug("ptr table created", "host", c.Host.String())

	return &tw, nil
}

func loadResponse(c config.Config, nameserver string) (res *HostSearchResult, err error) {
	res = &HostSearchResult{}

	target := c.Host.String()

	if nameserver == "" {
		nameserver = DefaultNameserver
	}

	arpa, err := dns.ReverseAddr(target)
	if err != nil {
		log.Fatal(err)
	}

	dc := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(arpa, dns.TypePTR)
	r, _, err := dc.Exchange(&m, nameserver+":53")
	if err != nil {
		log.Fatal(err)
	}
	if len(r.Answer) == 0 {
		log.Fatal("no results")
	}

	for _, ans := range r.Answer {
		if ans != nil {
			res.Data.PTR = append(res.Data.PTR, ans.(*dns.PTR))
		}
	}

	rd, err := json.Marshal(res.Data)
	if err != nil {
		return nil, err
	}

	res.Raw = rd

	// res.Data.PTR = r.Answer[0].(*dns.PTR)
	return res, nil
}

func unmarshalResponse(data []byte) (*HostSearchResult, error) {
	var res HostSearchResult

	uData := Data{}
	if err := json.Unmarshal(data, &uData); err != nil {
		return nil, err
	}
	res.Raw = data
	res.Data = uData
	return &res, nil
}

func loadResultsFile(path string) (res *HostSearchResult, err error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening ptr file: %w", err)
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func (ssr *HostSearchResult) CreateTable() *table.Writer {
	tw := table.NewWriter()

	return &tw
}

func fetchData(c config.Config) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if c.UseTestData {
		result, err = loadResultsFile("providers/ptr/testdata/ptr_google_dns_resp.json")
		if err != nil {
			return nil, fmt.Errorf("error loading ptr test data: %w", err)
		}

		return result, nil
	}

	// load data from cache
	cacheKey := fmt.Sprintf("ptr_%s_report.json", strings.ReplaceAll(c.Host.String(), ".", "_"))
	var item *cache.Item
	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		if item.Value != nil && len(item.Value) > 0 {
			result, err = unmarshalResponse(item.Value)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling cached ptr response: %w", err)
			}

			c.Logger.Info("ptr response found in cache", "host", c.Host.String())

			result.Raw = item.Value

			c.Stats.Mu.Lock()
			c.Stats.FindHostUsedCache[ProviderName] = true
			c.Stats.Mu.Unlock()

			return result, nil
		}
	}

	result, err = loadResponse(c, "")
	if err != nil {
		return nil, fmt.Errorf("loading ptr api response: %w", err)
	}

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, ResultTTL); err != nil {
		return nil, err
	}

	return result, nil
}

type Data struct {
	Name string     `json:"name,omitempty"`
	PTR  []*dns.PTR `json:"ptr,omitempty"`
	Msg  dns.Msg    `json:"msg,omitempty"`
}

type HostSearchResult struct {
	Raw  []byte `json:"raw"`
	Data Data   `json:"data,omitempty"`
}
