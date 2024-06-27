package ptr

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/providers"

	"github.com/miekg/dns"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName           = "ptr"
	portLastModifiedFormat = "2006-01-02T15:04:05+07:00"
	ResultTTL              = 30 * time.Minute
	DefaultNameserver      = "1.1.1.1:53"
)

type Client struct {
	session.Session
}

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating ptr client")

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
	if c.UseTestData || (c.Session.Providers.PTR.Enabled != nil && *c.Session.Providers.PTR.Enabled) {
		return true
	}

	return false
}

func (c *Client) Priority() *int32 {
	return c.Session.Providers.PTR.OutputPriority
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
}

func (c *Client) Rate(findRes []byte) (providers.RateResult, error) {
	return providers.RateResult{}, nil
}

func (c *Client) Initialise() error {
	if c.Session.Cache == nil {
		return errors.New("cache not set")
	}

	start := time.Now()
	defer func() {
		c.Session.Stats.Mu.Lock()
		c.Session.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Session.Stats.Mu.Unlock()
	}()

	c.Session.Logger.Debug("initialising ptr client")

	return nil
}

func (c *Client) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Session.Stats.Mu.Lock()
		c.Session.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Session.Stats.Mu.Unlock()
	}()

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Session.Logger.Debug("ptr host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (c *Client) CreateTable(data []byte) (*table.Writer, error) {
	start := time.Now()
	defer func() {
		c.Session.Stats.Mu.Lock()
		c.Session.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Session.Stats.Mu.Unlock()
	}()

	var findHostData HostSearchResult
	if err := json.Unmarshal(data, &findHostData); err != nil {
		return nil, fmt.Errorf("error unmarshalling ptr data: %w", err)
	}

	if len(findHostData.RR) == 0 {
		return nil, errors.New("no ptr data")
	}

	tw := table.NewWriter()

	tw.AppendHeader(table.Row{" ", "PTR", "Name", "TTL", "Rdlength", "Class", "Rrtype"})

	for x, ptr := range findHostData.RR {
		tw.AppendRow(table.Row{fmt.Sprintf("RR[%d]", x+1), ptr.Ptr, ptr.Header.Name, ptr.Header.Ttl, ptr.Header.Rdlength, ptr.Header.Class, ptr.Header.Rrtype})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: 15},
	})
	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("PTR | Host: %s", c.Session.Host.String())
	c.Session.Logger.Debug("ptr table created", "host", c.Session.Host.String())

	return &tw, nil
}

func loadResponse(c session.Session) (res *HostSearchResult, err error) {
	res = &HostSearchResult{}

	target := c.Host.String()

	arpa, err := dns.ReverseAddr(target)
	if err != nil {
		log.Fatal(err)
	}

	dc := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(arpa, dns.TypePTR)

	if len(c.Providers.PTR.Nameservers) == 0 {
		c.Providers.PTR.Nameservers = append(c.Providers.PTR.Nameservers, DefaultNameserver)
	}

	for _, nameserver := range c.Providers.PTR.Nameservers {
		if !strings.Contains(nameserver, ":") {
			nameserver += ":53"
		}

		var r *dns.Msg

		r, _, err = dc.Exchange(&m, nameserver)
		if err != nil {
			c.Logger.Info("ptr query failure", "nameserver", nameserver, "error", err)

			continue
		}

		if len(r.Answer) == 0 {
			return nil, providers.ErrNoDataFound
		}

		for _, ans := range r.Answer {
			if ans != nil {
				rRes := ans.(*dns.PTR)

				var newPtr Ptr

				newPtr.Ptr = rRes.Ptr
				rHeader := rRes.Header()
				newPtr.Header = Header{
					Name:     rHeader.Name,
					Ttl:      rHeader.Ttl,
					Rdlength: rHeader.Rdlength,
					Class:    rHeader.Class,
					Rrtype:   rHeader.Rrtype,
				}
				res.RR = append(res.RR, &newPtr)
			}
		}

		rd, err := json.Marshal(res)
		if err != nil {
			return nil, fmt.Errorf("error marshalling ptr data: %w", err)
		}

		res.Raw = rd
	}

	return res, nil
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
		return res, fmt.Errorf("error decoding ptr file: %w", err)
	}

	return res, nil
}

func loadTestData(l *slog.Logger) (*HostSearchResult, error) {
	tdf, err := loadResultsFile("providers/ptr/testdata/ptr_8_8_8_8_report.json")
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ptr test data: %w", err)
	}

	tdf.Raw = raw

	l.Info("ptr match returned from test data", "host", "8.8.8.8")

	return tdf, nil
}

func fetchData(c session.Session) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if c.UseTestData {
		result, err = loadTestData(c.Logger)
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
			err = json.Unmarshal(item.Value, &result)
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

	result, err = loadResponse(c)
	if err != nil {
		return nil, fmt.Errorf("loading ptr api response: %w", err)
	}

	resultTTL := ResultTTL
	if c.Providers.PTR.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(c.Providers.PTR.ResultCacheTTL)
	}

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching ptr response: %w", err)
	}

	return result, nil
}

type HostSearchResult struct {
	Raw json.RawMessage `json:"raw,omitempty"`
	RR  []*Ptr          `json:"rr,omitempty"`
	Msg dns.Msg         `json:"msg,omitempty"`
}

type Ptr struct {
	Header Header `json:"header,omitempty"`
	Ptr    string `json:"ptr,omitempty"`
}

type Header struct {
	Name     string `dns:"cdomain-name"`
	Rrtype   uint16 `json:"rrtype,omitempty"`
	Class    uint16 `json:"class,omitempty"`
	Ttl      uint32 `json:"ttl,omitempty"` //nolint:stylecheck
	Rdlength uint16 `json:"rdlength,omitempty"`
}
