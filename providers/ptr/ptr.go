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
	MaxColumnWidth         = 120
	IndentPipeHyphens      = " |-----"
	portLastModifiedFormat = "2006-01-02T15:04:05+07:00"
	ResultTTL              = time.Duration(30 * time.Minute)
	DefaultNameserver      = "9.9.9.9"
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
	return c.Session.Providers.PTR.Enabled
}

func (c *Client) GetConfig() *session.Session {
	return &c.Session
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

	var findHostData *Data
	if err := json.Unmarshal(data, &findHostData); err != nil {
		return nil, fmt.Errorf("error unmarshalling ptr data: %w", err)
	}

	if findHostData == nil {
		return nil, errors.New("no ptr data")
	}

	tw := table.NewWriter()

	for x, ptr := range findHostData.RR {
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
	tw.SetTitle("PTR | Host: %s", c.Session.Host.String())
	c.Session.Logger.Debug("ptr table created", "host", c.Session.Host.String())

	return &tw, nil
}

func loadResponse(c session.Session, nameserver string) (res *HostSearchResult, err error) {
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
		return nil, fmt.Errorf("error querying nameserver: %w", err)
	}

	if len(r.Answer) == 0 {
		return nil, providers.ErrNoDataFound
	}

	for _, ans := range r.Answer {
		if ans != nil {
			res.Data.RR = append(res.Data.RR, ans.(*dns.PTR))
		}
	}

	rd, err := json.Marshal(res.Data)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ptr data: %w", err)
	}

	res.Raw = rd

	return res, nil
}

func unmarshalResponse(data []byte) (*HostSearchResult, error) {
	var res HostSearchResult

	uData := Data{}
	if err := json.Unmarshal(data, &uData); err != nil {
		return nil, fmt.Errorf("error unmarshalling ptr data: %w", err)
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
		return res, fmt.Errorf("error decoding ptr file: %w", err)
	}

	return res, nil
}

func (ssr *HostSearchResult) CreateTable() *table.Writer {
	tw := table.NewWriter()

	return &tw
}

func loadTestData(l *slog.Logger) (*HostSearchResult, error) {
	tdf, err := loadResultsFile("providers/ptr/testdata/ptr_8_8_8_8_report.json")
	if err != nil {
		return nil, err
	}

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
		return nil, fmt.Errorf("error caching ptr response: %w", err)
	}

	return result, nil
}

type Data struct {
	Name string     `json:"name,omitempty"`
	RR   []*dns.PTR `json:"rr,omitempty"`
	Msg  dns.Msg    `json:"msg,omitempty"`
}

type HostSearchResult struct {
	Raw  json.RawMessage `json:"raw,omitempty"`
	Data Data            `json:"data,omitempty"`
}

func (data Data) MarshalJSON() ([]byte, error) {
	type Header struct {
		Name     string `dns:"cdomain-name"`
		Rrtype   uint16 `json:"rrtype,omitempty"`
		Class    uint16 `json:"class,omitempty"`
		Ttl      uint32 `json:"ttl,omitempty"` // nolint:revive
		Rdlength uint16 `json:"rdlength,omitempty"`
	}

	type ptr struct {
		Header Header `json:"header,omitempty"`
		Ptr    string `json:"ptr,omitempty"`
	}

	type myData struct {
		Name string `json:"name,omitempty"`
		RR   []*ptr `json:"rr,omitempty"`
	}

	var res myData

	res.Name = data.Name
	for _, r := range data.RR {
		res.RR = append(res.RR, &ptr{
			Header: Header{
				Name:     r.Header().Name,
				Rrtype:   r.Header().Rrtype,
				Class:    r.Header().Class,
				Ttl:      r.Header().Ttl,
				Rdlength: r.Header().Rdlength,
			},
			Ptr: r.Ptr,
		})
	}

	out, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ptr data: %w", err)
	}

	return out, nil
}
