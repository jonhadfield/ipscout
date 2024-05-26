package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/fatih/color"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName           = "virustotal"
	APIURL                 = "https://www.virustotal.com"
	HostIPPath             = "/api/v3/ip_addresses"
	IndentPipeHyphens      = " |-----"
	portLastModifiedFormat = "2006-01-02T15:04:05.999999"
	ResultTTL              = 12 * time.Hour
)

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

type Provider interface {
	LoadData() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}

type ProviderClient struct {
	session.Session
}

func (c *ProviderClient) Enabled() bool {
	vtot := c.Session.Providers.VirusTotal
	if vtot.APIKey != "" && (c.Session.Providers.VirusTotal.Enabled != nil && *c.Session.Providers.VirusTotal.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() int {
	return 100
}

func loadAPIResponse(ctx context.Context, c session.Session, apiKey string) (res *HostSearchResult, err error) {
	urlPath, err := url.JoinPath(APIURL, HostIPPath, c.Host.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create virustotal api url path: %w", err)
	}

	sURL, err := url.Parse(urlPath)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, sURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("x-apikey", apiKey) //nolint:canonicalheader

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal api request failed: %s", resp.Status)
	}

	// read response body
	rBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading virustotal response: %w", err)
	}

	defer resp.Body.Close()

	if rBody == nil {
		return nil, providers.ErrNoDataFound
	}

	res, err = unmarshalResponse(rBody)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	res.Raw = rBody

	if res.Raw == nil {
		return nil, fmt.Errorf("virustotal: %w", providers.ErrNoMatchFound)
	}

	return res, nil
}

func unmarshalResponse(data []byte) (*HostSearchResult, error) {
	var res HostSearchResult

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling virustotal data: %w", err)
	}

	res.Raw = data

	return &res, nil
}

func loadResultsFile(path string) (res *HostSearchResult, err error) {
	// get raw data
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading virustotal file: %w", err)
	}

	// unmarshal data
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening virustotal file: %w", err)
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, fmt.Errorf("error decoding virustotal file: %w", err)
	}

	res.Raw = raw

	return res, nil
}

func (ssr *HostSearchResult) CreateTable() *table.Writer {
	tw := table.NewWriter()

	return &tw
}

type Client struct {
	Config     Config
	HTTPClient *retryablehttp.Client
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func fetchData(c session.Session) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if c.UseTestData {
		result, err = loadResultsFile("providers/virustotal/testdata/virustotal_google_dns_resp.json")
		if err != nil {
			return nil, fmt.Errorf("error loading virustotal test data: %w", err)
		}

		return result, nil
	}

	// load data from cache
	cacheKey := fmt.Sprintf("virustotal_%s_report.json", strings.ReplaceAll(c.Host.String(), ".", "_"))

	var item *cache.Item

	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		if item.Value != nil && len(item.Value) > 0 {
			result, err = unmarshalResponse(item.Value)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling cached virustotal response: %w", err)
			}

			c.Logger.Info("virustotal response found in cache", "host", c.Host.String())

			result.Raw = item.Value

			c.Stats.Mu.Lock()
			c.Stats.FindHostUsedCache[ProviderName] = true
			c.Stats.Mu.Unlock()

			return result, nil
		}
	}

	result, err = loadAPIResponse(context.Background(), c, c.Providers.VirusTotal.APIKey)
	if err != nil {
		return nil, fmt.Errorf("loading virustotal api response: %w", err)
	}

	resultTTL := ResultTTL
	if c.Providers.VirusTotal.ResultCacheTTL != 0 {
		resultTTL = time.Minute * time.Duration(c.Providers.VirusTotal.ResultCacheTTL)
	}

	c.Logger.Debug("caching virustotal response", "duration", resultTTL.String())

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        cacheKey,
		Value:      result.Raw,
		Created:    time.Now(),
	}, resultTTL); err != nil {
		return nil, fmt.Errorf("error caching virustotal response: %w", err)
	}

	return result, nil
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

	c.Logger.Debug("initialising virustotal client")

	if c.Providers.VirusTotal.APIKey == "" && !c.UseTestData {
		return fmt.Errorf("virustotal provider api key not set")
	}

	return nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	result, err := fetchData(c.Session)
	if err != nil {
		return nil, err
	}

	c.Logger.Debug("virustotal host match data", "size", len(result.Raw))

	return result.Raw, nil
}

func (ard AnalysisResultData) ResultHasAny(v []string) bool {
	for x := range v {
		if strings.Contains(ard.Result, v[x]) {
			return true
		}
	}

	return false
}

func (ard AnalysisResultData) GetMethod() string {
	return ard.Method
}

func (ard AnalysisResultData) GetEngineName() string {
	return ard.EngineName
}

func (ard AnalysisResultData) GetCategory() string {
	return ard.Category
}

func (ard AnalysisResultData) GetResult() string {
	return ard.Result
}

func (ard AnalysisResultData) ShouldOutput(sess *session.Session) bool {
	if sess.Providers.VirusTotal.ShowProviders == nil || !*sess.Providers.VirusTotal.ShowProviders {
		return false
	}

	switch ard.Result {
	case "clean":
		if sess.Providers.VirusTotal.ShowClean != nil && *sess.Providers.VirusTotal.ShowClean {
			return true
		}

	case "unrated":
		if sess.Providers.VirusTotal.ShowUnrated != nil && *sess.Providers.VirusTotal.ShowUnrated {
			return true
		}

	case "harmless":
		if sess.Providers.VirusTotal.ShowHarmless != nil && *sess.Providers.VirusTotal.ShowHarmless {
			return true
		}

	case "suspicous":
		return true
	case "malicious":
		return true
	default:
		return false
	}

	return false
}

func (lra LastAnalysisResults) ShouldOutput(sess *session.Session) bool {
	if sess.Providers.VirusTotal.ShowProviders == nil || !*sess.Providers.VirusTotal.ShowProviders {
		return false
	}

	return true
}

func (lra LastAnalysisResults) GetTableRows(sess *session.Session, tw table.Writer) {
	provs := map[string]struct {
		ard AnalysisResultData
	}{
		"Acronis":                      {ard: lra.Acronis.AnalysisResultData},
		"0xSI_f33d":                    {ard: lra.ZeroXSIF33D.AnalysisResultData},
		"Abusix":                       {ard: lra.Abusix.AnalysisResultData},
		"ADMINUSLabs":                  {ard: lra.ADMINUSLabs.AnalysisResultData},
		"Criminal IP":                  {ard: lra.CriminalIP.AnalysisResultData},
		"AILabs (MONITORAPP)":          {ard: lra.AILabsMONITORAPP.AnalysisResultData},
		"AlienVault":                   {ard: lra.AlienVault.AnalysisResultData},
		"AlphaSOC":                     {ard: lra.AlphaSOC.AnalysisResultData},
		"Antiy-AVL":                    {ard: lra.AntiyAVL.AnalysisResultData},
		"ArcSight Threat Intelligence": {ard: lra.ArcSightThreatIntelligence.AnalysisResultData},
		"AutoShun":                     {ard: lra.AutoShun.AnalysisResultData},
		"benkow.cc":                    {ard: lra.BenkowCc.AnalysisResultData},
		"BitDefender":                  {ard: lra.BitDefender.AnalysisResultData},
		"Bkav":                         {ard: lra.BitDefender.AnalysisResultData},
		"Certego":                      {ard: lra.Certego.AnalysisResultData},
		"Chong Lua Dao":                {ard: lra.ChongLuaDao.AnalysisResultData},
		"CINS Army":                    {ard: lra.CINSArmy.AnalysisResultData},
		"Cluster25":                    {ard: lra.Cluster25.AnalysisResultData},
		"CRDF":                         {ard: lra.Crdf.AnalysisResultData},
		"CSIS Security Group":          {ard: lra.CSISSecurityGroup.AnalysisResultData},
		"Snort IP sample list":         {ard: lra.SnortIPSampleList.AnalysisResultData},
		"CMC Threat Intelligence":      {ard: lra.CMCThreatIntelligence.AnalysisResultData},
		"Cyan":                         {ard: lra.Cyan.AnalysisResultData},
		"Cyble":                        {ard: lra.Cyble.AnalysisResultData},
		"CyRadar":                      {ard: lra.CyRadar.AnalysisResultData},
		"DNS8":                         {ard: lra.DNS8.AnalysisResultData},
		"Dr.Web":                       {ard: lra.DrWeb.AnalysisResultData},
		"Ermes":                        {ard: lra.Ermes.AnalysisResultData},
		"ESET":                         {ard: lra.Eset.AnalysisResultData},
		"ESTsecurity":                  {ard: lra.ESTsecurity.AnalysisResultData},
		"EmergingThreats":              {ard: lra.EmergingThreats.AnalysisResultData},
		"Emsisoft":                     {ard: lra.Emsisoft.AnalysisResultData},
		"Forcepoint ThreatSeeker":      {ard: lra.ForcepointThreatSeeker.AnalysisResultData},
		"Fortinet":                     {ard: lra.Fortinet.AnalysisResultData},
		"Google Safebrowsing":          {ard: lra.GoogleSafebrowsing.AnalysisResultData},
		"GreenSnow":                    {ard: lra.GreenSnow.AnalysisResultData},
		"Gridinsoft":                   {ard: lra.Gridinsoft.AnalysisResultData},
		"Heimdal Security":             {ard: lra.HeimdalSecurity.AnalysisResultData},
		"Hunt.io Intelligence":         {ard: lra.HuntIoIntelligence.AnalysisResultData},
		"IPsum":                        {ard: lra.IPsum.AnalysisResultData},
		"Juniper Networks":             {ard: lra.JuniperNetworks.AnalysisResultData},
		"K7AntiVirus":                  {ard: lra.K7AntiVirus.AnalysisResultData},
		"Kaspersky":                    {ard: lra.Kaspersky.AnalysisResultData},
		"Lionic":                       {ard: lra.Lionic.AnalysisResultData},
		"Lumu":                         {ard: lra.Lumu.AnalysisResultData},
		"MalwarePatrol":                {ard: lra.MalwarePatrol.AnalysisResultData},
		"MalwareURL":                   {ard: lra.MalwareURL.AnalysisResultData},
		"Malwared":                     {ard: lra.Malwared.AnalysisResultData},
		"Netcraft":                     {ard: lra.Netcraft.AnalysisResultData},
		"OpenPhish":                    {ard: lra.OpenPhish.AnalysisResultData},
		"Phishing Database":            {ard: lra.PhishingDatabase.AnalysisResultData},
		"PhishFort":                    {ard: lra.PhishFort.AnalysisResultData},
		"PhishLabs":                    {ard: lra.PhishLabs.AnalysisResultData},
		"Phishtank":                    {ard: lra.Phishtank.AnalysisResultData},
		"PREBYTES":                     {ard: lra.Prebytes.AnalysisResultData},
		"Quick Heal":                   {ard: lra.QuickHeal.AnalysisResultData},
		"Quttera":                      {ard: lra.Quttera.AnalysisResultData},
		"SafeToOpen":                   {ard: lra.SafeToOpen.AnalysisResultData},
		"Sansec eComscan":              {ard: lra.SansecEComscan.AnalysisResultData},
		"Scantitan":                    {ard: lra.Scantitan.AnalysisResultData},
		"SCUMWARE.org":                 {ard: lra.SCUMWAREOrg.AnalysisResultData},
		"Seclookup":                    {ard: lra.Seclookup.AnalysisResultData},
		"SecureBrain":                  {ard: lra.SecureBrain.AnalysisResultData},
		"Segasec":                      {ard: lra.Segasec.AnalysisResultData},
		"SOCRadar":                     {ard: lra.SOCRadar.AnalysisResultData},
		"Sophos":                       {ard: lra.Sophos.AnalysisResultData},
		"Spam404":                      {ard: lra.Spam404.AnalysisResultData},
		"StopForumSpam":                {ard: lra.StopForumSpam.AnalysisResultData},
		"Sucuri SiteCheck":             {ard: lra.SucuriSiteCheck.AnalysisResultData},
		"ThreatHive":                   {ard: lra.ThreatHive.AnalysisResultData},
		"Threatsourcing":               {ard: lra.Threatsourcing.AnalysisResultData},
		"Trustwave":                    {ard: lra.Trustwave.AnalysisResultData},
		"Underworld":                   {ard: lra.Underworld.AnalysisResultData},
		"URLhaus":                      {ard: lra.URLhaus.AnalysisResultData},
		"URLQuery":                     {ard: lra.URLQuery.AnalysisResultData},
		"Viettel Threat Intelligence":  {ard: lra.ViettelThreatIntelligence.AnalysisResultData},
		"VIPRE":                        {ard: lra.Vipre.AnalysisResultData},
		"VX Vault":                     {ard: lra.VXVault.AnalysisResultData},
		"ViriBack":                     {ard: lra.ViriBack.AnalysisResultData},
		"Webroot":                      {ard: lra.Webroot.AnalysisResultData},
		"Yandex Safebrowsing":          {ard: lra.YandexSafebrowsing.AnalysisResultData},
		"ZeroCERT":                     {ard: lra.ZeroCERT.AnalysisResultData},
		"desenmascara.me":              {ard: lra.DesenmascaraMe.AnalysisResultData},
		"malwares.com URL checker":     {ard: lra.MalwaresComURLChecker.AnalysisResultData},
		"securolytics":                 {ard: lra.Securolytics.AnalysisResultData},
		"Xcitium Verdict Cloud":        {ard: lra.XcitiumVerdictCloud.AnalysisResultData},
		"zvelo":                        {ard: lra.Zvelo.AnalysisResultData},
	}

	for providerName, rda := range provs {
		if rda.ard.ShouldOutput(sess) {
			tw.AppendRow(table.Row{"", color.CyanString(providerName)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s Result: %s", IndentPipeHyphens, rda.ard.Result)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s Category: %s", IndentPipeHyphens, rda.ard.Category)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s Method: %s", IndentPipeHyphens, rda.ard.Method)})
		}
	}
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	var result *HostSearchResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("error unmarshalling virustotal data: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	tw := table.NewWriter()
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth, ColorsHeader: text.Colors{text.BgCyan}},
	})

	var rows []table.Row

	tm := time.Unix(int64(result.Data.Attributes.LastAnalysisDate), 0)

	rda := result.Data.Attributes
	tw.AppendRow(table.Row{providers.PadRight("Network", providers.Column1MinWidth), result.Data.Attributes.Network})
	tw.AppendRow(table.Row{"Country", result.Data.Attributes.Country})
	tw.AppendRow(table.Row{"Reputation", result.Data.Attributes.Reputation})
	tw.AppendRow(table.Row{"Total Votes", fmt.Sprintf("Malicious %d Harmless %d", result.Data.Attributes.TotalVotes.Malicious, result.Data.Attributes.TotalVotes.Harmless)})
	tw.AppendRow(table.Row{"Last Analysis", color.CyanString(tm.UTC().Format(providers.TimeFormat))})
	tw.AppendRow(table.Row{"", fmt.Sprintf("%s Malicious: %d", IndentPipeHyphens, rda.LastAnalysisStats.Malicious)})
	tw.AppendRow(table.Row{"", fmt.Sprintf("%s Suspicious: %d", IndentPipeHyphens, rda.LastAnalysisStats.Suspicious)})
	tw.AppendRow(table.Row{"", fmt.Sprintf("%s Harmless: %d", IndentPipeHyphens, rda.LastAnalysisStats.Harmless)})
	tw.AppendRow(table.Row{"", fmt.Sprintf("%s Undetected: %d", IndentPipeHyphens, rda.LastAnalysisStats.Undetected)})
	tw.AppendRow(table.Row{"", fmt.Sprintf("%s Timeout: %d", IndentPipeHyphens, rda.LastAnalysisStats.Timeout)})
	tw.AppendRow(table.Row{"Results", " ---"})
	rda.LastAnalysisResults.GetTableRows(&c.Session, tw)

	tw.AppendRows(rows)
	tw.SetAutoIndex(false)
	// tw.SetStyle(table.StyleColoredDark)
	// tw.Style().Options.DrawBorder = true
	tw.SetTitle("VIRUS TOTAL | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("VIRUS TOTAL | Host: %s", result.Data.ID)
	}

	c.Logger.Debug("virustotal table created", "host", c.Host.String())

	return &tw, nil
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating virustotal client")

	tc := &ProviderClient{
		c,
	}

	return tc, nil
}

func (c *Client) GetConfig() *session.Session {
	return &c.Config.Session
}

func (c *Client) GetData() (result *HostSearchResult, err error) {
	result, err = loadResultsFile("virustotal/testdata/virustotal_183_81_169_238_resp.json")
	if err != nil {
		return nil, err
	}

	return result, nil
}

type LastAnalysisResults struct {
	Acronis struct {
		AnalysisResultData
	} `json:"Acronis,omitempty"`
	ZeroXSIF33D struct {
		AnalysisResultData
	} `json:"0xSI_f33d,omitempty"`
	Abusix struct {
		AnalysisResultData
	} `json:"Abusix,omitempty"`
	ADMINUSLabs struct {
		AnalysisResultData
	} `json:"ADMINUSLabs,omitempty"`
	CriminalIP struct {
		AnalysisResultData
	} `json:"Criminal IP,omitempty"`
	AILabsMONITORAPP struct {
		AnalysisResultData
	} `json:"AILabs (MONITORAPP),omitempty"`
	AlienVault struct {
		AnalysisResultData
	} `json:"AlienVault,omitempty"`
	AlphaMountainAi struct {
		AnalysisResultData
	} `json:"alphaMountain.ai,omitempty"`
	AlphaSOC struct {
		AnalysisResultData
	} `json:"AlphaSOC,omitempty"`
	AntiyAVL struct {
		AnalysisResultData
	} `json:"Antiy-AVL,omitempty"`
	ArcSightThreatIntelligence struct {
		AnalysisResultData
	} `json:"ArcSight Threat Intelligence,omitempty"`
	AutoShun struct {
		AnalysisResultData
	} `json:"AutoShun,omitempty"`
	BenkowCc struct {
		AnalysisResultData
	} `json:"benkow.cc,omitempty"`
	BforeAiPreCrime struct {
		AnalysisResultData
	} `json:"Bfore.Ai PreCrime,omitempty"`
	BitDefender struct {
		AnalysisResultData
	} `json:"BitDefender,omitempty"`
	Bkav struct {
		AnalysisResultData
	} `json:"Bkav,omitempty"`
	Blueliv struct {
		AnalysisResultData
	} `json:"Blueliv,omitempty"`
	Certego struct {
		AnalysisResultData
	} `json:"Certego,omitempty"`
	ChongLuaDao struct {
		AnalysisResultData
	} `json:"Chong Lua Dao,omitempty"`
	CINSArmy struct {
		AnalysisResultData
	} `json:"CINS Army,omitempty"`
	Cluster25 struct {
		AnalysisResultData
	} `json:"Cluster25,omitempty"`
	Crdf struct {
		AnalysisResultData
	} `json:"CRDF,omitempty"`
	CSISSecurityGroup struct {
		AnalysisResultData
	} `json:"CSIS Security Group,omitempty"`
	SnortIPSampleList struct {
		AnalysisResultData
	} `json:"Snort IP sample list,omitempty"`
	CMCThreatIntelligence struct {
		AnalysisResultData
	} `json:"CMC Threat Intelligence,omitempty"`
	Cyan struct {
		AnalysisResultData
	} `json:"Cyan,omitempty"`
	Cyble struct {
		AnalysisResultData
	} `json:"Cyble,omitempty"`
	CyRadar struct {
		AnalysisResultData
	} `json:"CyRadar,omitempty"`
	DNS8 struct {
		AnalysisResultData
	} `json:"DNS8,omitempty"`
	DrWeb struct {
		AnalysisResultData
	} `json:"Dr.Web,omitempty"`
	Ermes struct {
		AnalysisResultData
	} `json:"Ermes,omitempty"`
	Eset struct {
		AnalysisResultData
	} `json:"ESET,omitempty"`
	ESTsecurity struct {
		AnalysisResultData
	} `json:"ESTsecurity,omitempty"`
	EmergingThreats struct {
		AnalysisResultData
	} `json:"EmergingThreats,omitempty"`
	Emsisoft struct {
		AnalysisResultData
	} `json:"Emsisoft,omitempty"`
	ForcepointThreatSeeker struct {
		AnalysisResultData
	} `json:"Forcepoint ThreatSeeker,omitempty"`
	Fortinet struct {
		AnalysisResultData
	} `json:"Fortinet,omitempty"`
	GData struct {
		AnalysisResultData
	} `json:"G-Data,omitempty"`
	GoogleSafebrowsing struct {
		AnalysisResultData
	} `json:"Google Safebrowsing,omitempty"`
	GreenSnow struct {
		AnalysisResultData
	} `json:"GreenSnow,omitempty"`
	Gridinsoft struct {
		AnalysisResultData
	} `json:"Gridinsoft,omitempty"`
	HeimdalSecurity struct {
		AnalysisResultData
	} `json:"Heimdal Security,omitempty"`
	HuntIoIntelligence struct {
		AnalysisResultData
	} `json:"Hunt.io Intelligence,omitempty"`
	IPsum struct {
		AnalysisResultData
	} `json:"IPsum,omitempty"`
	JuniperNetworks struct {
		AnalysisResultData
	} `json:"Juniper Networks,omitempty"`
	K7AntiVirus struct {
		AnalysisResultData
	} `json:"K7AntiVirus,omitempty"`
	Kaspersky struct {
		AnalysisResultData
	} `json:"Kaspersky,omitempty"`
	Lionic struct {
		AnalysisResultData
	} `json:"Lionic,omitempty"`
	Lumu struct {
		AnalysisResultData
	} `json:"Lumu,omitempty"`
	MalwarePatrol struct {
		AnalysisResultData
	} `json:"MalwarePatrol,omitempty"`
	MalwareURL struct {
		AnalysisResultData
	} `json:"MalwareURL,omitempty"`
	Malwared struct {
		AnalysisResultData
	} `json:"Malwared,omitempty"`
	Netcraft struct {
		AnalysisResultData
	} `json:"Netcraft,omitempty"`
	OpenPhish struct {
		AnalysisResultData
	} `json:"OpenPhish,omitempty"`
	PhishingDatabase struct {
		AnalysisResultData
	} `json:"Phishing Database,omitempty"`
	PhishFort struct {
		AnalysisResultData
	} `json:"PhishFort,omitempty"`
	PhishLabs struct {
		AnalysisResultData
	} `json:"PhishLabs,omitempty"`
	Phishtank struct {
		AnalysisResultData
	} `json:"Phishtank,omitempty"`
	Prebytes struct {
		AnalysisResultData
	} `json:"PREBYTES,omitempty"`
	PrecisionSec struct {
		AnalysisResultData
	} `json:"PrecisionSec,omitempty"`
	QuickHeal struct {
		AnalysisResultData
	} `json:"Quick Heal,omitempty"`
	Quttera struct {
		AnalysisResultData
	} `json:"Quttera,omitempty"`
	SafeToOpen struct {
		AnalysisResultData
	} `json:"SafeToOpen,omitempty"`
	SansecEComscan struct {
		AnalysisResultData
	} `json:"Sansec eComscan,omitempty"`
	Scantitan struct {
		AnalysisResultData
	} `json:"Scantitan,omitempty"`
	SCUMWAREOrg struct {
		AnalysisResultData
	} `json:"SCUMWARE.org,omitempty"`
	Seclookup struct {
		AnalysisResultData
	} `json:"Seclookup,omitempty"`
	SecureBrain struct {
		AnalysisResultData
	} `json:"SecureBrain,omitempty"`
	Segasec struct {
		AnalysisResultData
	} `json:"Segasec,omitempty"`
	SOCRadar struct {
		AnalysisResultData
	} `json:"SOCRadar,omitempty"`
	Sophos struct {
		AnalysisResultData
	} `json:"Sophos,omitempty"`
	Spam404 struct {
		AnalysisResultData
	} `json:"Spam404,omitempty"`
	StopForumSpam struct {
		AnalysisResultData
	} `json:"StopForumSpam,omitempty"`
	SucuriSiteCheck struct {
		AnalysisResultData
	} `json:"Sucuri SiteCheck,omitempty"`
	ThreatHive struct {
		AnalysisResultData
	} `json:"ThreatHive,omitempty"`
	Threatsourcing struct {
		AnalysisResultData
	} `json:"Threatsourcing,omitempty"`
	Trustwave struct {
		AnalysisResultData
	} `json:"Trustwave,omitempty"`
	Underworld struct {
		AnalysisResultData
	} `json:"Underworld,omitempty"`
	URLhaus struct {
		AnalysisResultData
	} `json:"URLhaus,omitempty"`
	URLQuery struct {
		AnalysisResultData
	} `json:"URLQuery,omitempty"`
	ViettelThreatIntelligence struct {
		AnalysisResultData
	} `json:"Viettel Threat Intelligence,omitempty"`
	Vipre struct {
		AnalysisResultData
	} `json:"VIPRE,omitempty"`
	VXVault struct {
		AnalysisResultData
	} `json:"VX Vault,omitempty"`
	ViriBack struct {
		AnalysisResultData
	} `json:"ViriBack,omitempty"`
	Webroot struct {
		AnalysisResultData
	} `json:"Webroot,omitempty"`
	YandexSafebrowsing struct {
		AnalysisResultData
	} `json:"Yandex Safebrowsing,omitempty"`
	ZeroCERT struct {
		AnalysisResultData
	} `json:"ZeroCERT,omitempty"`
	DesenmascaraMe struct {
		AnalysisResultData
	} `json:"desenmascara.me,omitempty"`
	MalwaresComURLChecker struct {
		AnalysisResultData
	} `json:"malwares.com URL checker,omitempty"`
	Securolytics struct {
		AnalysisResultData
	} `json:"securolytics,omitempty"`
	XcitiumVerdictCloud struct {
		AnalysisResultData
	} `json:"Xcitium Verdict Cloud,omitempty"`
	Zvelo struct {
		AnalysisResultData
	} `json:"zvelo,omitempty"`
}

type HostSearchResultData struct {
	ID    string `json:"id,omitempty"`
	Type  string `json:"type,omitempty"`
	Links struct {
		Self string `json:"self,omitempty"`
	} `json:"links,omitempty"`
	Attributes struct {
		LastAnalysisStats struct {
			Malicious  int `json:"malicious,omitempty"`
			Suspicious int `json:"suspicious,omitempty"`
			Undetected int `json:"undetected,omitempty"`
			Harmless   int `json:"harmless,omitempty"`
			Timeout    int `json:"timeout,omitempty"`
		} `json:"last_analysis_stats,omitempty"`
		LastAnalysisResults  LastAnalysisResults `json:"last_analysis_results,omitempty"`
		LastModificationDate int                 `json:"last_modification_date,omitempty"`
		LastAnalysisDate     int                 `json:"last_analysis_date,omitempty"`

		Whois      string `json:"whois,omitempty"`
		WhoisDate  int    `json:"whois_date,omitempty"`
		Reputation int    `json:"reputation,omitempty"`
		Country    string `json:"country,omitempty"`
		TotalVotes struct {
			Harmless  int `json:"harmless,omitempty"`
			Malicious int `json:"malicious,omitempty"`
		} `json:"total_votes,omitempty"`
		Continent                string `json:"continent,omitempty"`
		Asn                      int    `json:"asn,omitempty"`
		AsOwner                  string `json:"as_owner,omitempty"`
		Network                  string `json:"network,omitempty"`
		Tags                     []any  `json:"tags,omitempty"`
		RegionalInternetRegistry string `json:"regional_internet_registry,omitempty"`
	} `json:"attributes,omitempty"`
}

type AnalysisResultData struct {
	Method     string `json:"method,omitempty"`
	EngineName string `json:"engine_name,omitempty"`
	Category   string `json:"category,omitempty"`
	Result     string `json:"result,omitempty"`
}

type HostSearchResult struct {
	Raw   []byte               `json:"raw"`
	Error string               `json:"error"`
	Data  HostSearchResultData `json:"data,omitempty"`
}
