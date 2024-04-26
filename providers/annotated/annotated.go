package annotated

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"gopkg.in/yaml.v3"

	"github.com/araddon/dateparse"

	_ "io/fs"

	_ "regexp"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/providers"
)

const (
	ProviderName           = "annotated"
	CacheTTL               = 5 * time.Minute
	MaxColumnWidth         = 120
	ipFileSuffixesToIgnore = "sh,conf"
)

type Annotated struct {
	Client *retryablehttp.Client
	Root   string
	Paths  []string
}
type ProviderClient struct {
	config.Config
}

func (c *ProviderClient) Enabled() bool {
	return c.Config.Providers.Annotated.Enabled
}

func (c *ProviderClient) GetConfig() *config.Config {
	return &c.Config
}

func NewProviderClient(c config.Config) (*ProviderClient, error) {
	c.Logger.Debug("creating annotated client")

	if c.Logger == nil {
		return nil, errors.New("logger not set")
	}

	if c.Stats == nil {
		return nil, errors.New("stats not set")
	}

	if c.Cache == nil {
		return nil, errors.New("cache not set")
	}

	tc := &ProviderClient{
		Config: c,
	}

	return tc, nil
}

func LoadAnnotatedIPPrefixesFromPaths(paths []string, prefixesWithAnnotations PrefixesWithAnnotations) error {
	for _, path := range paths {
		if err := LoadFilePrefixesWithAnnotationsFromPath(path, prefixesWithAnnotations); err != nil {
			return err
		}
	}

	return nil
}

type YamlPrefixAnnotationsRecords struct {
	Prefixes    []string         `yaml:"prefixes"`
	Annotations []yamlAnnotation `yaml:"annotations"`
}

func ReadAnnotatedPrefixesFromFile(l *slog.Logger, path string, prefixesWithAnnotations map[netip.Prefix][]annotation) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	var pwars []YamlPrefixAnnotationsRecords

	err = yaml.Unmarshal(file, &pwars)
	if err != nil {
		return err
	}

	for _, pwar := range pwars {
		// parse and repack annotations
		annotationSource := path

		annotations := parseAndRepackYAMLAnnotations(nil, annotationSource, pwar.Annotations)

		for _, p := range pwar.Prefixes {
			var parsedPrefix netip.Prefix

			parsedPrefix, err = netip.ParsePrefix(p)
			if err != nil {
				l.Debug("failed to parse", "prefix", parsedPrefix)

				continue
			}

			prefixesWithAnnotations[parsedPrefix] = append(prefixesWithAnnotations[parsedPrefix], annotations...)
		}
	}

	return err
}

func parseAndRepackYAMLAnnotations(l *slog.Logger, source string, yas []yamlAnnotation) (pyas []annotation) {
	for _, ya := range yas {
		pDate, err := dateparse.ParseAny(ya.Date, dateparse.PreferMonthFirst(false))
		if err != nil {
			l.Debug("failed to parse date,so zeroing", "date", pDate)
		}

		pyas = append(pyas, annotation{
			Date:   pDate,
			Author: ya.Author,
			Notes:  ya.Notes,
			Source: source,
		})
	}

	return
}

func (c *ProviderClient) Initialise() error {
	if c.Providers.Annotated.Paths == nil {
		return errors.New("no paths provided for annotated provider")
	}

	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	c.Logger.Debug("initialising annotated client")

	// check for combined data in cache
	uh := generateURLsHash(c.Providers.Annotated.Paths)

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName+"_"+uh)
	if err != nil {
		return err
	}

	if ok {
		c.Logger.Info("annotated provider data found in cache")

		return nil
	}

	// load data from source and store in cache
	prefixesWithAnnotations := make(map[netip.Prefix][]annotation)
	err = LoadAnnotatedIPPrefixesFromPaths(c.Providers.Annotated.Paths, prefixesWithAnnotations)
	if err != nil {
		return fmt.Errorf("loading annotated files: %w", err)
	}

	mPWAs, err := json.Marshal(prefixesWithAnnotations)
	if err != nil {
		return fmt.Errorf("error marshalling annotated prefixes: %w", err)
	}

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        providers.CacheProviderPrefix + ProviderName + "_" + uh,
		Value:      mPWAs,
		Version:    "-",
		Created:    time.Now(),
	}, CacheTTL); err != nil {
		return err
	}

	return nil
}

func generateURLsHash(urls []string) string {
	sort.Strings(urls)

	s := strings.Join(urls, "")
	h := sha1.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))[:providers.CacheKeySHALen]
}

type HostSearchResult map[netip.Prefix][]annotation

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	var err error
	var result HostSearchResult
	if err = json.Unmarshal(data, &result); err != nil {
		switch {
		case errors.Is(err, providers.ErrNoDataFound):
			return nil, fmt.Errorf("data not loaded: %w", err)
		case errors.Is(err, providers.ErrFailedToFetchData):
			return nil, err
		case errors.Is(err, providers.ErrNoMatchFound):
			// reset the error as no longer useful for table creation
			return nil, nil
		default:
			return nil, fmt.Errorf("error loading annotated api response: %w", err)
		}
	}

	tw := table.NewWriter()
	var rows []table.Row

	for prefix, annotations := range result {
		tw.AppendRow(table.Row{"Prefix", dashIfEmpty(prefix.String())})
		for _, anno := range annotations {
			tw.AppendRow(table.Row{"Date", anno.Date})
			tw.AppendRow(table.Row{"Author", anno.Author})

			if len(anno.Notes) == 0 {
				tw.AppendRow(table.Row{"Notes", "-"})
			} else {
				for x := range anno.Notes {
					if x == 0 {
						tw.AppendRow(table.Row{"Notes", anno.Notes[x]})
						continue
					}
					tw.AppendRow(table.Row{"", anno.Notes[x]})
				}
			}

			tw.AppendRow(table.Row{"Source", anno.Source})
		}

	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("ANNOTATED | Host: %s", c.Host.String())

	return &tw, nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	var err error

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, err
	}

	match, err := matchIPToDoc(c.Host, doc)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("annotated match found", "host", c.Host.String())

	var raw []byte

	raw, err = json.Marshal(match)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	// TODO: remove before release
	//if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
	//	if err = os.WriteFile(fmt.Sprintf("%s/backups/annotated_%s_report.json", config.GetConfigRoot("", config.AppName),
	//		strings.ReplaceAll(c.Host.String(), ".", "_")), raw, 0o644); err != nil {
	//		panic(err)
	//	}
	//	c.Logger.Info("backed up annotated response", "host", c.Host.String())
	//}

	return raw, nil
}

func matchIPToDoc(ip netip.Addr, doc map[netip.Prefix][]annotation) (*HostSearchResult, error) {
	var result HostSearchResult

	for prefix, annotations := range doc {
		if prefix.Contains(ip) {
			if result == nil {
				result = make(HostSearchResult)
			}

			result[prefix] = annotations
		}
	}

	if result == nil {
		return nil, providers.ErrNoMatchFound
	}

	return &result, nil
}

func unmarshalResponse(data []byte) (HostSearchResult, error) {
	var res HostSearchResult

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	// res.Raw = data
	return res, nil
}

func (c *ProviderClient) loadProviderDataFromCache() (map[netip.Prefix][]annotation, error) {
	// load data from cache
	uh := generateURLsHash(c.Providers.Annotated.Paths)

	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + uh
	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		if item.Value != nil && len(item.Value) > 0 {
			var result map[netip.Prefix][]annotation
			result, err = unmarshalResponse(item.Value)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling cached annotated response: %w", err)
			}

			c.Logger.Info("annotated response found in cache", "host", c.Host.String())

			c.Stats.Mu.Lock()
			c.Stats.FindHostUsedCache[ProviderName] = true
			c.Stats.Mu.Unlock()

			return result, nil
		}
	}

	return nil, nil
}

type Repository struct {
	Url         string   `toml:"url"`
	GitHubUser  string   `toml:"github_user"`
	GitHubToken string   `toml:"github_token"`
	Paths       []string `toml:"paths"`
	Patterns    []string `toml:"patterns"`
}

func getValidFilePathsFromDir(l *slog.Logger, dir string) (paths []os.FileInfo) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		l.Warn("failed to read", "dir", dir, "error", err.Error())
	}

	suffixesToIgnore := strings.Split(ipFileSuffixesToIgnore, ",")

	for _, file := range files {
		if !file.IsDir() {
			if slices.Contains(suffixesToIgnore, filepath.Ext(file.Name())) {
				continue
			}

			paths = append(paths, file)
		}
	}

	return
}

func LoadFilePrefixesWithAnnotationsFromPath(path string, prefixesWithAnnotations map[netip.Prefix][]annotation) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return err
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}

	var fileCount int64

	var files []os.FileInfo

	pathIsDir := info.IsDir()
	if pathIsDir {
		// if directory, then retrieve all files within
		files = getValidFilePathsFromDir(nil, path)
	} else {
		files = []os.FileInfo{info}
	}

	for _, file := range files {
		// set the file to read to the path
		fPath := path
		// prefix with path if it was a directory
		if pathIsDir {
			fPath = filepath.Join(path, file.Name())
		}

		// Get annotations from file
		err = ReadAnnotatedPrefixesFromFile(nil, fPath, prefixesWithAnnotations)
		if err != nil {
			return err
		}

		fileCount++
	}

	return err
}

type PrefixesWithAnnotations map[netip.Prefix][]annotation

type VersionedAnnotatedDoc struct {
	LastFetchedFromSource time.Time
	LastFetchededFromDB   time.Time
	Doc                   PrefixesWithAnnotations
}

type annotation struct {
	Date   time.Time `yaml:"date"`
	Author string    `yaml:"author"`
	Notes  []string  `yaml:"notes"`
	Source string    `yaml:"source"`
}

type yamlAnnotation struct {
	Date   string   `yaml:"date"`
	Author string   `yaml:"author"`
	Notes  []string `yaml:"notes"`
	Source string   `yaml:"source"`
}

func dashIfEmpty(value interface{}) string {
	switch v := value.(type) {
	case string:
		if len(v) == 0 {
			return "-"
		}
		return v
	case *string:
		if v == nil || len(*v) == 0 {
			return "-"
		}
		return *v
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return "-"
	}
}
