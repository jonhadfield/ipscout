package annotated

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ipq/common"
	"gopkg.in/yaml.v3"
	"sort"

	"github.com/araddon/dateparse"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/sirupsen/logrus"
	_ "io/fs"
	"io/ioutil"
	"net/netip"
	"os"
	"path/filepath"
	_ "regexp"
	"slices"
	"strings"
	"time"
)

const (
	ProviderName   = "annotated"
	CacheTTL       = time.Duration(10 * time.Minute)
	MaxColumnWidth = 120
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

func ReadAnnotatedPrefixesFromFile(path string, prefixesWithAnnotations map[netip.Prefix][]annotation) error {
	file, err := os.ReadFile(path)
	if err != nil {
		logrus.Error(err)

		return err
	}

	var pwars []YamlPrefixAnnotationsRecords

	err = yaml.Unmarshal(file, &pwars)
	if err != nil {
		return err
	}

	for _, pwar := range pwars {
		// parse and repack annotations
		annotationSource := path

		annotations := parseAndRepackYAMLAnnotations(annotationSource, pwar.Annotations)

		for _, p := range pwar.Prefixes {
			parsedPrefix, err := netip.ParsePrefix(p)
			if err != nil {
				logrus.Warnf("failed to parse prefix: %s", parsedPrefix)
				continue
			}

			prefixesWithAnnotations[parsedPrefix] = append(prefixesWithAnnotations[parsedPrefix], annotations...)
		}
	}

	return err
}

func parseAndRepackYAMLAnnotations(source string, yas []yamlAnnotation) (pyas []annotation) {
	for _, ya := range yas {
		pDate, err := dateparse.ParseAny(ya.Date, dateparse.PreferMonthFirst(false))
		if err != nil {
			logrus.Warnf("%s | failed to parse date %s, so zeroing", common.GetFunctionName(), pDate)
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
		Key:     providers.CacheProviderPrefix + ProviderName + "_" + uh,
		Value:   mPWAs,
		Version: "-",
		Created: time.Now(),
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

	return hex.EncodeToString(h.Sum(nil))
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
			tw.AppendRow(table.Row{"Notes", strings.Join(anno.Notes, ", ")})
			tw.AppendRow(table.Row{"Source", anno.Source})
		}

	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("Annotated | Host: %s", c.Host.String())

	return &tw, nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	//var out []byte

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

	// match.ETag = item.Version

	var raw []byte

	raw, err = json.Marshal(match)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	// match.Raw = raw

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

func matchIPToDoc(ip netip.Addr, doc map[netip.Prefix][]annotation) (HostSearchResult, error) {
	var result HostSearchResult

	for prefix, annotations := range doc {
		if prefix.Contains(ip) {
			result[prefix] = annotations
		}
	}

	return result, nil

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
			fmt.Println("item.Value: ", string(item.Value))
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

//
//func GetListPaths(root string, repo Repository) (paths []string, err error) {
//	if len(repo.Patterns) == 0 {
//		logrus.Warnf("%s | no patterns provided for repos", funcName)
//	}
//
//	// compile regex patterns
//	var regexes []*regexp.Regexp
//
//	// compile provided patterns into regexes
//	for _, p := range repo.Patterns {
//		var regex *regexp.Regexp
//
//		regex, err = regexp.Compile(p)
//		if err != nil {
//			return
//		}
//
//		regexes = append(regexes, regex)
//	}
//
//	var sourcePaths []string
//	// if no paths provided then default to root
//	if len(repo.Paths) == 0 {
//		parts := strings.Split(repo.Url, "/")
//		name := parts[len(parts)-1]
//		sourcePaths = []string{filepath.Join(root, name)}
//	}
//
//	// loop through source paths
//	for _, sp := range sourcePaths {
//		// loop through files and apply patterns
//		var files []fs.DirEntry
//
//		files, err = os.ReadDir(sp)
//		if err != nil {
//			logrus.Errorf("%s | %s", funcName, err.Error())
//			return
//		}
//
//		for _, file := range files {
//			if !file.IsDir() {
//				for _, r := range regexes {
//					fPath := filepath.Join(sp, file.Name())
//
//					if r.MatchString(fPath) {
//						paths = append(paths, fPath)
//					}
//				}
//			}
//		}
//	}
//
//	return paths, err
//}

// LoadAnnotatedIPPrefixesFromPaths accepts a file Path or directory and then generates a fully qualified Path
// in order to call a function to load the ips from each fully qualified file Path
//func LoadAnnotatedIPPrefixesFromPaths(root string, paths []string, prefixesWithAnnotations PrefixesWithAnnotations) error {
//	for _, path := range paths {
//		if err := LoadFilePrefixesWithAnnotationsFromPath(root, path, prefixesWithAnnotations); err != nil {
//			return err
//		}
//	}
//
//	return nil
//}

const (
	ipFileSuffixesToIgnore  = "sh,conf"
	cacheFreshnessThreshold = 5
)

func getValidFilePathsFromDir(dir string) (paths []os.FileInfo) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		logrus.Errorf("%s - %s", dir, err)
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
		logrus.Debugf("calling getValidFilePathsFromDir with path: %s", path)
		files = getValidFilePathsFromDir(path)
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
		logrus.Infof("loading %s", fPath)

		err = ReadAnnotatedPrefixesFromFile(fPath, prefixesWithAnnotations)
		if err != nil {
			return err
		}

		fileCount++
	}

	return err
}

type PrefixesWithAnnotations map[netip.Prefix][]annotation

// ProcessRepositories clones the list repositories and then updates the db with the content
//func ProcessRepositories(sess *session.IPQSession) error {
//	funcName := common.GetFunctionName()
//
//	var err error
//
//	// clone/update existing repositories defined in configuration
//
//	// produce list of cloned paths to read ip lists from
//	paths, err := getRepositoryPaths(config.Annotated)
//	if err != nil {
//		return err
//	}
//	// prefixesWithPaths will create a map of Prefix + Annotations it features in for each path provided
//	prefixesWithAnnotations := make(PrefixesWithAnnotations)
//
//	err = LoadAnnotatedIPPrefixesFromPaths(config.Annotated.Root, paths, prefixesWithAnnotations)
//	if err != nil {
//		return err
//	}
//
//	vad := VersionedAnnotatedDoc{
//		LastFetchedFromSource: time.Now(),
//		Doc:                   prefixesWithAnnotations,
//	}
//
//	logrus.Infof("%s | setting update lock to '%s'", funcName, model.ReasonRecentlyUpdated)
//
//	if err = model.SetUpdateLockInDB(sess.DBConnPool, identifier, model.ReasonRecentlyUpdated, time.Now().UTC()); err != nil {
//		logrus.Errorf("%s | failed to set update lock for '%s': %s", funcName, model.ReasonRecentlyUpdated, err.Error())
//		return err
//	}
//
//	return nil
//}

func marshallVersionedAnnotatedDoc(doc VersionedAnnotatedDoc) (versionedAnnotatedDocJSON string, err error) {
	funcName := common.GetFunctionName()

	logrus.Tracef(fmt.Sprintf("%s | marshalling doc", funcName))

	b, err := json.Marshal(doc)
	if err != nil {
		return
	}

	return string(b), nil
}

type VersionedAnnotatedDoc struct {
	LastFetchedFromSource time.Time
	LastFetchededFromDB   time.Time
	Doc                   PrefixesWithAnnotations
}

//func LoadFromSource(sess *session.IPQSession) (err error) {
//	config := sess.Config.(*session.LoaderConfig)
//
//	if len(config.Annotated.Repositories) > 0 {
//		if err = ProcessRepositories(sess); err != nil {
//			return err
//		}
//	}
//
//	logrus.Debugf("%s | completed annotated load successfully", common.GetFunctionName())
//
//	return
//}

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
