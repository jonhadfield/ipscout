package session

import (
	_ "embed"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"
)

const (
	AppName               = "ipscout"
	DefaultIndentSpaces   = 2
	DefaultMaxReports     = 5
	DefaultConfigFileName = "config.yaml"
	// DefaultConfigFileRoot = ".session/ipscout"
)

//go:embed config.yaml
var defaultConfig string

type Stats struct {
	Mu                  sync.Mutex
	InitialiseDuration  map[string]time.Duration
	InitialiseUsedCache map[string]bool
	FindHostDuration    map[string]time.Duration
	FindHostUsedCache   map[string]bool
	CreateTableDuration map[string]time.Duration
}

func CreateStats() *Stats {
	return &Stats{
		InitialiseDuration:  make(map[string]time.Duration),
		InitialiseUsedCache: make(map[string]bool),
		FindHostDuration:    make(map[string]time.Duration),
		FindHostUsedCache:   make(map[string]bool),
		CreateTableDuration: make(map[string]time.Duration),
	}
}

func New() *Session {
	return &Session{
		Stats: CreateStats(),
	}
}

func (c *Session) Validate() error {
	switch {
	case c.Logger == nil:
		return fmt.Errorf("logger not set")
	case c.Stats == nil:
		return fmt.Errorf("stats not set")
	case c.Cache == nil:
		return fmt.Errorf("cache not set")
	}

	return nil
}

type Config struct {
	Global GlobalConfig `mapstructure:"global"`
}

type GlobalConfig struct {
	LogLevel      string   `mapstructure:"log-level"`
	Output        string   `mapstructure:"output"`
	IndentSpaces  int      `mapstructure:"indent-spaces"`
	Ports         []string `mapstructure:"ports"`
	MaxValueChars int32    `mapstructure:"max-value-chars"`
	MaxAge        string   `mapstructure:"max-age"`
	MaxReports    int      `mapstructure:"max-reports"`
	DisableCache  bool     `mapstructure:"disable-cache"`
}

type Session struct {
	App struct {
		Version string
		SemVer  string
	}
	Logger *slog.Logger
	Stats  *Stats
	Target *os.File
	Output string
	Cache  *badger.DB
	Config Config

	HTTPClient   *retryablehttp.Client
	Host         netip.Addr
	Providers    Providers `mapstructure:"providers"`
	HideProgress bool      `mapstructure:"hide-progress"`

	// MaxWidth      int
	UseTestData bool
}

type Providers struct {
	AbuseIPDB struct {
		Enabled bool   `mapstructure:"enabled"`
		APIKey  string `mapstructure:"api-key"`
		MaxAge  int    `mapstructure:"max-age"`
	} `mapstructure:"abuseipdb"`
	Annotated struct {
		Enabled bool     `mapstructure:"enabled"`
		Paths   []string `mapstructure:"paths"`
	} `mapstructure:"annotated"`
	AWS struct {
		Enabled bool   `mapstructure:"enabled"`
		URL     string `mapstructure:"url"`
	} `mapstructure:"aws"`
	Azure struct {
		Enabled bool   `mapstructure:"enabled"`
		URL     string `mapstructure:"url"`
	} `mapstructure:"azure"`
	CriminalIP struct {
		APIKey  string `mapstructure:"api-key"`
		Enabled bool   `mapstructure:"enabled"`
	} `mapstructure:"criminalip"`
	DigitalOcean struct {
		Enabled bool `mapstructure:"enabled"`
		URL     string
	} `mapstructure:"digitalocean"`
	GCP struct {
		Enabled bool `mapstructure:"enabled"`
		URL     string
	} `mapstructure:"gcp"`
	ICloudPR struct {
		Enabled bool   `mapstructure:"enabled"`
		URL     string `mapstructure:"url"`
	} `mapstructure:"icloudpr"`
	IPURL struct {
		Enabled bool     `mapstructure:"enabled"`
		URLs    []string `mapstructure:"urls"`
	} `mapstructure:"ipurl"`
	Linode struct {
		Enabled bool `mapstructure:"enabled"`
		URL     string
	} `mapstructure:"linode"`
	Shodan struct {
		APIKey  string `mapstructure:"api-key"`
		Enabled bool   `mapstructure:"enabled"`
	} `mapstructure:"shodan"`
	PTR struct {
		Enabled bool `mapstructure:"enabled"`
	} `mapstructure:"ptr"`
}

func unmarshalConfig(data []byte) (*Session, error) {
	var conf Session
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &conf, nil
}

func CreateDefaultConfigIfMissing(path string) error {
	if path == "" {
		return fmt.Errorf("session path not specified")
	}

	var err error

	// check if session already exists
	_, err = os.Stat(filepath.Join(path, DefaultConfigFileName))

	switch {
	case err == nil:
		return nil
	case os.IsNotExist(err):
		// check default session is valid
		if _, err = unmarshalConfig([]byte(defaultConfig)); err != nil {
			return fmt.Errorf("default session invalid: %w", err)
		}

		// create dir specified in path argument if missing
		if _, err = os.Stat(path); os.IsNotExist(err) {
			if err = os.MkdirAll(path, 0o700); err != nil {
				return fmt.Errorf("failed to create session directory: %w", err)
			}
		}

		if err = os.WriteFile(filepath.Join(path, DefaultConfigFileName), []byte(defaultConfig), 0o600); err != nil {
			return fmt.Errorf("failed to write default session: %w", err)
		}
	case err != nil:
		return fmt.Errorf("failed to stat session directory: %w", err)
	}

	return nil
}

// CreateConfigPathStructure creates all the necessary paths under session root if they don't exist
// and returns an error if it fails to create the directory, or the session root does not exist
func CreateConfigPathStructure(configRoot string) error {
	// check session root exists
	_, err := os.Stat(configRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("session root does not exist: %v", err)
		}
	}

	for _, dir := range []string{"backups", "cache"} {
		_, err = os.Stat(path.Join(configRoot, dir))
		if err != nil {
			if os.IsNotExist(err) {
				mErr := os.MkdirAll(path.Join(configRoot, dir), 0o700)
				if mErr != nil {
					return fmt.Errorf("failed to create %s directory: %v", dir, mErr)
				}
			} else {
				return fmt.Errorf("failed to stat %s directory: %v", dir, err)
			}
		}
	}

	return nil
}

// GetConfigRoot returns the root path for the app's session directory
// if root is specified, it will use that, otherwise it will use the user's home directory
func GetConfigRoot(root string, appName string) string {
	// if root specified then use that
	if root != "" {
		return path.Join(root, ".config", appName)
	}

	// otherwise, use the user's home directory
	home, err := homedir.Dir()
	if err != nil {
		os.Exit(1)
	}

	return path.Join(home, ".config", appName)
}