package config

import (
	_ "embed"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"
	"log/slog"
	"net/netip"
	"os"
	"path"
	"path/filepath"
)

const (
	AppName               = "crosscheck-ip"
	DefaultIndentSpaces   = 2
	DefaultConfigFileName = "config.yaml"
	// DefaultConfigFileRoot = ".config/crosscheck-ip"
)

//go:embed config.yaml
var defaultConfig string

type Config struct {
	Logger *slog.Logger
	Cache  *badger.DB
	Global struct {
		IndentSpaces  int      `mapstructure:"indent-spaces"`
		Ports         []string `mapstructure:"ports"`
		MaxValueChars int32    `mapstructure:"max-value-chars"`
		MaxAge        string   `mapstructure:"max-age"`
	} `mapstructure:"global"`
	HttpClient   *retryablehttp.Client
	Host         netip.Addr
	Providers    Providers `mapstructure:"providers"`
	HideProgress bool      `mapstructure:"hide-progress"`

	// MaxWidth      int
	UseTestData bool
}

type Providers struct {
	Shodan struct {
		APIKey   string   `mapstructure:"api-key"`
		Enabled  bool     `mapstructure:"enabled"`
		MaxPorts int      `mapstructure:"max-ports"`
		Ports    []string `mapstructure:"ports"`
	} `mapstructure:"shodan"`
	CriminalIP struct {
		APIKey   string   `mapstructure:"api-key"`
		Enabled  bool     `mapstructure:"enabled"`
		MaxPorts int      `mapstructure:"max-ports"`
		Ports    []string `mapstructure:"ports"`
	} `mapstructure:"criminalip"`
	AWS struct {
		Enabled bool `mapstructure:"enabled"`
	} `mapstructure:"aws"`
	DigitalOcean struct {
		Enabled bool `mapstructure:"enabled"`
	} `mapstructure:"digitalocean"`
}

func unmarshalConfig(data []byte) (*Config, error) {
	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &conf, nil
}

func CreateDefaultConfigIfMissing(path string) error {
	var err error

	// check if config already exists
	_, err = os.Stat(filepath.Join(path, DefaultConfigFileName))

	switch {
	case err == nil:
		// DEBUG
		// fmt.Println("config already exists")
		return nil
	case os.IsNotExist(err):
		// check default config is valid
		if _, err = unmarshalConfig([]byte(defaultConfig)); err != nil {
			return fmt.Errorf("default config invalid: %w", err)
		}

		// create dir specified in path argument if missing
		if _, err = os.Stat(path); os.IsNotExist(err) {
			if err = os.MkdirAll(path, 0700); err != nil {
				return fmt.Errorf("failed to create config directory: %w", err)
			}
		}

		if err = os.WriteFile(filepath.Join(path, DefaultConfigFileName), []byte(defaultConfig), 0700); err != nil {
			return fmt.Errorf("failed to write default config: %w", err)
		}
	case err != nil:
		return fmt.Errorf("failed to stat config directory: %w", err)
	}

	return nil
}

// CreateCachePathIfNotExist creates a cache directory in the specified path if it does not exist
// and returns an error if it fails to create the directory, or the config root does not exist
func CreateCachePathIfNotExist(configRoot string) error {
	// check config root exists
	_, err := os.Stat(configRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("config root does not exist: %v", err)
		}
	}

	_, err = os.Stat(path.Join(configRoot, "cache"))
	if err != nil {
		if os.IsNotExist(err) {
			mErr := os.MkdirAll(path.Join(configRoot, "cache"), 0700)
			if mErr != nil {
				return fmt.Errorf("failed to create cache directory: %v", mErr)
			}
		} else {
			return fmt.Errorf("failed to stat cache directory: %v", err)
		}
	}

	return nil
}

// GetConfigRoot returns the root path for the app's config directory
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
