package config

import (
	_ "embed"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"
	"net/netip"
	"os"
	"path"
	"path/filepath"
)

const (
	AppName               = "noodle"
	DefaultIndentSpaces   = 2
	DefaultConfigFileName = "config.yaml"
	// DefaultConfigFileRoot = ".config/noodle"
)

//go:embed config.yaml
var defaultConfig string

type Config struct {
	Cache  *badger.DB
	Global struct {
		IndentSpaces  int      `mapstructure:"indent-spaces"`
		Ports         []string `mapstructure:"ports"`
		MaxValueChars int32    `mapstructure:"max-value-chars"`
	} `mapstructure:"global"`
	HttpClient *retryablehttp.Client
	Host       netip.Addr
	Providers  Providers `mapstructure:"providers"`

	// MaxWidth      int
	UseTestData bool
}

type Providers struct {
	Shodan struct {
		APIKey      string   `mapstructure:"api-key"`
		Enabled     bool     `mapstructure:"enabled"`
		MaxPorts    int      `mapstructure:"max-ports"`
		Ports       []int    `mapstructure:"ports"`
		Protocols   []string `mapstructure:"protocols"`
		NoOlderThan string   `mapstructure:"no-older-than"`
	} `mapstructure:"shodan"`
	CriminalIP struct {
		APIKey      string   `mapstructure:"api-key"`
		Enabled     bool     `mapstructure:"enabled"`
		MaxPorts    int      `mapstructure:"max-ports"`
		Ports       []int    `mapstructure:"ports"`
		Protocols   []string `mapstructure:"protocols"`
		NoOlderThan string   `mapstructure:"no-older-than"`
	} `mapstructure:"criminalip"`
}

func unmarshalConfig(data []byte) (*Config, error) {
	var conf Config

	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &conf, nil
}

func CreateDefaultConfigIfMissing(path string) error {
	var conf *Config

	var err error

	// check if config already exists
	if _, err = os.Stat(filepath.Join(path, DefaultConfigFileName)); err == nil {
		return nil
	}

	// check default config is valid
	if conf, err = unmarshalConfig([]byte(defaultConfig)); err != nil {
		return fmt.Errorf("default config invalid: %w", err)
	}

	if err = yaml.Unmarshal([]byte(defaultConfig), &conf); err != nil {
		return fmt.Errorf("default config invalid: %w", err)
	}

	// create dir specified in path argument if missing
	if _, err = os.Stat(path); os.IsNotExist(err) {
		if err = os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	// create default config file if missing
	if _, err = os.Stat(path); os.IsNotExist(err) {
		if err = os.WriteFile(filepath.Join(path, DefaultConfigFileName), []byte(defaultConfig), 0700); err != nil {
			return fmt.Errorf("failed to write default config: %w", err)
		}
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
