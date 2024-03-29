package config

import (
	"github.com/hashicorp/go-retryablehttp"
	"net/netip"
)

const (
	DefaultIndentSpaces = 2
)

type Config struct {
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
