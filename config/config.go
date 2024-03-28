package config

import (
	"github.com/hashicorp/go-retryablehttp"
	"net/netip"
)

const (
	DefaultIndentSpaces = 2
)

type Default struct {
	HttpClient   *retryablehttp.Client
	Host         netip.Addr
	LimitPorts   []string
	MaxWidth     int
	IndentSpaces int
	UseTestData  bool
}
