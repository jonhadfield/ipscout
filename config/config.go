package config

import (
	"github.com/hashicorp/go-retryablehttp"
	"net/netip"
)

type Default struct {
	HttpClient  *retryablehttp.Client
	Host        netip.Addr
	UseTestData bool
}
