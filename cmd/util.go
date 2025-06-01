package cmd

import (
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	retryWaitMin = 3 * time.Second
	retryWaitMax = 5 * time.Second
	retryMax     = 3
)

func getHTTPClient() *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.RetryWaitMin = retryWaitMin
	hc.RetryWaitMax = retryWaitMax
	hc.RetryMax = retryMax
	hc.Logger = nil

	return hc
}
