package cmd

import "github.com/hashicorp/go-retryablehttp"

func getHTTPClient() *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.RetryWaitMin = 1
	hc.RetryWaitMax = 1
	hc.RetryMax = 1
	hc.Logger = nil

	return hc
}
