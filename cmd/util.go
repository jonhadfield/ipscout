package cmd

import "github.com/hashicorp/go-retryablehttp"

func getHTTPClient() *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.RetryWaitMin = 3
	hc.RetryWaitMax = 5
	hc.RetryMax = 3
	hc.Logger = nil

	return hc
}
