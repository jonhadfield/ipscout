package shodan

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShodanHostDNSQuery(t *testing.T) {
	t.Parallel()

	jf, err := os.Open("testdata/shodan_google_dns_resp.json")
	require.NoError(t, err)
	defer jf.Close()

	decoder := json.NewDecoder(jf)

	var sr HostSearchResult
	err = decoder.Decode(&sr)
	require.NoError(t, err)

	require.Equal(t, "Mountain View", sr.City)
	require.Equal(t, "CA", sr.RegionCode)
	require.Nil(t, sr.Os)
	require.Empty(t, sr.Tags)
	require.Equal(t, 134744072, sr.IP)
	require.Equal(t, "Google LLC", sr.Isp)
	require.Nil(t, sr.AreaCode)
	require.Equal(t, -122.0775, sr.Longitude)
	require.Equal(t, "2024-04-28T12:50:55.650683", sr.LastUpdate)
	require.Equal(t, []int{443, 53}, sr.Ports)
	require.Equal(t, 37.4056, sr.Latitude)
	require.Equal(t, []string{"dns.google"}, sr.Hostnames)
	require.Equal(t, "US", sr.CountryCode)
	require.Equal(t, "United States", sr.CountryName)
	require.Equal(t, []string{"dns.google"}, sr.Domains)
	require.Equal(t, "Google LLC", sr.Org)
	require.Equal(t, -553166942, sr.Data[0].Hash)
	require.Empty(t, sr.Data[0].Opts)
	require.Equal(t, "2024-04-28T09:18:08.964972", sr.Data[0].Timestamp)
	require.Equal(t, "Google LLC", sr.Data[0].Isp)
	require.Equal(t, "\nRecursion: enabled", sr.Data[0].Data)
	require.NotNil(t, sr.Data[0].Shodan)
	require.Equal(t, "na", sr.Data[0].Shodan.Region)
	require.Equal(t, "dns-tcp", sr.Data[0].Shodan.Module)
	require.True(t, sr.Data[0].Shodan.Ptr)
	require.Empty(t, sr.Data[0].Shodan.Options)
	require.Equal(t, "750fb3c2-8743-44db-b1ff-25e9028e4345", sr.Data[0].Shodan.ID)
	require.Equal(t, "d89a99e2d29a6c9d44f01585e74209a6c7d174c7", sr.Data[0].Shodan.Crawler)
	require.Equal(t, 53, sr.Data[0].Port)
	require.Equal(t, []string{"dns.google"}, sr.Data[0].Hostnames)
	require.Equal(t, "2024-04-28T09:18:08.964972", sr.Data[0].Timestamp)
	require.NotEmpty(t, sr.Data[0].Location)
	require.Equal(t, "Mountain View", sr.Data[0].Location.City)
	require.Equal(t, "CA", sr.Data[0].Location.RegionCode)
	require.Nil(t, sr.Data[0].Location.AreaCode)
	require.Equal(t, -122.0775, sr.Data[0].Location.Longitude)
	require.Equal(t, 37.4056, sr.Data[0].Location.Latitude)
	require.Equal(t, "United States", sr.Data[0].Location.CountryName)
	require.Equal(t, "US", sr.Data[0].Location.CountryCode)
	require.Nil(t, sr.Data[0].DNS.ResolverHostname)
	require.True(t, sr.Data[0].DNS.Recursive)
	require.Nil(t, sr.Data[0].DNS.ResolverID)
	require.Nil(t, sr.Data[0].DNS.Software)
	require.Equal(t, 134744072, sr.Data[0].IP)
	require.Equal(t, "dns.google", sr.Data[0].Domains[0])
	require.Equal(t, "Google LLC", sr.Data[0].Org)
	require.Nil(t, sr.Data[0].Os)
	require.Equal(t, "AS15169", sr.Data[0].Asn)
	require.Equal(t, "tcp", sr.Data[0].Transport)
	require.Equal(t, "8.8.8.8", sr.Data[0].IPStr)
	// ///
	require.Equal(t, -553166942, sr.Data[1].Hash)
	require.Empty(t, sr.Data[1].Opts)
	require.Equal(t, "2024-04-28T12:50:55.650683", sr.Data[1].Timestamp)
	require.Equal(t, "Google LLC", sr.Data[1].Isp)
	require.Equal(t, "\nRecursion: enabled", sr.Data[1].Data)
	require.NotNil(t, sr.Data[1].Shodan)
	require.Equal(t, "eu", sr.Data[1].Shodan.Region)
	require.Equal(t, "dns-udp", sr.Data[1].Shodan.Module)
	require.True(t, sr.Data[1].Shodan.Ptr)
	require.Empty(t, sr.Data[1].Shodan.Options)
	require.Equal(t, "8a5051c2-01a9-44fc-850a-25335e57326e", sr.Data[1].Shodan.ID)
	require.Equal(t, "487814a778c983e2dcef234806292d88c5cbf3ec", sr.Data[1].Shodan.Crawler)
	require.Equal(t, 53, sr.Data[1].Port)
	require.Equal(t, []string{"dns.google"}, sr.Data[1].Hostnames)
	require.Equal(t, "2024-04-28T12:50:55.650683", sr.Data[1].Timestamp)
	require.NotEmpty(t, sr.Data[1].Location)
	require.Equal(t, "Mountain View", sr.Data[1].Location.City)
	require.Equal(t, "CA", sr.Data[1].Location.RegionCode)
	require.Nil(t, sr.Data[1].Location.AreaCode)
	require.Equal(t, -122.0775, sr.Data[1].Location.Longitude)
	require.Equal(t, 37.4056, sr.Data[1].Location.Latitude)
	require.Equal(t, "United States", sr.Data[1].Location.CountryName)
	require.Equal(t, "US", sr.Data[1].Location.CountryCode)
	require.Nil(t, sr.Data[1].DNS.ResolverHostname)
	require.True(t, sr.Data[1].DNS.Recursive)
	require.Nil(t, sr.Data[1].DNS.ResolverID)
	require.Nil(t, sr.Data[1].DNS.Software)
	require.Equal(t, 134744072, sr.Data[1].IP)
	require.Equal(t, "dns.google", sr.Data[1].Domains[0])
	require.Equal(t, "Google LLC", sr.Data[1].Org)
	require.Nil(t, sr.Data[1].Os)
	require.Equal(t, "AS15169", sr.Data[1].Asn)
	require.Equal(t, "udp", sr.Data[1].Transport)
	require.Equal(t, "8.8.8.8", sr.Data[1].IPStr)
	// ///
	require.Equal(t, -1020052518, sr.Data[2].Hash)
	require.Empty(t, sr.Data[2].Opts)
	require.Equal(t, "2024-04-28T09:25:24.474444", sr.Data[2].Timestamp)
	require.Equal(t, "Google LLC", sr.Data[2].Isp)
	require.Equal(t, "HTTP/1.1 200 OK\r\nContent-Security-Policy: object-src 'none';base-uri 'self';script-src 'nonce-iRRB3YCy7UKnm1gs9cWAWA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/honest_dns/1_0;frame-ancestors 'none'\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 28 Apr 2024 09:25:24 GMT\r\nServer: scaffolding on HTTPServer2\r\nCache-Control: private\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\nAccept-Ranges: none\r\nVary: Accept-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n", sr.Data[2].Data)
	require.NotNil(t, sr.Data[2].Shodan)
	require.Equal(t, "na", sr.Data[2].Shodan.Region)
	require.Equal(t, "https", sr.Data[2].Shodan.Module)
	require.True(t, sr.Data[2].Shodan.Ptr)
	require.Empty(t, sr.Data[2].Shodan.Options)
	require.Equal(t, "80b7f761-7a88-4a9b-acd0-dfb1f260c5aa", sr.Data[2].Shodan.ID)
	require.Equal(t, "ea0db9f26a43b503e537983ddb14b4f59b0f8632", sr.Data[2].Shodan.Crawler)
	require.Equal(t, 443, sr.Data[2].Port)
	require.Equal(t, []string{"dns.google"}, sr.Data[2].Hostnames)
	require.Equal(t, "2024-04-28T09:25:24.474444", sr.Data[2].Timestamp)
	require.NotEmpty(t, sr.Data[2].Location)
	require.Equal(t, "Mountain View", sr.Data[2].Location.City)
	require.Equal(t, "CA", sr.Data[2].Location.RegionCode)
	require.Nil(t, sr.Data[2].Location.AreaCode)
	require.Equal(t, -122.0775, sr.Data[2].Location.Longitude)
	require.Equal(t, 37.4056, sr.Data[2].Location.Latitude)
	require.Equal(t, "United States", sr.Data[2].Location.CountryName)
	require.Equal(t, "US", sr.Data[2].Location.CountryCode)
	require.Equal(t, 200, sr.Data[2].HTTP.Status)
	require.Empty(t, sr.Data[2].HTTP.RobotsHash)
	require.Equal(t, "help.emarketer.com", sr.Data[2].HTTP.Redirects[0].Host)
	require.Equal(t, "HTTP/1.1 302 Found\r\nX-Content-Type-Options: nosniff\r\nAccess-Control-Allow-Origin: *\r\nLocation: https://dns.google/\r\nDate: Sun, 28 Apr 2024 09:25:22 GMT\r\nContent-Type: text/html; charset=UTF-8\r\nServer: HTTP server (unknown)\r\nContent-Length: 216\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\n\r\n", sr.Data[2].HTTP.Redirects[0].Data)
	require.Equal(t, "/", sr.Data[2].HTTP.Location)
	require.Equal(t, "", sr.Data[2].HTTP.SecurityTxt)
	require.Equal(t, "Google Public DNS", sr.Data[2].HTTP.Title)
	require.Equal(t, 0, sr.Data[2].HTTP.SitemapHash)
	require.Equal(t, -82718941, sr.Data[2].HTTP.HTMLHash)
	require.Empty(t, sr.Data[2].HTTP.Robots)
	require.Equal(t, 56641965, sr.Data[2].HTTP.Favicon.Hash)
	require.Equal(t, "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAABa1BMVEUAAAA0p100qFM0qFY1pW81\npmg1p141p2M2pHw2pH02pXU3oYs3ook4n5k4oY85np86m6s6m6w7mLo7mLs7mbY7mbc7p1M8lcQ8\nlsM+ks4+ks8+oYo/j9g/j9k/kNg/p1NAiudAi+VAjOFAjeBBh+9BiO1BietChfRChvJEhfRIhvNI\npVJJonNKhPJMhPJMpVJRkcdTh/BXo1FZie5ag+xeie1fhORmlZ5on1Bsnk90juV4m05+jOCAmE2D\ngMuMkdmNk0yQkkuQlNeWltSXj0qliEiubLqvgka0f0W1lbm4m7e7mrS9eUPBdkLHcEDOm5vSZj3S\noJXTZD3UoJLZXTvdWTrgonzhUzjkTjflp3LmSjfoRjboRzbqQzXqRDXqRTXqRjXqRzXsYDHtYjHt\nYzHtqlruqlfveSzveizweyzwr0/yjSbyjib1nSD1nh/1nx/3tSz4rBf4rRb4tyb6uQn6uQr6uhn7\nugj7vAU/At79AAAAAXRSTlMAQObYZgAAArlJREFUeNrt2PVz1EAYxvFlcSnFXQoUXgoUdyvu7ra4\nFy22fz53NJ27Xmx38z7vwpHnl860yXw/c9PJJVGqXuXp9KLGBRG6bHHrWIJ2XeQ8iKB1VIH2Xuw+\nryCkr7dH7vcSRe3PWE9cgqD+xJVETIKgvp5PxCQI68/eyAUI60/uI+IRhPX1MmICBPbnEjEJnC52\nqd9O7+cCuF9p2/8wZS3hAUXHLiZiEnh+zSR/7CE4oPD4SRvYAP7fss1L8AoCA0pOWUjEJQi5y9DL\nB+MC1F4CA8pOIj5A4G1elwNUDfjfAaoGhAGUJAB8Ja4BQX3JL0PO/l8K0P59QQBv31tAJAPQYn2v\n5yIC9D2eDImkAe0EIlTf4fXEPiJkvxSwZTe2XyZIXgUC+yWCefh+oWDmoEBfHXd5FQjsK3V5Ww5g\nqUxfqdtHMvtzhPJKmYfnVqf70/qF+qa5Gwc6+xPWyfRNsgenOwBLZP4BTGtXdrb3ewYkLgFm3O4e\na/XTrwIRAtOxx5c2j12CVxHhBSa9W4dGAQuI8AKTtUdnFzX6s7YSXmBydm2/nrqG8ACTu3unjhLB\nBaZoRHBBYd+caT/08CYAoDCfPvz1navnh3ZwCnzqf2Yb+/Kq6djFAfDNJ4LRfXt//+bFE3uqCAL6\n4whjjusXTh4cYASUnWaz9lOunyOwcn0swOlUIEDJASp8ANkCwQ+gOwCV+pmCbgCoGiAIqNiPDrA1\nIDLAdinACPb/bQDPHRnz/ZgggKkffEdmsQAj1g8EWD6ACngutJx9/ydTa4UA2QTL3S9+O+JThwBa\nisbPr5i+gyDZR1DfGTAM6jsL3sQGPEf1XQVPfqD6roIRWN9R8AnXdxMM4/JugrfIvovgBbTvIHj6\nHZl3EYxg++WEz+B8KeEDPF8ieIfPFxteStSLDM9+ydTzEapelf0GmFdLbOXMqToAAAAASUVORK5C\nYII=\n", sr.Data[2].HTTP.Favicon.Data)
	require.Equal(t, "https://dns.google:443/static/93dd5954/favicon.png", sr.Data[2].HTTP.Favicon.Location)
	require.Equal(t, 134744072, sr.Data[2].IP)
	require.Equal(t, "dns.google", sr.Data[2].Domains[0])
	require.Equal(t, "Google LLC", sr.Data[2].Org)
	require.Nil(t, sr.Data[2].Os)
	require.Equal(t, "AS15169", sr.Data[2].Asn)
	require.Equal(t, "tcp", sr.Data[2].Transport)
	require.Equal(t, "8.8.8.8", sr.Data[2].IPStr)
}
