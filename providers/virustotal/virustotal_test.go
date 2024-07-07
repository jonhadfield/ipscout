package virustotal

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"

	"github.com/stretchr/testify/require"
)

func TestRateHost(t *testing.T) {
	rc := providers.RatingConfig{}
	rc.Global.HighThreatCountryCodes = []string{"CN"}
	rc.Global.MediumThreatCountryCodes = []string{"US"}
	rc.ProviderRatingsConfigs.VirusTotal.SuspiciousScore = ToPtr(float64(7.6))
	rc.ProviderRatingsConfigs.VirusTotal.MaliciousScore = ToPtr(float64(9.2))
	attrs := HostSearchResultDataAttributes{
		LastAnalysisStats:    LastAnalysisStats{},
		LastAnalysisResults:  LastAnalysisResults{},
		LastModificationDate: 0,
		LastAnalysisDate:     0,
		Reputation:           0,
		Country:              "",
		TotalVotes:           TotalVotes{},
		Asn:                  0,
	}

	res := rateHost(attrs, rc)
	// nothing detected so should return 0
	require.Equal(t, float64(0), res.Score)

	// expect country US to bring score up to 3
	attrs.Country = "US"
	res = rateHost(attrs, rc)
	require.Equal(t, float64(6), res.Score)

	// setting a report of suspicious should bring score up to 7.6
	attrs.LastAnalysisStats.Suspicious = 2
	res = rateHost(attrs, rc)
	require.Equal(t, float64(7.6), res.Score)

	// setting a report of malicious should bring score up to 9.2
	attrs.LastAnalysisStats.Malicious = 1
	res = rateHost(attrs, rc)
	require.Equal(t, float64(9.2), res.Score)
}

//nolint:funlen
func TestVirusTotalHostQuery(t *testing.T) {
	t.Parallel()

	jf, err := os.Open("testdata/virustotal_183_81_169_238_resp.json")
	require.NoError(t, err)
	defer jf.Close()

	decoder := json.NewDecoder(jf)

	var vtr HostSearchResult
	err = decoder.Decode(&vtr)
	require.NoError(t, err)
	require.Equal(t, "183.81.169.238", vtr.Data.ID)
	require.Equal(t, "https://www.virustotal.com/api/v3/ip_addresses/183.81.169.238", vtr.Data.Links.Self)
	require.Equal(t, 1715748622, vtr.Data.Attributes.LastModificationDate)
	require.Equal(t, "inetnum: 182.161.64.0 - 184.255.255.255\nnetname: NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK\ndescr: IPv4 address block not managed by the RIPE NCC\nremarks: ------------------------------------------------------\nremarks:\nremarks: For registration information,\nremarks: you can consult the following sources:\nremarks:\nremarks: IANA\nremarks: http://www.iana.org/assignments/ipv4-address-space\nremarks: http://www.iana.org/assignments/iana-ipv4-special-registry\nremarks: http://www.iana.org/assignments/ipv4-recovered-address-space\nremarks:\nremarks: AFRINIC (Africa)\nremarks: http://www.afrinic.net/ whois.afrinic.net\nremarks:\nremarks: APNIC (Asia Pacific)\nremarks: http://www.apnic.net/ whois.apnic.net\nremarks:\nremarks: ARIN (Northern America)\nremarks: http://www.arin.net/ whois.arin.net\nremarks:\nremarks: LACNIC (Latin America and the Carribean)\nremarks: http://www.lacnic.net/ whois.lacnic.net\nremarks:\nremarks: ------------------------------------------------------\ncountry: EU # Country is really world wide\nadmin-c: IANA1-RIPE\ntech-c: IANA1-RIPE\nstatus: ALLOCATED UNSPECIFIED\nmnt-by: RIPE-NCC-HM-MNT\ncreated: 2021-12-21T16:03:56Z\nlast-modified: 2021-12-21T16:03:56Z\nsource: RIPE\nrole: Internet Assigned Numbers Authority\naddress: see http://www.iana.org.\nadmin-c: IANA1-RIPE\ntech-c: IANA1-RIPE\nnic-hdl: IANA1-RIPE\nremarks: For more information on IANA services\nremarks: go to IANA web site at http://www.iana.org.\nmnt-by: RIPE-NCC-MNT\ncreated: 1970-01-01T00:00:00Z\nlast-modified: 2001-09-22T09:31:27Z\nsource: RIPE # Filtered\n", vtr.Data.Attributes.Whois) //nolint:misspell
	require.Equal(t, 1713585338, vtr.Data.Attributes.WhoisDate)
	require.Equal(t, -6, vtr.Data.Attributes.Reputation)
	require.Equal(t, "NL", vtr.Data.Attributes.Country)
	require.Equal(t, 0, vtr.Data.Attributes.TotalVotes.Harmless)
	require.Equal(t, 6, vtr.Data.Attributes.TotalVotes.Malicious)
	require.Equal(t, "EU", vtr.Data.Attributes.Continent)
	require.Equal(t, "ip_address", vtr.Data.Type)
	require.Equal(t, 206264, vtr.Data.Attributes.Asn)
	require.Equal(t, "Amarutu Technology Ltd", vtr.Data.Attributes.AsOwner)
	require.Equal(t, "https://www.virustotal.com/api/v3/ip_addresses/183.81.169.238", vtr.Data.Links.Self)
	require.Equal(t, 15, vtr.Data.Attributes.LastAnalysisStats.Malicious)
	require.Equal(t, 2, vtr.Data.Attributes.LastAnalysisStats.Suspicious)
	require.Equal(t, 24, vtr.Data.Attributes.LastAnalysisStats.Undetected)
	require.Equal(t, 51, vtr.Data.Attributes.LastAnalysisStats.Harmless)
	require.Equal(t, 0, vtr.Data.Attributes.LastAnalysisStats.Timeout)
	require.Equal(t, "blacklist", vtr.Data.Attributes.LastAnalysisResults.Acronis.Method)
	require.Equal(t, "Acronis", vtr.Data.Attributes.LastAnalysisResults.Acronis.EngineName)
	require.Equal(t, "harmless", vtr.Data.Attributes.LastAnalysisResults.Acronis.Category)
	require.Equal(t, "clean", vtr.Data.Attributes.LastAnalysisResults.Acronis.Result)
	require.Equal(t, "blacklist", vtr.Data.Attributes.LastAnalysisResults.ZeroXSIF33D.Method)
	require.Equal(t, "0xSI_f33d", vtr.Data.Attributes.LastAnalysisResults.ZeroXSIF33D.EngineName)
	require.Equal(t, "undetected", vtr.Data.Attributes.LastAnalysisResults.ZeroXSIF33D.Category)
	require.Equal(t, "unrated", vtr.Data.Attributes.LastAnalysisResults.ZeroXSIF33D.Result)
	require.Equal(t, "blacklist", vtr.Data.Attributes.LastAnalysisResults.Abusix.Method)
	require.Equal(t, "Abusix", vtr.Data.Attributes.LastAnalysisResults.Abusix.EngineName)
	require.Equal(t, "harmless", vtr.Data.Attributes.LastAnalysisResults.Abusix.Category)
	require.Equal(t, "clean", vtr.Data.Attributes.LastAnalysisResults.Abusix.Result)
	require.Equal(t, "blacklist", vtr.Data.Attributes.LastAnalysisResults.ADMINUSLabs.Method)
	require.Equal(t, "ADMINUSLabs", vtr.Data.Attributes.LastAnalysisResults.ADMINUSLabs.EngineName)
	require.Equal(t, "harmless", vtr.Data.Attributes.LastAnalysisResults.ADMINUSLabs.Category)
	require.Equal(t, "clean", vtr.Data.Attributes.LastAnalysisResults.ADMINUSLabs.Result)
	require.Equal(t, "blacklist", vtr.Data.Attributes.LastAnalysisResults.CriminalIP.Method)
	require.Equal(t, "Criminal IP", vtr.Data.Attributes.LastAnalysisResults.CriminalIP.EngineName)
	require.Equal(t, "malicious", vtr.Data.Attributes.LastAnalysisResults.CriminalIP.Category)
	require.Equal(t, "malicious", vtr.Data.Attributes.LastAnalysisResults.CriminalIP.Result)
	require.Equal(t, "blacklist", vtr.Data.Attributes.LastAnalysisResults.AILabsMONITORAPP.Method)
	require.Equal(t, "AILabs (MONITORAPP)", vtr.Data.Attributes.LastAnalysisResults.AILabsMONITORAPP.EngineName)
	require.Equal(t, "harmless", vtr.Data.Attributes.LastAnalysisResults.AILabsMONITORAPP.Category)
	require.Equal(t, "clean", vtr.Data.Attributes.LastAnalysisResults.AILabsMONITORAPP.Result)
	require.Equal(t, "suspicious", vtr.Data.Attributes.LastAnalysisResults.AlphaMountainAi.Result)
	require.Equal(t, "unrated", vtr.Data.Attributes.LastAnalysisResults.AutoShun.Result)
	require.Equal(t, "clean", vtr.Data.Attributes.LastAnalysisResults.BforeAiPreCrime.Result)
	require.Equal(t, "clean", vtr.Data.Attributes.LastAnalysisResults.Blueliv.Result)
}

func ToPtr[T any](v T) *T {
	return &v
}

func TestAnalysisResultData_ShouldOutput(t *testing.T) {
	s := session.New()
	s.Providers.VirusTotal.ShowProviders = ToPtr(true)
	s.Providers.VirusTotal.ShowClean = ToPtr(true)
	s.Providers.VirusTotal.ShowHarmless = ToPtr(true)

	type fields struct {
		Method     string
		EngineName string
		Category   string
		Result     string
	}

	type args struct {
		session.Session
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		// TODO: Add test cases.
		{
			name: "show clean not harmless",
			args: args{},
			want: true,
			fields: fields{
				Method:     "blacklist",
				EngineName: "Acronis",
				Category:   "harmless",
				Result:     "clean",
			},
		},
		{
			name: "show harmless not clean",
			args: args{
				*s,
			},
			want: true,
			fields: fields{
				Method:     "blacklist",
				EngineName: "Acronis",
				Category:   "harmless",
				Result:     "harmless",
			},
		},
		{
			name: "show harmless and clean",
			args: args{
				*s,
			},
			want: true,
			fields: fields{
				Method:     "blacklist",
				EngineName: "Acronis",
				Category:   "harmless",
				Result:     "clean",
			},
		},
		{
			name: "show neither",
			args: args{
				*s,
			},
			want: false,
			fields: fields{
				Method:     "blacklist",
				EngineName: "Acronis",
				Category:   "harmless",
				Result:     "none",
			},
		},
		{
			name: "show neither with unrated",
			args: args{
				*s,
			},
			want: false,
			fields: fields{
				Method:     "blacklist",
				EngineName: "Acronis",
				Category:   "harmless",
				Result:     "unrated",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ard := AnalysisResultData{
				Method:     tt.fields.Method,
				EngineName: tt.fields.EngineName,
				Category:   tt.fields.Category,
				Result:     tt.fields.Result,
			}
			if got := ard.ShouldOutput(s); got != tt.want {
				t.Errorf("ShouldOutput() = %v, want %v", got, tt.want)
			}
		})
	}
}
