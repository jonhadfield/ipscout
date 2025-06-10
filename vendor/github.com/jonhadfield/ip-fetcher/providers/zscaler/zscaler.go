package zscaler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ip-fetcher/internal/pflog"
	"github.com/jonhadfield/ip-fetcher/internal/web"
	"github.com/sirupsen/logrus"
)

const (
	ShortName   = "zscaler"
	FullName    = "Zscaler"
	HostType    = "security"
	SourceURL   = "https://www.zscaler.com"
	DownloadURL = "https://api.config.zscaler.com/zscaler.net/cenr/json"
)

type Zscaler struct {
	Client      *retryablehttp.Client
	DownloadURL string
}

func New() Zscaler {
	pflog.SetLogLevel()

	c := web.NewHTTPClient()
	if logrus.GetLevel() < logrus.DebugLevel {
		c.Logger = nil
	}

	return Zscaler{
		DownloadURL: DownloadURL,
		Client:      c,
	}
}

func (z *Zscaler) FetchData() ([]byte, http.Header, int, error) {
	if z.DownloadURL == "" {
		z.DownloadURL = DownloadURL
	}

	return web.Request(z.Client, z.DownloadURL, http.MethodGet, nil, nil, web.DefaultRequestTimeout)
}

func (z *Zscaler) Fetch() (Doc, error) {
	data, _, _, err := z.FetchData()
	if err != nil {
		return Doc{}, err
	}

	return ProcessData(data)
}

type Doc struct {
	ZscalerNet struct {
		ContinentEMEA struct {
			CityAbuDhabiII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Abu Dhabi II"`
			CityAmsterdamII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Amsterdam II"`
			CityAmsterdamIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Amsterdam III"`
			CityBrusselsII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Brussels II"`
			CityCapetownIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Capetown IV"`
			CityCopenhagenII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Copenhagen II"`
			CityDubaiI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Dubai I"`
			CityDusseldorfI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Dusseldorf I"`
			CityFrankfurtIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Frankfurt IV"`
			CityFrankfurtVI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Frankfurt VI"`
			CityHelsinkiI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Helsinki I"`
			CityJohannesburgIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Johannesburg III"`
			CityKingdomOfSaudiArabiaI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Kingdom of Saudi Arabia I"`
			CityLagosII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Lagos II"`
			CityLagosIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Lagos III"`
			CityLisbonI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Lisbon I"`
			CityLondonIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : London III"`
			CityLondonV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : London V"`
			CityMadridIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Madrid III"`
			CityMadridIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Madrid IV"`
			CityManchesterI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Manchester I"`
			CityManchesterII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Manchester II"`
			CityMarseilleI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Marseille I"`
			CityMilanIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Milan III"`
			CityMunichI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Munich I"`
			CityOsloIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Oslo III"`
			CityParisII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Paris II"`
			CityParisIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Paris IV"`
			CityRouenI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Rouen I"`
			CityStockholmIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Stockholm III"`
			CityTelAviv []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Tel Aviv"`
			CityTelAvivII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Tel Aviv II"`
			CityViennaI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Vienna I"`
			CityWarsawII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Warsaw II"`
			CityZurich []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Zurich"`
		} `json:"continent : EMEA"`
		ContinentAmericas struct {
			CityAtlantaII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Atlanta II"`
			CityAtlantaIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Atlanta III"`
			CityBogotaI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Bogota I"`
			CityBostonI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Boston I"`
			CityBuenosAiresI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Buenos Aires I"`
			CityChicago []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Chicago"`
			CityChicagoII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Chicago II"`
			CityDallasI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Dallas I"`
			CityDallasII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Dallas II"`
			CityDenverIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Denver III"`
			CityLosAngeles []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Los Angeles"`
			CityLosAngelesII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Los Angeles II"`
			CityMexicoCityI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Mexico City I"`
			CityMiamiIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Miami III"`
			CityMontrealI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Montreal I"`
			CityNewYorkIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : New York III"`
			CityNewYorkIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : New York IV"`
			CityNuevoLaredoI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Nuevo Laredo I"`
			CityRioDeJaneiroI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Rio de Janeiro I"`
			CitySanFranciscoIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : San Francisco IV"`
			CitySantiagoI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Santiago I"`
			CitySaoPaulo []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Sao Paulo"`
			CitySaoPauloII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Sao Paulo II"`
			CitySaoPauloIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Sao Paulo IV"`
			CitySeattle []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Seattle"`
			CityTorontoIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Toronto III"`
			CityVancouverI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Vancouver I"`
			CityWashingtonDC []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Washington DC"`
			CityWashingtonDCIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Washington DC IV"`
		} `json:"continent : Americas"`
		ContinentAPAC struct {
			CityAucklandII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Auckland II"`
			CityBeijing []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Beijing"`
			CityBeijingIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Beijing III"`
			CityCanberraI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Canberra I"`
			CityChennai []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Chennai"`
			CityChennaiII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Chennai II"`
			CityChennaiIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Chennai III"`
			CityHongKongIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Hong Kong III"`
			CityHyderabadI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Hyderabad I"`
			CityKualaLumpurI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Kuala Lumpur I"`
			CityMelbourneII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Melbourne II"`
			CityMumbaiIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Mumbai IV"`
			CityMumbaiVI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Mumbai VI"`
			CityMumbaiVII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Mumbai VII"`
			CityNewDelhiI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : New Delhi I"`
			CityOsakaI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Osaka I"`
			CityPerthI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Perth I"`
			CitySeoulI []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Seoul I"`
			CityShanghai []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Shanghai"`
			CityShanghaiII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Shanghai II"`
			CitySingaporeIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Singapore IV"`
			CitySingaporeV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Singapore V"`
			CitySydneyIII []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Sydney III"`
			CityTaipei []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Taipei"`
			CityTianjin []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Tianjin"`
			CityTokyoIV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Tokyo IV"`
			CityTokyoV []struct {
				Range     string `json:"range"`
				Vpn       string `json:"vpn"`
				Gre       string `json:"gre"`
				Hostname  string `json:"hostname"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"city : Tokyo V"`
		} `json:"continent : APAC"`
	} `json:"zscaler.net"`
}

func ProcessData(data []byte) (Doc, error) {
	var doc Doc
	if err := json.Unmarshal(data, &doc); err != nil {
		return Doc{}, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return doc, nil
}
