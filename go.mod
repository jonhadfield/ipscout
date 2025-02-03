module github.com/jonhadfield/ipscout

go 1.22.4

require (
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor v1.4.0
	github.com/araddon/dateparse v0.0.0-20210429162001-6b43995a97de
	github.com/briandowns/spinner v1.23.2
	github.com/dgraph-io/badger/v4 v4.5.1
	github.com/dustin/go-humanize v1.0.1
	github.com/fatih/color v1.18.0
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/jedib0t/go-pretty/v6 v6.6.5
	github.com/jonhadfield/azwaf v0.0.0-20241111151416-7d03038b2003
	github.com/jonhadfield/ip-fetcher v0.0.0-20241024131552-b949d3536ff6
	github.com/miekg/dns v1.1.62
	github.com/mitchellh/go-homedir v1.1.0
	github.com/sashabaranov/go-openai v1.36.1
	github.com/spf13/cobra v1.8.1
	github.com/spf13/pflag v1.0.6
	github.com/spf13/viper v1.19.0
	github.com/stretchr/testify v1.10.0
	golang.org/x/sync v0.10.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

//replace github.com/jonhadfield/ip-fetcher => ../ip-fetcher
// replace github.com/jonhadfield/azwaf => ../azwaf

require (
	github.com/Azure/azure-pipeline-go v0.2.3 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.16.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.8.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.2.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage v1.6.0 // indirect
	github.com/Azure/azure-storage-blob-go v0.15.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.3.1 // indirect
	github.com/Danny-Dasilva/CycleTLS/cycletls v1.0.26 // indirect
	github.com/Danny-Dasilva/fhttp v0.0.0-20240217042913-eeeb0b347ce1 // indirect
	github.com/alexeyco/simpletable v1.0.0 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.3.9 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgraph-io/ristretto/v2 v2.1.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/flatbuffers v24.12.23+incompatible // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hexops/gotextdiff v1.0.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jonhadfield/findexec v0.0.0-20190902195615-78db24cd4e77 // indirect
	github.com/jszwec/csvutil v1.10.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-ieproxy v0.0.12 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/refraction-networking/utls v1.6.6 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sagikazarmark/locafero v0.6.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tidwall/btree v1.7.0 // indirect
	github.com/tidwall/buntdb v1.3.2 // indirect
	github.com/tidwall/gjson v1.17.1 // indirect
	github.com/tidwall/grect v0.1.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/rtred v0.1.2 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tidwall/tinyqueue v0.1.1 // indirect
	github.com/wI2L/jsondiff v0.6.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/ztrue/tracerr v0.4.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/term v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	google.golang.org/protobuf v1.36.3 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	h12.io/socks v1.0.3 // indirect
)
