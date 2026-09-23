# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- bump azwaf to 0.13.0, which moves to v2 of Azure's armfrontdoor SDK. The Azure WAF
  provider is unaffected in use; it needs Azure resource IDs and is disabled by default

## [0.15.3] - 2026-09-21

### Fixed

- a provider whose IP ranges could not be fetched, such as GitHub when its API rate limits
  you, was reported twice: "failed to fetch ip ranges for github", then "lookup failed for
  github". It is now reported once. It is still looked up, as it may answer from cached
  ranges

## [0.15.2] - 2026-09-21

### Fixed

- a provider refusing its API key was reported as a generic lookup failure. AbuseIPDB,
  IPAPI, IPQualityScore, Shodan and VirusTotal now report "rejected the API key", naming the
  environment variable to check. Shodan serves cached results for popular addresses without
  checking the key, so a bad Shodan key only shows up on lookups of other addresses

## [0.15.1] - 2026-09-21

### Fixed

- a config without an entry for a provider that needs setup, such as one of the keyed
  providers in a config written by an older release, printed "X provider not defined in
  config" for each of them on every run. A provider missing from the config is simply
  disabled, so these lines are gone

## [0.15.0] - 2026-09-21

A new install with no API keys used to get one to three results for most addresses. This
release adds two providers that need no key and answer for almost any address, fixes
IPAPI, and makes it clear when a provider that needs a key is not set up.

### Upgrading

- providers that need an API key (AbuseIPDB, Criminal IP, IPAPI, IPQualityScore, Shodan
  and VirusTotal) are now disabled in the default config. The first run of this release
  also updates your existing config, once, to disable any of them that has no key in the
  environment or in `api_key`, and says which it disabled. If you export a key in only some
  shells, run the upgrade from one that has it, or set `enabled: true` again afterwards.
  The change is recorded in a new `global.config_version` setting so it is never repeated
- a provider that needs a key and is enabled without one is now reported as an error
  instead of being skipped silently. To use one, set its key and set `enabled: true`
- IPAPI no longer runs without an API key. ipapi.co now rejects keyless requests for most
  users, so the IPAPI table had quietly stopped appearing. Location data now comes from the
  new ip-api.com provider unless you have an ipapi.co key

### Added

- ip-api.com provider: location, ISP and AS for any public address, and whether it is a
  proxy, VPN or Tor exit, a hosting provider or a mobile network. No API key is needed.
  Its free tier is limited to 45 requests a minute, is for non-commercial use only, and is
  served over plain HTTP, so the addresses you look up are sent unencrypted. Set
  `providers.ipapicom.enabled` to `false` if any of that rules it out
- InternetDB provider: the open ports, hostnames, tags, software and known vulnerabilities
  Shodan's free InternetDB holds for an address, with no API key. Private and other
  non-public addresses are not looked up
- when few providers have data on a host, a tip suggests API keys that would add more,
  with where to sign up. It appears at most once a day, never with `--output json`, and
  `global.disable_tips: true` turns it off
- a provider lookup that fails, such as a rate limited or unreachable API, is now reported
  after the results. Previously it was only logged, so the provider just seemed to have no
  data
- the TUI now shows config errors and warnings, failed lookups and the API key tip in its
  footer. It previously showed no messages at all

### Fixed

- IPAPI never sent the API key set in `providers.ipapi.api_key` or `IPAPI_API_KEY`, so
  setting one made no difference. It now sends it, and keeps it out of error messages
- an error response from ipapi.co, such as its rate limit, rendered nothing instead of
  being reported
- IPQualityScore ran without an API key when enabled in the config, and failed

## [0.14.1] - 2026-09-17

### Changed

- per-IP reputation and scanning results (AbuseIPDB, CriminalIP, VirusTotal, IPQS,
  Shodan) now render below ownership identity — bots, SaaS, CDN, hosting and the
  hyperscaler clouds — rather than above them. A GitLab or GCP match names who
  operates the host; those APIs enrich almost any address, so they sat too high
  when ranked only by "this exact IP". Exact blocklist hits stay near the top.
  Any `providers.<name>.output_priority` set in your config still takes precedence

## [0.14.0] - 2026-09-16

### Added

- eight providers from ip-fetcher v0.0.41: Amazonbot (with which of its three bot lists
  matched), CacheFly, Common Crawl's CCBot, GitLab, Huawei Cloud, Intercom (region and
  service), Mullvad VPN relays, and Salesforce Hyperforce (region and provider). All are
  enabled by default and need no API key

### Fixed

- a URL list the ipurl provider could not download — the firehol lists, or any configured
  in `providers.ipurl.urls` — was reported only as
  `error fetching ipurl data: url.GetPrefixURLMapFromURLResponses | no responses`, which
  said the download failed but not why. The cause is now part of the error: a refused proxy
  connection, a TLS or DNS failure, or the status a server answered with, such as a 403 from
  a filtering proxy

## [0.13.3] - 2026-09-15

### Fixed

- an azure login for a different tenant from the waf policy's subscription was reported
  only as `failed to fetch ip ranges for azurewaf (run with --log-level DEBUG for details)`,
  and the debug output was a paragraph of azure json with the tenant to use buried in it.
  It is now one line, like an expired login, naming the tenant the subscription belongs to:

  `azure waf: your azure login is for a different tenant from the waf policy's subscription, so its policies were not read. log in to the right tenant with: az login --tenant <id>`

  An expired login is still reported as expired; a login for the wrong tenant is not, since
  renewing it would change nothing

## [0.13.2] - 2026-09-14

### Fixed

- every `brew install`, `upgrade` and `update` printed Homebrew 7's warning that the ipscout
  cask calls the deprecated `postflight`. The cask now uses `postflight_steps`, which does
  the same thing: clearing the quarantine attribute so gatekeeper does not stop the binary

## [0.13.1] - 2026-09-14

### Fixed

- the providers whose ranges come from an ASN lookup — Alibaba, Contabo, Fly.io, Hetzner,
  IBM Cloud, Leaseweb, M247, OVH, Render, Scaleway, Tencent and Vultr — failed when a single
  RIPE stat lookup was slow, because one deadline covered the request and its retries, so a
  slow response used it up before a retry could run. Each attempt now has its own deadline
  and a slow lookup is tried up to three times. A failed lookup also no longer falls back to
  api.bgpview.io, which has not resolved since mid-2026, so it fails sooner and its error no
  longer names BGPView as a second source that was tried

## [0.13.0] - 2026-09-13

### Added

- Feodo Tracker and Tor exit node providers. abuse.ch's Feodo Tracker lists live botnet
  command and control servers — Dridex, Emotet, TrickBot, QakBot — and a match is the
  strongest single signal the tool reports, scoring 10.0 alongside the other threat feeds.
  Tor names the addresses traffic leaves the network from, which is not malicious in itself
  but means the address says nothing about who sent the request; it scores 6.0, above the
  identified services and below the threat feeds. Both sit with the blocklists in the
  output rather than with the ownership ranges, because both describe the exact address
- Microsoft 365 and Okta providers, reporting SaaS infrastructure. Microsoft 365 names the
  service area a range serves — Exchange Online, SharePoint, Skype or the common set — and
  Microsoft's own category for it, `Optimize`, `Allow` or `Default`. Okta names the cell,
  which is how it partitions its infrastructure

## [0.12.5] - 2026-09-13

### Fixed

- a provider that had already explained its own failure was named a second time in the
  generic `failed to fetch ip ranges for ...` line, which ends `run with --log-level DEBUG
  for details`. An expired azure login printed the cause and the `az login` command to fix
  it, and then a line inviting you to go looking for details that were already on screen.
  A provider that reports its own failure is now left out of the generic line

## [0.12.4] - 2026-09-13

### Fixed

- an expired azure login printed the whole azure error over the progress spinner: a paragraph of
  trace ids, correlation ids and timestamps, ending in the `az login` command to run. The
  expired-credential failures are now recognised and reported as one line after the results,
  naming the tenant to re-authenticate against:

  `azure waf: your azure credentials have expired, so its policies were not read. re-authenticate with: az login --tenant <id>`

  The full error is still available with `--log-level DEBUG`, which is now also the only level at
  which azwaf's own logging reaches the console. It logs a failed api call at ERROR, which is why
  this appeared over the spinner however ipscout's own log level was set

## [0.12.3] - 2026-09-05

### Changed

- releasing no longer needs `GITLAB_TOKEN` or `GITEA_TOKEN` unset by hand. goreleaser stops rather
  than guess when it can see tokens for more than one forge, and cutting 0.12.2 failed on that
  before it built anything. `make smoke` and `make release` now run goreleaser with those two
  unset in its environment, leaving the shell they were run from alone

- a scheduled job installs the Homebrew cask on macOS each week and checks that the binary runs.
  The cask clears `com.apple.quarantine` in a `postflight` block, which Homebrew has deprecated and
  goreleaser still generates; if that stanza stops running, gatekeeper kills the installed binary
  with no output, no release fails, and the first report would come from somebody who installed it

Nothing about ipscout itself changed in this release. The binaries are built from the same source
as 0.12.2 and behave identically, so there is no reason to upgrade for its own sake.

## [0.12.2] - 2026-09-05

### Fixed

- the install script did nothing on macOS. It tested `uname` against the lowercase `darwin`,
  where `uname` answers `Darwin`, so the branch that installs the binary never ran and the
  script exited reporting success. Only the Linux branch had ever worked

- the install script unpacked the archive into whatever directory it was run from and removed
  only the tarball afterwards, leaving the binary behind there. It works in a temporary
  directory that is removed however it exits

### Added

- the install script verifies the archive against the `checksums.txt` published beside it, and
  refuses to install a download that does not match. It also reads `IPSCOUT_VERSION` to pin a
  release, `IPSCOUT_INSTALL_DIR` to install somewhere other than `/usr/local/bin`, and
  `GITHUB_URL` for a mirror. It creates the install directory if it is missing, reaches for
  `sudo` only when the directory cannot be written to otherwise, and says so when the directory
  is not on your `PATH`

## [0.12.1] - 2026-09-04

### Changed

- built with Go 1.26.8, and ip-fetcher bumped to v0.0.35, which carries the
  `golang.org/x/crypto` v0.56.0 fix for GO-2026-6355 and GO-2026-6354

  Neither changes what ipscout does. The x/crypto advisories are reached through
  ip-fetcher's publisher, which ipscout does not import, and 0.12.0's binaries were
  already built on a patched toolchain, so this is dependency hygiene rather than a fix
  for anything a 0.12.0 user is exposed to. ip-fetcher v0.0.34 and v0.0.35 have identical
  provider source, so no lookup behaviour changes

## [0.12.0] - 2026-09-02

### Added

- Grafana Synthetic Monitoring, Sentry Uptime, Site24x7, updown.io and Uptrends providers,
  reporting whether the host is a monitoring probe rather than a visitor or the origin of
  the traffic it appears to send. Grafana and Site24x7 name the probe location, updown.io
  the node's city and country
- Detectify and Tenable providers, reporting whether the host is a vulnerability scanner
  belonging to a named service rather than an unattributed source probing your estate.
  Tenable names the region, service and sensor group behind the range, and flags a match
  in its separately published FedRAMP ranges

  Both sit above the monitoring providers in the output, and score 2.0 rather than the 1.0
  a monitoring probe scores: a scan is activity directed at you, where a probe is not

### Changed

- the release smoke test asserts the exact number of provider tables the packaged binary
  renders rather than merely more than zero. A build that had lost all but one provider
  passed the old check, which is the failure the script exists to catch. The count is
  `registry.All()` minus Azure WAF, the only provider that cannot be enabled without
  configuration. Adding a provider now means bumping `EXPECTED_TABLES` in
  `scripts/smoke.sh` alongside `expectedProviderCount`, or the release gate fails

## [0.11.5] - 2026-08-31

### Changed

- provider results are ordered by how specifically a match identifies the host, narrowest
  claim first: your own annotated prefixes, then blocklist hits naming the exact address,
  per-IP reputation and scanning, named bots and crawlers, monitoring probes, SaaS egress
  and CDN edge ranges, hosting providers, the hyperscaler clouds, and last PTR, IPtoASN
  and IPAPI, which make no ownership or threat claim at all

  The previous order had grown entry by entry and was inverted in places. Googlebot,
  Bingbot, Applebot and the other crawlers sat below Google, so a match on a small
  purpose-built range ranked beneath the enormous range containing it. Imperva sat with
  the blocklists, though a match there says who fronts the origin rather than who the
  host is. OVH, Hetzner and DigitalOcean were spread across the table despite being the
  same kind of answer

  Any `providers.<name>.output_priority` set in your config still takes precedence, so an
  order you have tuned yourself is unaffected
- the default output priorities were duplicated between the CLI and the TUI, which could
  drift and order the same results differently in each. Both now read the constants
  package, and Alibaba, Scaleway and Vultr have entries there rather than only local ones

## [0.11.4] - 2026-08-31

### Fixed

- a CriminalIP honeypot match scored nothing. The shipped rating config spelled the key
  `honeypotAttacked` while the code reads `honeypotAttackedScore`, so the value parsed as
  zero and the score was never raised. "This address attacked a honeypot" is the strongest
  signal CriminalIP reports, and it counted for less than being cloud-hosted

  If you have your own rating config it has the same key, copied from the shipped one.
  Rename it there too, or delete the file to fall back to the defaults

## [0.11.3] - 2026-08-31

### Changed

- bump azwaf to 0.5.0, used as a library by the Azure WAF provider. That release fixes
  azwaf's own CLI — flags that were parsed and then dropped, including `--dry-run` on
  destructive commands — and removes the CLI input structs behind them. ipscout uses only
  its config and policy packages, so no lookup behaviour changes here

### Fixed

- the README claimed every provider requires registration. 59 of the 67 need no
  configuration at all, and only five ask for an API key, so the opening undersold what
  the tool does on a first run. Corrected, along with the provider count, a screenshot
  regenerated from 0.11.2 that had been unchanged since May 2024, and a duplicated badge
  block

## [0.11.2] - 2026-08-30

### Fixed

- the cache never freed disk. Expiring an entry removed the key but not the data behind
  it, which the underlying store only reclaims when it rewrites its value log files, and
  nothing did. Found on a cache holding 66 live entries totalling 84 MB across 16 GB of
  files, the oldest thirteen months old. Closing the cache now rewrites a little on every
  run, so a healthy cache stops growing
- `ipscout cache gc` reclaims the rest in one go for a cache that has already grown, and
  reports what it freed. On the cache above it went from 15.9 GB to 1.1 GB

## [0.11.1] - 2026-08-30

### Changed

- bump dependencies: badger to 4.9.6 (the cache engine), miekg/dns to 1.1.73, go-pretty to
  6.8.3 and go-openai to 1.42.0
- the AI rating request sends `max_completion_tokens` rather than the deprecated
  `max_tokens`. Same request for the model in use — gpt-4o-mini emits no reasoning tokens,
  so the 1024 ceiling means what it did — but the old parameter is not accepted by the
  o1-series models and go-openai 1.42.0 deprecates it

## [0.11.0] - 2026-08-30

### Added

- Better Stack, Checkly, New Relic, Pingdom and StatusCake providers, reporting whether
  the host is an uptime or synthetic monitoring probe rather than a visitor or the origin
  of the traffic it appears to send. New Relic names the location the probe runs from,
  and StatusCake reports the location's title, server code, country and current status
- Gcore provider, reporting whether the host is Gcore CDN edge infrastructure rather than
  the origin server behind it
- Zoom provider, reporting whether the host belongs to Zoom's meeting and phone service
  ranges
- the GitHub release notes are now the changelog entry for the tag rather than a
  generated list of commit subjects and SHAs, so the release page says what changed and
  why. `make release` fails if the entry is missing rather than publishing empty notes,
  and checks for it before the smoke build rather than after it
- documentation for how a release is cut: tag before running `make release`, since
  otherwise GitHub creates the tag from the release as a lightweight one, and the GitHub
  token the publish step needs

### Fixed

- an iCloud Private Relay match scored zero. The provider read a rating score the shipped
  config never defined, so a match was detected, given a reason, and then contributed
  nothing. Scored 4.0, alongside Zscaler: infrastructure that obscures the originating
  host rather than indicating abuse
- the TUI active marker is now shown on the Team Cymru Bogons and GreenSnow panels. The
  marker is added by replacing the upper-cased provider name in the header, which never
  matched either mixed-case title, so selecting one gave no indication of which provider
  was focused

### Changed

- bump ip-fetcher to v0.0.25 then v0.0.29, which supplies the seven new provider sources
  and finds the Azure snapshot by name instead of scraping for it
- cache TTLs for the new providers sized on measurement: Gcore at 1 hour, the only one
  whose content changed over a five minute resample; Better Stack at 4 hours, the
  max-age it advertises; New Relic at 7 days, unchanged for over eight months. Checkly,
  Pingdom, StatusCake and Zoom stay at a day, where the headers carry no cadence
- UptimeRobot is categorised as Monitoring in the README, alongside the five monitoring
  providers added here

### Removed

- the `build-latest-docker-tag` make target, which built `./docker/Dockerfile` — a path
  that has never existed in this repository, so the target could only ever fail

## [0.10.0] - 2026-08-29

### Added

- Team Cymru Bogons provider, reporting whether the host falls in address space that
  should never appear as a source on the public internet, either unallocated by IANA or
  allocated but unrouted. Cached for four hours to match the source's rebuild, since a
  stale bogon list reports newly allocated legitimate space as unroutable
- GreenSnow provider, reporting whether the host appears on its list of addresses seen
  attacking servers. Cached for an hour: the list changed by seventeen entries over two
  minutes during review
- `make smoke`, a pre-release check that builds the release archives without publishing
  and exercises the packaged binary from a temporary directory with a throwaway HOME.
  `make release` depends on it, so a failure aborts before anything is published. It
  covers the gap unit tests cannot: they run inside the repository, so they could not
  catch 0.9.0 shipping a binary whose test data was unreachable outside the source tree
- README documentation for `document_cache_ttl` and `result_cache_ttl`, which were read
  from config but documented nowhere, so the cache durations were not discoverable

### Changed

- bump ip-fetcher to v0.0.25, which supplies the two new provider sources
- size the IP range cache TTL per provider from how often each source actually
  publishes, replacing the blanket 24 hours. Sources that publish rarely move to 7 days
  (Akamai, Atlassian, CDN77, DuckDuckBot, OpenAI, PerplexityBot, UptimeRobot); each had
  gone a fortnight to two years without changing while being refetched daily, and
  DuckDuckGo serves its list with a one year cache header
- shorten the threat feed TTLs, which were the opposite problem: at 24 hours a blocklist
  lookup could be a day out of date. blocklist.de moves to 1 hour, the CINS Army list to
  2, DShield to 4 and Spamhaus DROP and Emerging Threats to 12, each measured against the
  cadence the source was observed to publish at

## [0.9.2] - 2026-08-27

### Changed

- bump ip-fetcher to v0.0.24, updating logrus to 1.10.1, testify to 1.12.1 and
  go.yaml.in/yaml/v3 to 3.0.5. ip-fetcher's provider code is unchanged since v0.0.22 —
  v0.0.23 altered only its release workflow and v0.0.24 is dependency updates — so no
  providers are added and no lookup behaviour changes

### Fixed

- the README's Homebrew instructions no longer fail for new users. Homebrew refuses to
  load casks from untrusted taps, so `brew tap` followed by `brew install ipscout` errors
  with "Refusing to load cask ... from untrusted tap". Installing by fully qualified name
  needs no trust step, and the tap-first route is documented with `brew trust --tap`

## [0.9.1] - 2026-08-24

### Added

- README documentation for `ipscout rate`: the scored output, how the average is compared
  against `blockScoreThreshold` to give a block or allow recommendation, where the rating
  configuration lives and how to write one, and AI rating

### Fixed

- the shipped config's `rating.use-ai` and `rating.openai-api-key` keys were never read.
  The reader looks up `use_ai` and `openai_api_key`, matching the underscore convention
  used by every other key, so enabling AI rating in `config.yaml` silently did nothing.
  The shipped config now uses the underscore names, and the hyphenated names are read as
  a fallback so existing config files start working rather than staying ignored. The
  corrected key takes precedence when set, so a stale hyphenated value cannot override an
  explicit one

## [0.9.0] - 2026-08-24

### Added

- Anthropic and UptimeRobot providers, covering the Anthropic crawler prefixes and the
  UptimeRobot monitoring probe ranges
- Blocklist.de, CINS Army List, DShield, Emerging Threats and Spamhaus DROP threat feed
  providers, reporting whether the host appears on each blocklist
- TUI panels for the twelve providers that had none: Atlassian, Bunny CDN, CDN77, Contabo,
  Datadog, Fly.io, IBM Cloud, Imperva, Leaseweb, Render, Stripe and Tencent Cloud

### Changed

- bump ip-fetcher to v0.0.22, which supplies the seven new provider sources, shares the
  crawler prefix parsing across the eight bot providers and the geolocation csv parsing
  between linode and icloudpr, and picks up its dependency updates
- provider fetch failures are reported as a single line below the results, naming every
  provider whose IP range data could not be fetched, instead of one error per provider
  printed over the progress spinner while downloads are still running. The per-provider
  detail moves to debug logging
- widen the existing nolint directives in ui/annotated.go, ui/ptr.go and ui/shodan.go to
  cover staticcheck SA4006, which a newer staticcheck now reports for the same assignments

### Fixed

- TUI providers whose configuration was never read. alibaba, scaleway and vultr appeared in
  the interface but always reported the provider as not configured, and the twelve newly
  added panels would have done the same. A guard test now keeps the CLI and TUI provider
  configuration in step
- `--use-test-data` now works for an installed binary. The providers read their test data
  from a path relative to the directory containing go.mod, so outside a source checkout
  every provider silently returned no result. The test data is now embedded in the binary
  and extracted to the user cache when the source tree is unavailable; running from a
  checkout is unchanged
- the `<home>` placeholder in the shipped config's `rating.config_path` is expanded to the
  user's home directory. It never was, so `ipscout rate` looked for a file literally named
  `<home>/.config/ratingConfig.json` and always failed
- a missing rating config file falls back to the built-in defaults, with a warning naming
  the path, rather than being fatal. The shipped config always sets a path but the file is
  never written, so rating was unusable until one was created by hand. A config that exists
  but cannot be read or parsed is still an error
- `ipscout rate` now prints the messages buffered during a run; previously it collected
  them and discarded them
- a fetch failure is reported even when it leaves nothing to display, rather than exiting
  quietly with only "no results found"

## [0.8.1] - 2026-08-09
### Changed
- azure waf diagnostics flow through the session logger via azwaf v0.4.0's isolated slog
  logger, replacing the logrus level workaround; genuine errors surface at error level
  in ipscout's log format and routine azwaf output is silent by default

## [0.8.0] - 2026-08-08
### Added
- AhrefsBot, Applebot, DuckDuckBot and PerplexityBot web crawler providers, fetched via
  ip-fetcher v0.0.20 from each bot's published prefix feed

## [0.7.0] - 2026-08-08
### Added
- Akamai, Cloudflare, Fastly, GitHub, Google User-triggered Fetchers and Oracle Cloud (OCI)
  providers, surfacing the remaining ip-fetcher sources
### Changed
- the TUI resolves providers from the registry, so every registered provider now works in the UI
### Fixed
- providers no longer cache an empty document for 24h when an upstream returns an error response
- akamai fetches Akamai's published CIDR zip (via ip-fetcher v0.0.19); the previous source URL did not exist

## [0.6.6] - 2026-08-02
### Fixed
- azure waf diagnostics from the azwaf library now respect the configured log level
  instead of always printing at info

## [0.6.5] - 2026-07-30
### Changed
- changelog updates

## [0.6.4] - 2026-07-28
### Changed
- backfill changelog with release notes for 0.3.0 through 0.6.3

## [0.6.3] - 2026-07-28
### Changed
- bump otel and klauspost/compress to clear govulncheck findings

## [0.6.2] - 2026-07-28
### Changed
- migrate goreleaser config off deprecated options; Homebrew now distributes ipscout as a cask
  (pre-0.6.2 formula installs need a one-time `brew uninstall ipscout && brew install ipscout`)

## [0.6.1] - 2026-07-28
### Fixed
- honour the log-level flag in the TUI instead of always logging at debug

## [0.6.0] - 2026-07-27
### Added
- IPtoASN provider reporting the announcing AS number, name, country and range
- providers requiring no configuration are enabled by default, and existing config files are
  upgraded on startup to include newly added providers (iCloud Private Relay now enabled by default)
### Fixed
- azure provider activity, cache operations and routine no-match results now log at debug rather than info
### Security
- bump x/crypto, x/net, x/text and the Go toolchain to clear all open CVE advisories

## [0.5.0] - 2026-07-11
### Added
- 12 ip-fetcher providers: Atlassian, Bunny CDN, CDN77, Contabo, Datadog, Fly.io, IBM Cloud,
  Imperva, Leaseweb, Render, Stripe and Tencent Cloud
- OpenAI bots provider (GPTBot, OAI-SearchBot, ChatGPT-User)
- host rating support for Alibaba, M247, Scaleway and Vultr
### Changed
- `ipscout config` is driven from the provider registry
- standardise logging on slog, dropping logrus

## [0.4.4] - 2026-06-07
### Changed
- dependency updates

## [0.4.3] - 2026-05-10
### Changed
- refactors and CI improvements; dependency updates

## [0.4.2] - 2026-05-05
### Fixed
- google bot fetching

## [0.4.1] - 2026-05-03
### Fixed
- align provider log levels and bridge logrus to slog

## [0.4.0] - 2026-04-12
### Added
- CSV output, provider registry and batch processing
- handle IPs presented with /32 or /128 suffixes
### Fixed
- race condition, operator precedence and oversized cache value errors; larger badger value log

## [0.3.11] - 2026-02-07
### Changed
- migrate to the modern Azure SDK; CLI performance improvements; dependency updates

## [0.3.10] - 2025-11-21
### Security
- dependency bump fixing a library vulnerability

## [0.3.9] - 2025-11-18
### Changed
- dependency updates; VirusTotal test coverage

## [0.3.8] - 2025-11-08
### Changed
- dependency updates

## [0.3.7] - 2025-10-11
### Added
- Vultr provider for cloud hosting service IP detection

## [0.3.6] - 2025-07-29
### Added
- Alibaba, Scaleway and M247 providers; OVH added to default config

## [0.3.5] - 2025-07-28
### Fixed
- Azure IP downloads via ip-fetcher dependency bump

## [0.3.4] - 2025-07-13
### Fixed
- handle a reverse IP lookup resolving to a CNAME

## [0.3.3] - 2025-06-26
### Fixed
- remove fatal exits; PTR output alignment; bottom navigation arrows in the TUI

## [0.3.2] - 2025-06-25
### Added
- resolution of host names
### Fixed
- TUI corruption bug; provider selection retained when returning to the list

## [0.3.1] - 2025-06-24
### Added
- loading message

## [0.3.0] - 2025-06-24
### Added
- interactive terminal UI (`ipscout ui`) with mouse support
### Fixed
- OVH provider; Azure fix via dependency bump

## [0.2.10] - 2025-06-10
### Changed
- tidy vendor dependencies

## [0.2.9] - 2025-06-08
### Added
- allow use of host name in addition to IP

## [0.2.8] - 2025-06-02
### Changed
- bump Go version

## [0.2.7] - 2025-01-21
### Fixed
- IPQS provider issue

## [0.2.6] - 2024-10-24
### Changed
- DigitalOcean fix and dependency updates

## [0.2.5] - 2024-10-07
### Added
- threat indicator rating with OpenAI

## [0.2.4] - 2024-09-24
### Fixed
- Azure WAF functionality

## [0.2.3] - 2024-08-15
### Fixed
- prevent panic in edge cases

## [0.2.2] - 2024-07-07
### Changed
- improved output and minor updates

## [0.2.1] - 2024-07-07
### Added
- IPQualityScore and Google Special Crawler providers

## [0.2.0] - 2024-06-30
### Added
- rating for additional providers

## [0.1.6] - 2024-06-15
### Fixed
- suppress unwanted Azure WAF output

## [0.1.5] - 2024-06-14
### Added
- Azure WAF support
### Changed
- dependency updates

## [0.1.4] - 2024-05-28
### Changed
- update Azure download URL

## [0.1.3] - 2024-05-27
### Changed
- performance improvements

## [0.1.2] - 2024-05-26
### Changed
- improve output

## [0.1.1] - 2024-05-26
### Added
- configuration and colour options

## [0.1.0] - 2024-05-26
### Added
- selectable styles and Bingbot provider

## [0.0.16] - 2024-05-24
### Added
- cache initialisation command

## [0.0.15] - 2024-05-21
### Changed
- output improvements

## [0.0.14] - 2024-05-18
### Added
- configuration menu

## [0.0.13] - 2024-05-18
### Added
- enable providers automatically when requirements met

## [0.0.12] - 2024-05-18
### Added
- VirusTotal provider

## [0.0.11] - 2024-05-15
### Changed
- update Azure source

## [0.0.10] - 2024-05-14
### Added
- Google provider

## [0.0.9] - 2024-05-13
### Fixed
- disabled providers were still used

## [0.0.8] - 2024-05-13
### Added
- improved output and tests

## [0.0.7] - 2024-05-11
### Fixed
- minor issues

## [0.0.6] - 2024-05-10
### Changed
- refactoring and output improvements

## [0.0.6-beta] - 2024-05-08
### Changed
- session and messaging improvements

## [0.0.6-alpha] - 2024-05-07
### Fixed
- build versioning and output

## [0.0.5-beta] - 2024-05-07
### Added
- Googlebot provider

## [0.0.5-alpha] - 2024-05-06
### Added
- README updates for x86 and ARM Macs

## [0.0.4-alpha] - 2024-05-06
### Added
- README updates for x86 and ARM Macs

## [0.0.3-alpha] - 2024-05-06
### Added
- initial additional providers and cleanup

## [0.0.1-alpha] - 2024-05-06
### Added
- initial release

[Unreleased]: https://github.com/jonhadfield/ipscout/compare/0.15.3...HEAD
[0.15.3]: https://github.com/jonhadfield/ipscout/compare/0.15.2...0.15.3
[0.15.2]: https://github.com/jonhadfield/ipscout/compare/0.15.1...0.15.2
[0.15.1]: https://github.com/jonhadfield/ipscout/compare/0.15.0...0.15.1
[0.15.0]: https://github.com/jonhadfield/ipscout/compare/0.14.1...0.15.0
[0.13.3]: https://github.com/jonhadfield/ipscout/releases/tag/0.13.3
[0.13.2]: https://github.com/jonhadfield/ipscout/releases/tag/0.13.2
[0.13.1]: https://github.com/jonhadfield/ipscout/releases/tag/0.13.1
[0.13.0]: https://github.com/jonhadfield/ipscout/releases/tag/0.13.0
[0.12.5]: https://github.com/jonhadfield/ipscout/releases/tag/0.12.5
[0.12.4]: https://github.com/jonhadfield/ipscout/releases/tag/0.12.4
[0.12.3]: https://github.com/jonhadfield/ipscout/releases/tag/0.12.3
[0.12.2]: https://github.com/jonhadfield/ipscout/releases/tag/0.12.2
[0.12.1]: https://github.com/jonhadfield/ipscout/releases/tag/0.12.1
[0.12.0]: https://github.com/jonhadfield/ipscout/releases/tag/0.12.0
[0.11.5]: https://github.com/jonhadfield/ipscout/releases/tag/0.11.5
[0.11.4]: https://github.com/jonhadfield/ipscout/releases/tag/0.11.4
[0.11.3]: https://github.com/jonhadfield/ipscout/releases/tag/0.11.3
[0.11.2]: https://github.com/jonhadfield/ipscout/releases/tag/0.11.2
[0.11.1]: https://github.com/jonhadfield/ipscout/releases/tag/0.11.1
[0.11.0]: https://github.com/jonhadfield/ipscout/releases/tag/0.11.0
[0.10.0]: https://github.com/jonhadfield/ipscout/releases/tag/0.10.0
[0.2.10]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.10
[0.2.9]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.9
[0.2.8]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.8
[0.2.7]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.7
[0.2.6]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.6
[0.2.5]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.5
[0.2.4]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.4
[0.2.3]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.3
[0.2.2]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.2
[0.2.1]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.1
[0.2.0]: https://github.com/jonhadfield/ipscout/releases/tag/0.2.0
[0.1.6]: https://github.com/jonhadfield/ipscout/releases/tag/0.1.6
[0.1.5]: https://github.com/jonhadfield/ipscout/releases/tag/0.1.5
[0.1.4]: https://github.com/jonhadfield/ipscout/releases/tag/0.1.4
[0.1.3]: https://github.com/jonhadfield/ipscout/releases/tag/0.1.3
[0.1.2]: https://github.com/jonhadfield/ipscout/releases/tag/0.1.2
[0.1.1]: https://github.com/jonhadfield/ipscout/releases/tag/0.1.1
[0.1.0]: https://github.com/jonhadfield/ipscout/releases/tag/0.1.0
[0.0.16]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.16
[0.0.15]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.15
[0.0.14]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.14
[0.0.13]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.13
[0.0.12]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.12
[0.0.11]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.11
[0.0.10]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.10
[0.0.9]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.9
[0.0.8]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.8
[0.0.7]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.7
[0.0.6]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.6
[0.0.6-beta]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.6-beta
[0.0.6-alpha]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.6-alpha
[0.0.5-beta]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.5-beta
[0.0.5-alpha]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.5-alpha
[0.0.4-alpha]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.4-alpha
[0.0.3-alpha]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.3-alpha
[0.0.1-alpha]: https://github.com/jonhadfield/ipscout/releases/tag/0.0.1-alpha
