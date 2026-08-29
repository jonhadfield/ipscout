# IPScout

IPScout is a command-line tool for security analysts to enrich IP addresses with their origin and threat ratings.
All of the host reputation providers require registration but each of them offers a free tier.

<img src="docs/logo.png" alt="logo" width="200"/>

---

[![GoDoc](https://godoc.org/github.com/jonhadfield/ipscout?status.svg)](https://godoc.org/github.com/jonhadfield/ipscout)
[![Tests on Linux, MacOS and Windows](https://github.com/jonhadfield/ipscout/workflows/Test/badge.svg)](https://github.com/jonhadfield/ipscout/actions?query=workflow%3ATest)
[![Go Report Card](https://goreportcard.com/badge/github.com/jonhadfield/ipscout)](https://goreportcard.com/report/github.com/jonhadfield/ipscout)

## Table of Contents

- [Features](#features)
- [Output](#output)
- [Providers](#providers)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Rating](#rating)
- [Provider Details](#providers-1)
- [Changelog](#changelog)
- [License](#license)

## Features

- Query multiple reputation and hosting providers concurrently
- Cache provider metadata and lookup results
- Manage cached data with `ipscout cache`
- Show or output configuration with `ipscout config`
- Rate hosts using `ipscout rate`, optionally with AI assistance
- Supports Zscaler IP range lookups

[![GoDoc](https://godoc.org/github.com/jonhadfield/ipscout?status.svg)](https://godoc.org/github.com/jonhadfield/ipscout) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/df6b2974f0844444af617a1c0b0e2cfb)](https://app.codacy.com/gh/jonhadfield/ipscout/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade) [![Go Report Card](https://goreportcard.com/badge/github.com/jonhadfield/ipscout)](https://goreportcard.com/report/github.com/jonhadfield/ipscout)

## Output
### format
Results are displayed in a table by default but can also be outputted as JSON format using the `--output` flag.
- [table](examples/table.png)
- [json](examples/results.json)
### style
Table styles include ascii (for basic terminals), cyan, red, yellow, green, blue, and can be specified in the `config.yaml` file or with the `--style` flag.
Examples:
- [red](examples/table.png)
- [ascii](examples/ascii.txt)

## Providers

IPScout supports multiple well known sources. You can also provide custom sources
with the [Annotated](#Annotated) and [IPURL](#IPURL) providers.

Provider data and search results can be cached to reduce API calls and improve performance.

| Provider                                                  |     Category     |         Notes         |
|:----------------------------------------------------------|:----------------:|:---------------------:|
| [AbuseIPDB](#AbuseIPDB)                                   |  IP Reputation   | Registration required |
| [AhrefsBot](#AhrefsBot)                                   |   Web crawler    |           -           |
| [Akamai](#Akamai)                                         |       CDN        |           -           |
| [Alibaba Cloud](#Alibaba-Cloud)                           | Hosting Provider |           -           |
| [Annotated](#Annotated)                                   |  User Provided   |           -           |
| [Anthropic](#Anthropic)                                   |   Web crawler    |           -           |
| [Apple iCloud Private Relay](#Apple-iCloud-Private-Relay) |    Anonymiser    |           -           |
| [Applebot](#Applebot)                                     |   Web crawler    |           -           |
| [Atlassian](#Atlassian)                                   |       SaaS       |           -           |
| [AWS](#Amazon-Web-Services)                               | Hosting Provider |           -           |
| [Azure](#Azure)                                           | Hosting Provider |           -           |
| [Azure WAF](#Azure-WAF)                                   |       WAF        | Azure access required |
| [Bingbot](#Bingbot)                                       |   Web crawler    |           -           |
| [Blocklist.de](#Blocklistde)                              |   Threat Feed    |           -           |
| [Bunny CDN](#Bunny-CDN)                                   |       CDN        |           -           |
| [CDN77](#CDN77)                                           |       CDN        |           -           |
| [CINS Army List](#CINS-Army-List)                         |   Threat Feed    |           -           |
| [Cloudflare](#Cloudflare)                                 |       CDN        |           -           |
| [Contabo](#Contabo)                                       | Hosting Provider |           -           |
| [CriminalIP](#CriminalIP)                                 |  IP Reputation   | Registration required |
| [Datadog](#Datadog)                                       |       SaaS       |           -           |
| [DigitalOcean](#DigitalOcean)                             | Hosting Provider |           -           |
| [DShield](#DShield)                                       |   Threat Feed    |           -           |
| [DuckDuckBot](#DuckDuckBot)                               |   Web crawler    |           -           |
| [Emerging Threats](#Emerging-Threats)                     |   Threat Feed    |           -           |
| [Fastly](#Fastly)                                         |       CDN        |           -           |
| [Fly.io](#Flyio)                                          | Hosting Provider |           -           |
| [GCP](#Google-Cloud-Platform)                             | Hosting Provider |           -           |
| [GitHub](#GitHub)                                         |       SaaS       |           -           |
| [Google](#Google)                                         | Hosting Provider |           -           |
| [Google Special-case crawlers](#Google-Special-Crawlers)  |   Web crawler    |           -           |
| [Google User-triggered Fetchers](#Google-User-triggered-Fetchers) | Web crawler |         -           |
| [Googlebot](#Googlebot)                                   |   Web crawler    |           -           |
| [GreenSnow](#GreenSnow)                                   |   Threat Feed    |           -           |
| [Hetzner](#Hetzner)                                       | Hosting Provider |           -           |
| [IBM Cloud](#IBM-Cloud)                                   | Hosting Provider |           -           |
| [Imperva](#Imperva)                                       |       WAF        |           -           |
| [IPAPI](#IPAPI)                                           |  IP Geolocation  |           -           |
| [IPQualityScore](#IPQualityScore)                         |  IP Reputation   | Registration required |
| [IPtoASN](#IPtoASN)                                       |     ASN Data     |           -           |
| [IPURL](#IPURL)                                           |  User Provided   |           -           |
| [Leaseweb](#Leaseweb)                                     | Hosting Provider |           -           |
| [Linode](#Linode)                                         | Hosting Provider |           -           |
| [M247](#M247)                                             | Hosting Provider |           -           |
| [OpenAI](#OpenAI)                                         |   Web crawler    |           -           |
| [Oracle Cloud (OCI)](#Oracle-Cloud-OCI)                   | Hosting Provider |           -           |
| [OVH](#OVH)                                               | Hosting Provider |           -           |
| [PerplexityBot](#PerplexityBot)                           |   Web crawler    |           -           |
| [PTR](#PTR)                                               |       DNS        |           -           |
| [Render](#Render)                                         | Hosting Provider |           -           |
| [Scaleway](#Scaleway)                                     | Hosting Provider |           -           |
| [Vultr](#Vultr)                                           | Hosting Provider |           -           |
| [Shodan](#Shodan)                                         |  IP Reputation   | Registration required |
| [Spamhaus DROP](#Spamhaus-DROP)                           |   Threat Feed    |           -           |
| [Stripe](#Stripe)                                         |       SaaS       |           -           |
| [Team Cymru Bogons](#Team-Cymru-Bogons)                   |      Bogon       |           -           |
| [Tencent Cloud](#Tencent-Cloud)                           | Hosting Provider |           -           |
| [UptimeRobot](#UptimeRobot)                               |       SaaS       |           -           |
| [VirusTotal](#VirusTotal)                                 |  IP Reputation   | Registration required |
| [Zscaler](#Zscaler)                                       |    Security      |           -           |

## Installation

Binaries for macOS, Linux and Windows are available on the [releases](https://github.com/jonhadfield/ipscout/releases)
page.

### macOS - Homebrew

```
$ brew install --cask jonhadfield/ipscout/ipscout
```

Naming the cask in full is deliberate. Homebrew now refuses to load formulae and casks
from taps you have not trusted, so tapping first and installing by short name fails:

```
$ brew tap jonhadfield/ipscout
$ brew install ipscout
Error: Refusing to load cask jonhadfield/ipscout/ipscout from untrusted tap jonhadfield/ipscout.
```

Asking for the cask by its fully qualified name is treated as trusting that one cask, so
the single command above works with no extra step. If you prefer to tap first, trust the
tap once:

```
$ brew tap jonhadfield/ipscout
$ brew trust --tap jonhadfield/ipscout
$ brew install ipscout
```

Upgrades work normally either way, with `brew upgrade --cask ipscout`.

Since 0.6.2, ipscout is distributed as a Homebrew cask. If you installed an earlier
version (distributed as a formula), reinstall once to migrate:

```
$ brew uninstall ipscout
$ brew install --cask jonhadfield/ipscout/ipscout
```

### Linux
Install latest release.
```shell
curl -sL https://raw.githubusercontent.com/jonhadfield/ipscout/add_install_script/install | sh
```

### other distributions

Download the latest release from the [releases](https://github.com/jonhadfield/ipscout/releases) page.

### Build from source

Go 1.24 or later is required to compile ipscout. Clone the repository and run:

```shell
go build ./...
```

This will create an `ipscout` binary in the current directory.

### Releasing

Tag first, then release:

```shell
git tag -a 0.10.0 -m "new providers, cache ttl tuning and release checks."
git push origin 0.10.0
make release
```

Tags are annotated and unprefixed (`0.10.0`, not `v0.10.0`), with a short lowercase
message summarising the release.

Push the tag before running `make release`, not after. `goreleaser` publishes the release
for the tag at `HEAD`, and if that tag is not already on the remote GitHub creates it from
the release itself — as a lightweight tag, so the annotated object and its message stay on
your machine and the remote records only the commit. The `git push --follow-tags` at the
end of the target then has nothing left to send and reports `Everything up-to-date`, which
reads like success. Pushing first is what makes the annotated tag the one that lands.

`make release` builds and publishes the release. It depends on `make smoke`, which builds
the release archives without publishing and then runs the packaged binary from a temporary
directory with a throwaway `HOME`, so there is no `go.mod` above it and no existing config
or cache. That catches problems the unit tests cannot see, because they run inside the
repository. A failing smoke check aborts the release before anything is published.

`make smoke` can be run on its own at any time; it needs no network access.

Publishing needs a GitHub token with `repo` scope, for both the release and the push to
the `homebrew-ipscout` cask repository. `goreleaser` resolves its SCM token from the
environment, so if you keep a `GITLAB_TOKEN` set for other work, clear it for the run so
the GitHub one is used:

```shell
env -u GITLAB_TOKEN GITHUB_TOKEN="$(gh auth token)" make release
```

`gh auth token` reuses the `gh` CLI login rather than needing a separate PAT. Set
`GITHUB_TOKEN` yourself if you would rather not depend on `gh`.

### Updating the ip-fetcher dependency

Most providers source their IP-range data via [`ip-fetcher`](https://github.com/jonhadfield/ip-fetcher). It is pinned in `go.mod` to a `v`-prefixed release tag — that released module, not a local checkout, is the source of truth for upstream data formats. To pick up changes:

1. Cut a new `v`-prefixed release tag in the ip-fetcher repo (e.g. `v0.0.17`).
2. In this repo: `go get github.com/jonhadfield/ip-fetcher@vX.Y.Z && go mod tidy`.

The commented `replace` directive in `go.mod` is for local development only and must never be committed enabled.

## Usage

```shell
$ ipscout <host>
```
`<host>` can be an IP address or a fully qualified domain name.

Additional commands are available:

```shell
$ ipscout cache    # manage cached results
$ ipscout config   # view or output configuration
$ ipscout rate     # rate a host using provider data
```

## Configuration

A default configuration is created
on first run and located at: `$HOME/.config/ipscout/config.yaml`.

Some configuration can be overridden on the command line, see `ipscout --help`.

```yaml
---
global:
  indent_spaces: 2      # number of spaces to indent output
  max_value_chars: 300  # limit the number of characters output in results
  max_age: 90d          # maximum age of reports to consider
  max_reports: 5        # maximum number of reports to display
  ports: ["443/tcp"]    # filter results by port [tcp,udp,443/tcp,...]
  output: table         # output format: table or json
  style: cyan           # output style [ascii, cyan, green, yellow, red, blue]

providers:
# list of providers with their configurations below...
```

## Rating

`ipscout rate` combines the results from every provider that supports rating into a single
score and a block or allow recommendation.

```shell
$ ipscout rate 1.10.16.1
```

```
+------------+----------+-------+-----------------------------------------------------------+
| PROVIDER   | DETECTED | SCORE | REASONS                                                   |
+------------+----------+-------+-----------------------------------------------------------+
| spamhaus   | true     | 10.00 | listed on Spamhaus DROP (do not route or peer): SBL256894 |
| abuseipdb  | true     | 3.00  | confidence: 0.00                                          |
| ipqs       | true     | 9.00  | confidence: 0.00                                          |
| virustotal | true     | 0.00  | harmless                                                  |
+------------+----------+-------+-----------------------------------------------------------+
| AVERAGE    |          | 5.50  |                                                           |
+------------+----------+-------+-----------------------------------------------------------+
Recommendation: block
```

Each provider that matches the host contributes a score. The scores are averaged, and the
result is compared against `blockScoreThreshold`: below it the recommendation is `allow`,
otherwise `block`. A provider reporting a `noblock` threat indicator, such as an entry
annotated that way in your own data, forces `allow` regardless of the score.

### Rating configuration

No setup is required. If no rating configuration file exists, the built-in defaults are
used and the path checked is reported so you know where to put one.

To write your own, start from the defaults:

```shell
$ ipscout rate config --default > $HOME/.config/ratingConfig.json
```

The location is set by `rating.config_path` in `config.yaml`, and `<home>` in that value is
expanded to your home directory:

```yaml
rating:
  config_path: <home>/.config/ratingConfig.json
  use_ai: false
  openai_api_key: <your-openai-api-key>
```

`ipscout rate config` prints your rating configuration file, and `--path` prints one from a
specific location. Both validate what they read, so they are a way to check a file parses.
Unlike rating itself, they require the file to exist rather than falling back to the
defaults.

The configuration has a global section and a per-provider section, abbreviated here (the
shipped defaults list 26 high threat country codes and carry an entry for 50 providers):

```json
{
  "global": {
    "blockScoreThreshold": 5.0,
    "highThreatCountryCodes": ["CN", "RU", "IR"],
    "mediumThreatCountryCodes": ["NL", "CA"]
  },
  "providers": {
    "spamhaus": { "defaultMatchScore": 10.0 },
    "aws": { "defaultMatchScore": 7.0 },
    "shodan": {
      "openPortsScore": 5.0,
      "highThreatCountryMatchScore": 10.0,
      "mediumThreatCountryMatchScore": 7.0
    }
  }
}
```

Most providers take a single `defaultMatchScore`, applied when the host matches their data.
Threat feeds default to 10.0 and hosting providers to 7.0-8.0, so appearing on a blocklist
weighs more than merely being hosted somewhere. CriminalIP, Shodan and VirusTotal take
finer-grained scores for the specific conditions they report.

### AI rating

With `--ai`, the threat indicators each provider reports are shown and then sent to OpenAI,
which returns a written assessment in place of the scored table:

```shell
$ ipscout rate --ai 1.10.16.1
```

This requires an OpenAI API key, set with `--openai-api-key` or `rating.openai_api_key` in
`config.yaml`.

## Providers

Providers are configured in the `config.yaml` file.
A number of providers are enabled by default, but can be disabled by setting `enabled: false`.

Providers that fetch a list of IP ranges cache it, and refetch once the cache expires. The
defaults are chosen per provider from how often the source actually publishes, so a list
that changes a few times a year is not refetched daily. Override it per provider with
`document_cache_ttl`, in minutes:

```yaml
providers:
  aws:
    enabled: true
    document_cache_ttl: 360   # refetch AWS ranges every 6 hours instead of daily
```

Providers that query a per-host API cache the result instead, set with `result_cache_ttl`,
also in minutes.

### AbuseIPDB

This provider queries the [AbuseIPDB](https://www.abuseipdb.com/) API for information on an IP address, with a threat
confidence score, and any reports filed for them.
A [free plan](https://www.abuseipdb.com/pricing) exists for individuals, with a limit of 1000 requests per day.

Environment variable `ABUSEIPDB_API_KEY` must be set with your API key.

```yaml
providers:
  abuseipdb:
    enabled: false
```

### Alibaba Cloud

[Alibaba Cloud](https://www.alibabacloud.com/) is a hosting provider.
IP ranges are retrieved from the BGPView API and checked for matches against the target host.

### Annotated

The Annotated provider parses one or more user provided files containing prefixes and accomanying annotations.

```yaml
---
- prefixes: [ "20.20.20.0/24", "20.20.21.0/24" ]
  annotations:
    - date: 2024/04/19 18:58
      author: john doe <john.doe@example.com>
      notes:
        - My First Annotation
        - My Second Annotation
- prefixes: [ "9.9.9.9/32" ]
  annotations:
    - date: 2024/04/19 19:00
      author: jane doe <jane.does@example.com>
      notes:
        - Another Annotation
```

A list of files can be specified in the provider's `paths` section:

```yaml
providers:
  annotated:
    enabled: true
    paths:
      - /path/to/file.yaml
```

### Apple iCloud Private Relay

IP anonymisation service from [Apple](https://support.apple.com/en-us/102602).
> iCloud Private Relay — part of an iCloud+ subscription — helps protect your privacy when you browse the web in Safari.

### Amazon Web Services

[AWS](https://aws.amazon.com/) is a Hosting Provider
that [publishes](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html#aws-ip-download) network prefixes
used by their services.

### Azure

[Azure](https://azure.microsoft.com/) is a hosting provider
that [publishes](https://www.microsoft.com/en-gb/download/details.aspx?id=56519) network prefixes used by their
services.

### Azure WAF

[Azure WAF](https://azure.microsoft.com/en-gb/products/web-application-firewall/) is a Web Application Firewall used to secure services hosted on Azure.
This currently supports Azure Global WAF, used to secure Azure Front Door, and will show custom rules and prefixes matching the provided host.
Authentication will be read from the environment.

### Bingbot

[Bingbot](https://www.bing.com/webmasters/help/help-center-661b2d18) is the web crawler for the Bing search engine.
Bing [publishes](https://www.bing.com/toolbox/bingbot.json) network prefixes used by their crawlers.

### CriminalIP

Query the [CriminalIP](https://www.criminalip.io/) API for information on an IP address/endpoint, with risk ratings, and
any abuse reports filed for them.
A [free plan](https://www.criminalip.io/pricing) exists with a small number of free credits.

Set environment variable `CRIMINAL_IP_API_URL` with your API key.

### DigitalOcean

[DigitalOcean](https://www.digitalocean.com/) is a hosting provider
that [publishes](https://www.digitalocean.com/geo/google.csv) network prefixes used by their services.

### Google Cloud Platform

[GCP](https://cloud.google.com/) is a hosting provider
that [publishes](https://cloud.google.com/compute/docs/faq#find_ip_range) network prefixes used by their
services.

### Google

[Google](https://support.google.com/a/answer/10026322?hl=en-GB) provides a list of IP addresses used by customers of their services
 and publishes them [here](https://www.gstatic.com/ipranges/goog.json).

### Google Special Crawlers

[Google](https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers#special-case-crawlers) provides a list
 of IP addresses used by their non-Googlebot crawlers [here](https://developers.google.com/static/search/apis/ipranges/special-crawlers.json).

### Googlebot

[Googlebot](https://developers.google.com/search/docs/crawling-indexing/googlebot) is a web crawler
and [publishes](https://developers.google.com/static/search/apis/ipranges/googlebot.json) network prefixes used by their
bots.

### GreenSnow

[GreenSnow](https://greensnow.co/) collects addresses seen attacking servers, such as
brute force attempts against SSH, mail and web services, and publishes them at
[blocklist.greensnow.co/greensnow.txt](https://blocklist.greensnow.co/greensnow.txt).
IPScout downloads this list and checks whether the target IP appears in it. The list
changes constantly, so it is cached for an hour rather than the usual day.

### Hetzner

[Hetzner](https://www.hetzner.com/) is a hosting provider.
IP ranges are retrieved from the BGPView API and checked for matches against the target host.

### iCloud Private Relay

[iCloud Private Relay](https://support.apple.com/en-us/102602) is an anonymising service provided by Apple. They publish
their network prefixes [here](https://mask-api.icloud.com/egress-ip-ranges.csv).

### IPAPI

Query the [ipapi](https://ipapi.co/) API for geolocation data.
The API is free for up 30,000 requests per day.

### IPQualityScore

Query the [IPQualityScore](https://www.ipqualityscore.com/documentation/proxy-detection-api/overview) API for host reputation data.
The API is free to registered users for 5,000 requests.

Set environment variable `IPQS_API_KEY` with your API key.

### IPtoASN

[iptoasn.com](https://iptoasn.com/) publishes a free, hourly-updated IP address to ASN mapping.
The combined IPv4+IPv6 dataset is downloaded and cached, and the target host is matched against it to report the
announcing AS number, name, country and address range.

### IPURL

IPURL retrieves lists of IP prefixes from user provided URLs and checks the target IP address against them.
Documents are expected to contain a list of prefixes in CIDR format, one per line.

Example configuration:

```yaml
  ipurl:
    enabled: true
    urls:
      - "https://iplists.firehol.org/files/firehol_level1.netset"
      - "https://iplists.firehol.org/files/firehol_level2.netset"
      - "https://iplists.firehol.org/files/blocklist_de.ipset"
```

A match for target IP 3.68.116.6 in two of the above may return:

```
Prefixes
  3.68.116.0/28
   |----- https://iplists.firehol.org/files/firehol_level2.netset
   |----- https://iplists.firehol.org/files/blocklist_de.ipset
```

### Linode

[Linode](https://www.linode.com/) is a hosting provider
that [publishes](https://geoip.linode.com/) network prefixes used by their services.

### M247

[M247](https://www.m247.com/) is a global hosting and connectivity provider.
IP ranges are retrieved from the BGPView API and checked for matches against the target host.

### OpenAI

[OpenAI](https://platform.openai.com/docs/bots) operates a number of bots and publishes the network prefixes they crawl
and browse from: [GPTBot](https://openai.com/gptbot.json), [OAI-SearchBot](https://openai.com/searchbot.json)
and [ChatGPT-User](https://openai.com/chatgpt-user.json). A match shows which of the bots' lists contain the target host.

### OVH

[OVH](https://www.ovhcloud.com/) is a hosting provider
that [publishes](https://vps.ovh.net/ips.txt) network prefixes used by their services.

### Scaleway

[Scaleway](https://www.scaleway.com/) is a European hosting provider.
IP ranges are retrieved from the BGPView API and checked for matches against the target host.

### Vultr

[Vultr](https://www.vultr.com/) is a cloud hosting provider.
IP ranges are retrieved from the BGPView API and checked for matches against the target host.

### PTR

The PTR provider does a reverse lookup for the target IP.
See:

- https://en.wikipedia.org/wiki/Reverse_DNS_lookup
- https://www.cloudflare.com/en-gb/learning/dns/dns-records/dns-ptr-record/

Custom nameservers can be specified in the `config.yaml` file with port defaulting to 53 if not specified.

```yaml
  ptr:
    enabled: true
    nameservers:
      - 1.1.1.1:53
      - 8.8.8.8
      - 8.8.4.4:53
```

### Shodan

Query the [Shodan](https://www.shodan.io/) API for information on an IP address, with open ports, and services.

Set environment variable `SHODAN_API_KEY` with your API key.

### VirusTotal

Query the [VirusTotal](https://www.virustotal.com) API for information from various providers on an IP address.

Set environment variable `VIRUSTOTAL_API_KEY` with your API key.

### Zscaler

[Zscaler](https://www.zscaler.com/) publishes a list of IP prefixes used by its services.
IPScout downloads this list and checks whether the target IP is within those ranges.
The default source URL is `https://api.config.zscaler.com/zscaler.net/cenr/json` and
can be overridden in the configuration file.

```yaml
  zscaler:
    enabled: true
    url: https://api.config.zscaler.com/zscaler.net/cenr/json
    document_cache_ttl: 1440  # minutes
```

### AhrefsBot

[AhrefsBot](https://ahrefs.com/robot) is the web crawler for the Ahrefs SEO
platform. Ahrefs publishes the IP ranges used by its crawler at
[api.ahrefs.com/v3/public/crawler-ip-ranges](https://api.ahrefs.com/v3/public/crawler-ip-ranges).
IPScout downloads this list and checks whether the target IP is within those ranges.

### Akamai

[Akamai](https://www.akamai.com/) is a content delivery network that publishes
the IP ranges used by its edge platform at
[ip-ranges.akamai.com](https://ip-ranges.akamai.com/). IPScout downloads this
list and checks whether the target IP is within those ranges.

### Applebot

[Applebot](https://support.apple.com/en-us/119829) is Apple's web crawler, used
by products such as Siri and Spotlight. Apple publishes the IP ranges used by
the crawler at
[search.developer.apple.com/applebot.json](https://search.developer.apple.com/applebot.json).
IPScout downloads this list and checks whether the target IP is within those ranges.

### Atlassian

[Atlassian](https://www.atlassian.com/) publishes the IP ranges used by its
cloud products (Jira, Confluence, Bitbucket and others). IPScout downloads this
list and checks whether the target IP is within those ranges.

### Bunny CDN

[Bunny CDN](https://bunny.net/) is a content delivery network that publishes the
IP ranges used by its edge servers. IPScout downloads this list and checks
whether the target IP is within those ranges.

### CDN77

[CDN77](https://www.cdn77.com/) is a content delivery network that publishes the
prefixes used by its edge network. IPScout downloads this list and checks
whether the target IP is within those ranges.

### Cloudflare

[Cloudflare](https://www.cloudflare.com/) is a content delivery network that
publishes the IP ranges used by its edge network at
[cloudflare.com/ips-v4](https://www.cloudflare.com/ips-v4) and
[cloudflare.com/ips-v6](https://www.cloudflare.com/ips-v6). IPScout downloads
these lists and checks whether the target IP is within those ranges.

### Contabo

[Contabo](https://contabo.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat / BGPView APIs and checked for matches
against the target host.

### Datadog

[Datadog](https://www.datadoghq.com/) is an observability platform that
publishes the IP ranges used by its services. IPScout downloads this list and
checks whether the target IP is within those ranges.

### DuckDuckBot

[DuckDuckBot](https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot/)
is the web crawler for the DuckDuckGo search engine. DuckDuckGo publishes the IP
addresses used by the crawler at
[duckduckgo.com/duckduckbot.json](https://duckduckgo.com/duckduckbot.json).
IPScout downloads this list and checks whether the target IP is within those ranges.

### Fastly

[Fastly](https://www.fastly.com/) is a content delivery network that publishes
the IP ranges used by its edge network via its
[public IP list API](https://api.fastly.com/public-ip-list). IPScout downloads
this list and checks whether the target IP is within those ranges.

### Fly.io

[Fly.io](https://fly.io/) is an application hosting provider.
IP ranges are retrieved from the RIPE stat / BGPView APIs and checked for matches
against the target host.

### GitHub

[GitHub](https://github.com/) publishes the IP ranges used by its services
(web, API, Actions, Pages and others) via its
[meta API](https://api.github.com/meta). IPScout downloads this list and
reports the services associated with any matching range.

### Google User-triggered Fetchers

Google publishes the IP ranges used by its
[user-triggered fetchers](https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json),
tools that fetch pages on behalf of a user request. IPScout downloads this list
and checks whether the target IP is within those ranges.

### IBM Cloud

[IBM Cloud](https://www.ibm.com/cloud) is a hosting provider.
IP ranges are retrieved from the RIPE stat / BGPView APIs and checked for matches
against the target host.

### Imperva

[Imperva](https://www.imperva.com/) (Incapsula) is a web application firewall and
CDN that publishes the IP ranges used by its network. IPScout downloads this list
and checks whether the target IP is within those ranges.

### Leaseweb

[Leaseweb](https://www.leaseweb.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat / BGPView APIs and checked for matches
against the target host.

### Oracle Cloud (OCI)

[Oracle Cloud Infrastructure](https://www.oracle.com/cloud/) publishes the
[IP ranges](https://docs.oracle.com/iaas/tools/public_ip_ranges.json) used by
its services. IPScout downloads this list and reports the region and service
tags associated with any matching range.

### PerplexityBot

[PerplexityBot](https://docs.perplexity.ai/guides/bots) is the web crawler for
the Perplexity answer engine. Perplexity publishes the IP ranges used by the
crawler at
[perplexity.com/perplexitybot.json](https://www.perplexity.com/perplexitybot.json).
IPScout downloads this list and checks whether the target IP is within those ranges.

### Render

[Render](https://render.com/) is an application hosting provider.
IP ranges are retrieved from the RIPE stat / BGPView APIs and checked for matches
against the target host.

### Stripe

[Stripe](https://stripe.com/) publishes the IP ranges used by its API and webhook
infrastructure. IPScout downloads this list and checks whether the target IP is
within those ranges.

### Team Cymru Bogons

The [Team Cymru](https://www.team-cymru.com/bogon-reference) full bogon list covers
address space that should never appear as a source on the public internet: ranges IANA
has not allocated, plus those allocated but not yet routed. Traffic claiming to come from
one is typically spoofed or the result of a misconfiguration.

It is published as
[fullbogons-ipv4.txt](https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt) and
[fullbogons-ipv6.txt](https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt), and
rebuilt every four hours. IPScout caches it for four hours to match: bogon space shrinks
as addresses are allocated, so a stale list reports newly assigned, legitimate ranges as
unroutable. The generation time from the list header is shown with any match.

### Tencent Cloud

[Tencent Cloud](https://www.tencentcloud.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat / BGPView APIs and checked for matches
against the target host.

### Anthropic

[Anthropic](https://www.anthropic.com/) publishes the IP ranges used by its
crawlers, including ClaudeBot and the Claude user-triggered fetchers, at
[claude.com/crawling/bots.json](https://claude.com/crawling/bots.json).
IPScout downloads this list and checks whether the target IP is within those ranges.

### Blocklist.de

[Blocklist.de](https://www.blocklist.de/en/index.html) is a community-run service
that collects reports of hosts attacking other systems via SSH, mail, web and
other services. The aggregated list of reported addresses is published at
[lists.blocklist.de/lists/all.txt](https://lists.blocklist.de/lists/all.txt).
IPScout downloads this list and checks whether the target IP appears in it.

### CINS Army List

The [CINS Army List](https://cinsscore.com/) is the freely available subset of
the Collective Intelligence Network Security score, listing addresses with a poor
reputation that are not yet widely blocked. It is published at
[cinsscore.com/list/ci-badguys.txt](https://cinsscore.com/list/ci-badguys.txt).
IPScout downloads this list and checks whether the target IP appears in it.

### DShield

[DShield](https://www.dshield.org/) is the SANS Internet Storm Center's
distributed intrusion detection system. Its recommended block list, covering the
networks responsible for the most reported attacks, is published at
[feeds.dshield.org/block.txt](https://feeds.dshield.org/block.txt).
IPScout downloads this list and checks whether the target IP is within those
networks, reporting the attack count and network owner where available.

### Emerging Threats

[Emerging Threats](https://rules.emergingthreats.net/blockrules/) publishes open
rulesets and reputation data for intrusion detection systems. Its list of known
compromised hosts is published at
[rules.emergingthreats.net/blockrules/compromised-ips.txt](https://rules.emergingthreats.net/blockrules/compromised-ips.txt).
IPScout downloads this list and checks whether the target IP appears in it.

### Spamhaus DROP

[Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
(Don't Route Or Peer) lists netblocks that Spamhaus considers wholly controlled
by criminal operations. The lists are published at
[spamhaus.org/drop/drop_v4.json](https://www.spamhaus.org/drop/drop_v4.json) and
[spamhaus.org/drop/drop_v6.json](https://www.spamhaus.org/drop/drop_v6.json).
IPScout downloads both lists and checks whether the target IP is within those
netblocks, reporting the associated SBL identifier and RIR.

### UptimeRobot

[UptimeRobot](https://uptimerobot.com/help/locations/) is a website and service
monitoring platform. The IP ranges used by its monitoring probes are published at
[uptimerobot.com/inc/files/ips/IPv4andIPv6.txt](https://uptimerobot.com/inc/files/ips/IPv4andIPv6.txt).
IPScout downloads this list and checks whether the target IP is within those ranges.

## Changelog

See [CHANGELOG.md](docs/CHANGELOG.md) for release notes.

## License

IPScout is licensed under the [Apache 2.0 License](LICENSE).
