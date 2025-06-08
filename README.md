# Overview

IPScout is a command-line tool for security analysts to enrich IP addresses with their origin and threat ratings.
All of the host reputation providers require registration but each of them offers a free tier.

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
| [Annotated](#Annotated)                                   |  User Provided   |           -           |
| [Apple iCloud Private Relay](#Apple-iCloud-Private-Relay) |    Anonymiser    |           -           |
| [AWS](#Amazon-Web-Services)                               | Hosting Provider |           -           |
| [Azure](#Azure)                                           | Hosting Provider |           -           |
| [Azure WAF](#Azure-WAF)                                   |       WAF        | Azure access required |
| [Bingbot](#Bingbot)                                       |   Web crawler    |           -           |
| [CriminalIP](#CriminalIP)                                 |  IP Reputation   | Registration required |
| [DigitalOcean](#DigitalOcean)                             | Hosting Provider |           -           |
| [GCP](#Google-Cloud-Platform)                             | Hosting Provider |           -           |
| [Google Special-case crawlers](#Google-Special-Crawlers)  |   Web crawler    |           -           |
| [Googlebot](#Googlebot)                                   |   Web crawler    |           -           |
| [IPAPI](#IPAPI)                                           |  IP Geolocation  |           -           |
| [IPQualityScore](#IPQualityScore)                         |  IP Reputation   | Registration required |
| [IPURL](#IPURL)                                           |  User Provided   |           -           |
| [Linode](#Linode)                                         | Hosting Provider |           -           |
| [PTR](#PTR)                                               |       DNS        |           -           |
| [Shodan](#Shodan)                                         |  IP Reputation   | Registration required |
| [VirusTotal](#VirusTotal)                                 |  IP Reputation   | Registration required |
| [Zscaler](#Zscaler)                                       |    Security      |           -           |

## Installation

Binaries for macOS, Linux and Windows are available on the [releases](https://github.com/jonhadfield/ipscout/releases)
page.

### macOS - Homebrew

```
$ brew tap jonhadfield/ipscout
$ brew install ipscout
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

## Providers

Providers are configured in the `config.yaml` file.
A number of providers are enabled by default, but can be disabled by setting `enabled: false`.

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

