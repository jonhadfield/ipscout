# Overview

IPScout is a command line tool for network administrators and security analysts to quickly identify the origin
and threat of an IP address.

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
| [CriminalIP](#CriminalIP)                                 |  IP Reputation   | Registration required |
| [DigitalOcean](#DigitalOcean)                             | Hosting Provider |           -           |
| [GCP](#Google-Cloud-Platform)                             | Hosting Provider |           -           |
| [IPURL](#IPURL)                                           |  User Provided   |           -           |
| [IPAPI](#IPAPI)                                           |  IP Geolocation  |           -           |
| [Linode](#Linode)                                         | Hosting Provider |           -           |
| [PTR](#PTR)                                               |       DNS        |           -           |
| [Shodan](#Shodan)                                         |  IP Reputation   | Registration required |

## Installation

Binaries for macOS, Linux and Windows are available on the [releases](https://github.com/jonhadfield/ipscout/releases)
page.

### macOS - Homebrew

```
$ brew tap jonhadfield/ipscout
$ brew install ipscout
```

### other distributions

Download the latest release from the [releases](https://github.com/jonhadfield/ipscout/releases) page.

## Usage

```shell
$ ipscout <ip address>
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
  output: table         # output format: table or json
  ports: []             # filter results by port [tcp,udp,443/tcp,...]

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
    enabled: false
    paths:
      - /path/to/file.yaml
```

### Amazon Web Services

[AWS](https://aws.amazon.com/) is a Hosting Provider
that [publishes](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html#aws-ip-download) network prefixes
used by their services.

### Apple iCloud Private Relay

[iCloud Private Relay](https://support.apple.com/en-us/102602) is an anonymising service provided by Apple. They publish
their network prefixes [here](https://mask-api.icloud.com/egress-ip-ranges.csv).

### Azure

[Azure](https://azure.microsoft.com/) is a hosting provider
that [publishes](https://www.microsoft.com/en-gb/download/details.aspx?id=56519) network prefixes used by their
services.

### CriminalIP

Query the [CriminalIP](https://www.criminalip.io/) API for information on an IP address/endpoint, with risk ratings, and
any abuse reports filed for them.
A [free plan](https://www.criminalip.io/pricing) exists with a small number of free credits.

Environment variable `CRIMINAL_IP_API_KEY` must be set with your API key.

### DigitalOcean

[DigitalOcean](https://www.digitalocean.com/) is a hosting provider
that [publishes](https://www.digitalocean.com/geo/google.csv) network prefixes used by their services.

### Google Cloud Platform
[GCP](https://cloud.google.com/) is a hosting provider
that [publishes](https://cloud.google.com/compute/docs/faq#find_ip_range) network prefixes used by their
services.

### IPAPI

Query the [ipapi](https://ipapi.co/) API for geolocation data.
The API is free for up 30,000 requests per day.

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

