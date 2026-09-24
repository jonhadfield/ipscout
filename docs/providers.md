# Provider Details

Every provider IPScout can query, what it holds, and how to configure it. See the
[README](../README.md) for installation, usage and the provider summary table.

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

### Reclaiming cache space

Expiring an entry removes the key but not the data behind it: the cache's underlying store
only frees that space when it rewrites its value log files. Closing the cache does a couple
of rewrites on every run, which keeps a healthy cache from growing, but a cache that has
been in use for a long time can hold far more on disk than its live entries account for.

`ipscout cache gc` does the rest in one go, and reports what it freed:

```shell
$ ipscout cache gc
rewrote 302 value log file(s)
cache went from 15.9 GB to 1.1 GB
```

`ipscout cache list` shows the live entries, so the two together tell you whether a large
cache directory is real data or reclaimable space.

## AbuseIPDB

This provider queries the [AbuseIPDB](https://www.abuseipdb.com/) API for information on an IP address, with a threat
confidence score, and any reports filed for them.
A [free plan](https://www.abuseipdb.com/pricing) exists for individuals, with a limit of 1000 requests per day.

Environment variable `ABUSEIPDB_API_KEY` must be set with your API key, and `providers.abuseipdb.enabled` set to `true`.

```yaml
providers:
  abuseipdb:
    enabled: false
```

## Alibaba Cloud

[Alibaba Cloud](https://www.alibabacloud.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Annotated

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

## Apple iCloud Private Relay

IP anonymisation service from [Apple](https://support.apple.com/en-us/102602), who publish their
egress [prefixes](https://mask-api.icloud.com/egress-ip-ranges.csv).
> iCloud Private Relay — part of an iCloud+ subscription — helps protect your privacy when you browse the web in Safari.

## Amazon Web Services

[AWS](https://aws.amazon.com/) is a Hosting Provider
that [publishes](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html#aws-ip-download) network prefixes
used by their services.

## Azure

[Azure](https://azure.microsoft.com/) is a hosting provider
that [publishes](https://www.microsoft.com/en-gb/download/details.aspx?id=56519) network prefixes used by their
services.

## Azure WAF

[Azure WAF](https://azure.microsoft.com/en-gb/products/web-application-firewall/) is a Web Application Firewall used to secure services hosted on Azure.
This currently supports Azure Global WAF, used to secure Azure Front Door, and will show custom rules and prefixes matching the provided host.
Authentication will be read from the environment.

## Better Stack

[Better Stack](https://betterstack.com/) runs uptime monitoring, and publishes the
addresses its checks originate from at
[uptime.betterstack.com/ips.txt](https://uptime.betterstack.com/ips.txt). A match means
the host is a Better Stack probe rather than the origin of the traffic it appears to
send.

## Bingbot

[Bingbot](https://www.bing.com/webmasters/help/help-center-661b2d18) is the web crawler for the Bing search engine.
Bing [publishes](https://www.bing.com/toolbox/bingbot.json) network prefixes used by their crawlers.

## CriminalIP

Query the [CriminalIP](https://www.criminalip.io/) API for information on an IP address/endpoint, with risk ratings, and
any abuse reports filed for them.
A [free plan](https://www.criminalip.io/pricing) exists with a small number of free credits.

Set environment variable `CRIMINAL_IP_API_URL` with your API key.

## Detectify

[Detectify](https://detectify.com/) runs external attack surface scans, and publishes the
addresses its scanners originate from at
[docs.detectify.com](https://docs.detectify.com/network-setup/scanner-ip-addresses). A
match means the host is a Detectify scanner rather than an unattributed source probing
your estate.

## DigitalOcean

[DigitalOcean](https://www.digitalocean.com/) is a hosting provider
that [publishes](https://www.digitalocean.com/geo/google.csv) network prefixes used by their services.

## Google Cloud Platform

[GCP](https://cloud.google.com/) is a hosting provider
that [publishes](https://cloud.google.com/compute/docs/faq#find_ip_range) network prefixes used by their
services.

## Google

[Google](https://support.google.com/a/answer/10026322?hl=en-GB) provides a list of IP addresses used by customers of their services
 and publishes them [here](https://www.gstatic.com/ipranges/goog.json).

## Google Special Crawlers

[Google](https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers#special-case-crawlers) provides a list
 of IP addresses used by their non-Googlebot crawlers [here](https://developers.google.com/static/search/apis/ipranges/special-crawlers.json).

## Googlebot

[Googlebot](https://developers.google.com/search/docs/crawling-indexing/googlebot) is a web crawler
and [publishes](https://developers.google.com/static/search/apis/ipranges/googlebot.json) network prefixes used by their
bots.

## Grafana

[Grafana](https://grafana.com/) runs synthetic monitoring from a set of public probes, and
publishes their ranges at
[allowlists.grafana.com/synthetics](https://allowlists.grafana.com/synthetics). A match
means the host is a Grafana probe rather than the origin of the traffic it appears to
send. The document also names the probe location.

## GreenSnow

[GreenSnow](https://greensnow.co/) collects addresses seen attacking servers, such as
brute force attempts against SSH, mail and web services, and publishes them at
[blocklist.greensnow.co/greensnow.txt](https://blocklist.greensnow.co/greensnow.txt).
IPScout downloads this list and checks whether the target IP appears in it. The list
changes constantly, so it is cached for an hour rather than the usual day.

## Hetzner

[Hetzner](https://www.hetzner.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Huawei Cloud

[Huawei Cloud](https://www.huaweicloud.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat API for Huawei's published ASNs and checked for
matches against the target host.

## InternetDB

Query Shodan's free [InternetDB](https://internetdb.shodan.io/) API for the open ports,
hostnames, tags, software (CPEs) and known vulnerabilities recorded for an IP address. No API
key is needed. Private and other non-public addresses are not looked up.

## IPAPI

Query the [ipapi](https://ipapi.co/) API for geolocation data.
ipapi.co rate limits keyless requests so heavily that they fail for most users, so this
provider only runs with an API key. See [pricing](https://ipapi.co/pricing/).

Set environment variable `IPAPI_API_KEY`, or `providers.ipapi.api_key` in the config, with
your API key, and set `providers.ipapi.enabled` to `true`.

## ip-api.com

Query the [ip-api.com](https://ip-api.com/) API for geolocation, ISP and AS data, and whether
the address is a proxy, VPN or Tor exit, a hosting provider or a mobile network. No API key is
needed.

The free tier is limited to 45 requests per minute, is for non-commercial use only, and is
served over plain HTTP, so the addresses you look up are sent unencrypted. Set
`providers.ipapicom.enabled` to `false` if any of these rule it out for you.

## IPQualityScore

Query the [IPQualityScore](https://www.ipqualityscore.com/documentation/proxy-detection-api/overview) API for host reputation data.
The API is free to registered users for 5,000 requests.

Set environment variable `IPQS_API_KEY` with your API key, and set `providers.ipqs.enabled` to `true`.

## IPtoASN

[iptoasn.com](https://iptoasn.com/) publishes a free, hourly-updated IP address to ASN mapping.
The combined IPv4+IPv6 dataset is downloaded and cached, and the target host is matched against it to report the
announcing AS number, name, country and address range.

## IPURL

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

## Linode

[Linode](https://www.linode.com/) is a hosting provider
that [publishes](https://geoip.linode.com/) network prefixes used by their services.

## M247

[M247](https://www.m247.com/) is a global hosting and connectivity provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Microsoft 365

[Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service)
publishes the ranges its services run from. A match names the service area — Exchange
Online, SharePoint, Skype or the common set — and Microsoft's own category for the range:
`Optimize`, `Allow` or `Default`.

## Mullvad

[Mullvad](https://mullvad.net/) is a VPN provider. IPScout downloads the full relay list
from Mullvad's API and checks whether the target IP is an ingress address for any active
relay.

## New Relic

[New Relic](https://newrelic.com/) publishes the addresses its synthetic monitors run
from, grouped by location. A match means the host is a New Relic synthetics probe, and
names the location it runs from, such as "Washington, DC, USA".

## Okta

[Okta](https://help.okta.com/en-us/content/topics/security/ip-address-allow-listing.htm)
publishes the ranges its cells run from. A match names the cell, which is how Okta
partitions its infrastructure.

## OpenAI

[OpenAI](https://platform.openai.com/docs/bots) operates a number of bots and publishes the network prefixes they crawl
and browse from: [GPTBot](https://openai.com/gptbot.json), [OAI-SearchBot](https://openai.com/searchbot.json)
and [ChatGPT-User](https://openai.com/chatgpt-user.json). A match shows which of the bots' lists contain the target host.

## OVH

[OVH](https://www.ovhcloud.com/) is a hosting provider
that [publishes](https://vps.ovh.net/ips.txt) network prefixes used by their services.

## Scaleway

[Scaleway](https://www.scaleway.com/) is a European hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Vultr

[Vultr](https://www.vultr.com/) is a cloud hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Pingdom

[Pingdom](https://www.pingdom.com/) publishes the addresses its uptime probes run from.
A match means the host is a Pingdom probe rather than a visitor.

## PTR

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

## Sentry

[Sentry](https://sentry.io/) runs uptime checks from a published set of addresses, listed
at
[docs.sentry.io](https://docs.sentry.io/security-legal-pii/security/ip-ranges/). A match
means the host is a Sentry uptime checker rather than the origin of the traffic it appears
to send.

## Shodan

Query the [Shodan](https://www.shodan.io/) API for information on an IP address, with open ports, and services.

Set environment variable `SHODAN_API_KEY` with your API key, and set `providers.shodan.enabled` to `true`.

## Uptrends

[Uptrends](https://www.uptrends.com/) monitors sites from a set of checkpoints, and
publishes their addresses for allowlisting at
[uptrends.com](https://www.uptrends.com/support/kb/account/ip-addresses-for-whitelisting).
A match means the host is an Uptrends checkpoint rather than the origin of the traffic it
appears to send.

## VirusTotal

Query the [VirusTotal](https://www.virustotal.com) API for information from various providers on an IP address.

Set environment variable `VIRUSTOTAL_API_KEY` with your API key, and set `providers.virustotal.enabled` to `true`.

## Zoom

[Zoom](https://zoom.us/) publishes the network ranges its meeting and phone services use.
A match means the host belongs to Zoom's service infrastructure.

## Zscaler

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

## AhrefsBot

[AhrefsBot](https://ahrefs.com/robot) is the web crawler for the Ahrefs SEO
platform. Ahrefs publishes the IP ranges used by its crawler at
[api.ahrefs.com/v3/public/crawler-ip-ranges](https://api.ahrefs.com/v3/public/crawler-ip-ranges).
IPScout downloads this list and checks whether the target IP is within those ranges.

## Akamai

[Akamai](https://www.akamai.com/) is a content delivery network that publishes
the IP ranges used by its edge platform at
[ip-ranges.akamai.com](https://ip-ranges.akamai.com/). IPScout downloads this
list and checks whether the target IP is within those ranges.

## Applebot

[Applebot](https://support.apple.com/en-us/119829) is Apple's web crawler, used
by products such as Siri and Spotlight. Apple publishes the IP ranges used by
the crawler at
[search.developer.apple.com/applebot.json](https://search.developer.apple.com/applebot.json).
IPScout downloads this list and checks whether the target IP is within those ranges.

## Amazonbot

[Amazonbot](https://developer.amazon.com/amazonbot) is Amazon's web crawler. IPScout
downloads the Amazonbot, Amzn-SearchBot and Amzn-User prefix lists embedded in Amazon's
developer documentation and reports which list(s) a matching address belongs to.

## Atlassian

[Atlassian](https://www.atlassian.com/) publishes the IP ranges used by its
cloud products (Jira, Confluence, Bitbucket and others). IPScout downloads this
list and checks whether the target IP is within those ranges.

## Bunny CDN

[Bunny CDN](https://bunny.net/) is a content delivery network that publishes the
IP ranges used by its edge servers. IPScout downloads this list and checks
whether the target IP is within those ranges.

## CacheFly

[CacheFly](https://www.cachefly.com/) is a content delivery network that publishes its
CDN edge prefixes at [cachefly.cachefly.net/ips/cdn.txt](https://cachefly.cachefly.net/ips/cdn.txt).
IPScout downloads this list and checks whether the target IP is within those ranges.

## CCBot

[CCBot](https://commoncrawl.org/ccbot) is Common Crawl's web crawler. IPScout downloads
the published prefix document from
[index.commoncrawl.org/ccbot.json](https://index.commoncrawl.org/ccbot.json) and checks
whether the target IP is within those ranges.

## CDN77

[CDN77](https://www.cdn77.com/) is a content delivery network that publishes the
prefixes used by its edge network. IPScout downloads this list and checks
whether the target IP is within those ranges.

## Cloudflare

[Cloudflare](https://www.cloudflare.com/) is a content delivery network that
publishes the IP ranges used by its edge network at
[cloudflare.com/ips-v4](https://www.cloudflare.com/ips-v4) and
[cloudflare.com/ips-v6](https://www.cloudflare.com/ips-v6). IPScout downloads
these lists and checks whether the target IP is within those ranges.

## Contabo

[Contabo](https://contabo.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Datadog

[Datadog](https://www.datadoghq.com/) is an observability platform that
publishes the IP ranges used by its services. IPScout downloads this list and
checks whether the target IP is within those ranges.

## DuckDuckBot

[DuckDuckBot](https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot/)
is the web crawler for the DuckDuckGo search engine. DuckDuckGo publishes the IP
addresses used by the crawler at
[duckduckgo.com/duckduckbot.json](https://duckduckgo.com/duckduckbot.json).
IPScout downloads this list and checks whether the target IP is within those ranges.

## Fastly

[Fastly](https://www.fastly.com/) is a content delivery network that publishes
the IP ranges used by its edge network via its
[public IP list API](https://api.fastly.com/public-ip-list). IPScout downloads
this list and checks whether the target IP is within those ranges.

## Fly.io

[Fly.io](https://fly.io/) is an application hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Feodo Tracker

[Feodo Tracker](https://feodotracker.abuse.ch/) is abuse.ch's list of botnet command and
control servers — Dridex, Emotet, TrickBot and QakBot among them. A match means the host is
a live C2 server, which is the strongest single signal in the tool: it scores 10.0, level
with the other threat feeds.

## Gcore

[Gcore](https://gcore.com/) is a CDN and edge platform that publishes the addresses its
edge nodes serve from. A match means the host is Gcore edge infrastructure rather than
the origin server behind it.

## GitHub

[GitHub](https://github.com/) publishes the IP ranges used by its services
(web, API, Actions, Pages and others) via its
[meta API](https://api.github.com/meta). IPScout downloads this list and
reports the services associated with any matching range.

## GitLab

[GitLab](https://about.gitlab.com/) publishes the IP ranges used by GitLab.com (web, API
and webhooks) in its documentation. IPScout extracts those CIDRs and checks whether the
target IP is within them.

## Google User-triggered Fetchers

Google publishes the IP ranges used by its
[user-triggered fetchers](https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json),
tools that fetch pages on behalf of a user request. IPScout downloads this list
and checks whether the target IP is within those ranges.

## IBM Cloud

[IBM Cloud](https://www.ibm.com/cloud) is a hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Imperva

[Imperva](https://www.imperva.com/) (Incapsula) is a web application firewall and
CDN that publishes the IP ranges used by its network. IPScout downloads this list
and checks whether the target IP is within those ranges.

## Intercom

[Intercom](https://www.intercom.com/) publishes the IP ranges used by its US, EU and AU
workspaces. IPScout merges those lists and reports the region and service associated with
any matching range.

## Leaseweb

[Leaseweb](https://www.leaseweb.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Oracle Cloud (OCI)

[Oracle Cloud Infrastructure](https://www.oracle.com/cloud/) publishes the
[IP ranges](https://docs.oracle.com/iaas/tools/public_ip_ranges.json) used by
its services. IPScout downloads this list and reports the region and service
tags associated with any matching range.

## PerplexityBot

[PerplexityBot](https://docs.perplexity.ai/guides/bots) is the web crawler for
the Perplexity answer engine. Perplexity publishes the IP ranges used by the
crawler at
[perplexity.com/perplexitybot.json](https://www.perplexity.com/perplexitybot.json).
IPScout downloads this list and checks whether the target IP is within those ranges.

## Render

[Render](https://render.com/) is an application hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Salesforce

[Salesforce](https://www.salesforce.com/) publishes Hyperforce public IP ranges at
[ip-ranges.salesforce.com](https://ip-ranges.salesforce.com/ip-ranges.json). IPScout
downloads this list and reports the region and provider associated with any matching range.

## StatusCake

[StatusCake](https://www.statuscake.com/) publishes the locations its monitoring runs
from, each with an address. A match means the host is a StatusCake probe, and reports the
location's title, server code, country and current status.

## Stripe

[Stripe](https://stripe.com/) publishes the IP ranges used by its API and webhook
infrastructure. IPScout downloads this list and checks whether the target IP is
within those ranges.

## Team Cymru Bogons

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

## Tenable

[Tenable](https://www.tenable.com/) runs cloud vulnerability scanners, and publishes their
ranges at
[docs.tenable.com](https://docs.tenable.com/vulnerability-management/Content/Settings/Sensors/CloudSensors.htm).
A match means the host is a Tenable cloud sensor rather than an unattributed source
scanning your estate. The document names the region, service and sensor group behind the
range, and flags the separately published FedRAMP ranges.

## Tencent Cloud

[Tencent Cloud](https://www.tencentcloud.com/) is a hosting provider.
IP ranges are retrieved from the RIPE stat API and checked for matches against the target host.

## Anthropic

[Anthropic](https://www.anthropic.com/) publishes the IP ranges used by its
crawlers, including ClaudeBot and the Claude user-triggered fetchers, at
[claude.com/crawling/bots.json](https://claude.com/crawling/bots.json).
IPScout downloads this list and checks whether the target IP is within those ranges.

## Blocklist.de

[Blocklist.de](https://www.blocklist.de/en/index.html) is a community-run service
that collects reports of hosts attacking other systems via SSH, mail, web and
other services. The aggregated list of reported addresses is published at
[lists.blocklist.de/lists/all.txt](https://lists.blocklist.de/lists/all.txt).
IPScout downloads this list and checks whether the target IP appears in it.

## Checkly

[Checkly](https://www.checklyhq.com/) runs synthetic monitoring checks and publishes the
static addresses they run from. A match means the host is a Checkly probe.

## CINS Army List

The [CINS Army List](https://cinsscore.com/) is the freely available subset of
the Collective Intelligence Network Security score, listing addresses with a poor
reputation that are not yet widely blocked. It is published at
[cinsscore.com/list/ci-badguys.txt](https://cinsscore.com/list/ci-badguys.txt).
IPScout downloads this list and checks whether the target IP appears in it.

## DShield

[DShield](https://www.dshield.org/) is the SANS Internet Storm Center's
distributed intrusion detection system. Its recommended block list, covering the
networks responsible for the most reported attacks, is published at
[feeds.dshield.org/block.txt](https://feeds.dshield.org/block.txt).
IPScout downloads this list and checks whether the target IP is within those
networks, reporting the attack count and network owner where available.

## Emerging Threats

[Emerging Threats](https://rules.emergingthreats.net/blockrules/) publishes open
rulesets and reputation data for intrusion detection systems. Its list of known
compromised hosts is published at
[rules.emergingthreats.net/blockrules/compromised-ips.txt](https://rules.emergingthreats.net/blockrules/compromised-ips.txt).
IPScout downloads this list and checks whether the target IP appears in it.

## Site24x7

[Site24x7](https://www.site24x7.com/) monitors sites from locations worldwide and
publishes the addresses each location checks from. A match means the host is a Site24x7
monitoring location rather than the origin of the traffic it appears to send.

## Spamhaus DROP

[Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
(Don't Route Or Peer) lists netblocks that Spamhaus considers wholly controlled
by criminal operations. The lists are published at
[spamhaus.org/drop/drop_v4.json](https://www.spamhaus.org/drop/drop_v4.json) and
[spamhaus.org/drop/drop_v6.json](https://www.spamhaus.org/drop/drop_v6.json).
IPScout downloads both lists and checks whether the target IP is within those
netblocks, reporting the associated SBL identifier and RIR.

## Tor Exit Node

[Tor](https://check.torproject.org/) publishes the addresses traffic leaves its network
from. A match means the request reached you through Tor, so the address says nothing about
who sent it. Not malicious in itself, and plenty of legitimate traffic uses it, but it is a
deliberate anonymiser rather than an ordinary host: it scores 6.0, above the identified
services and below the threat feeds.

## updown.io

[updown.io](https://updown.io/) checks sites from a set of nodes whose addresses it
publishes at [updown.io/api](https://updown.io/api). A match means the host is an
updown.io node rather than the origin of the traffic it appears to send.

## UptimeRobot

[UptimeRobot](https://uptimerobot.com/help/locations/) is a website and service
monitoring platform. The IP ranges used by its monitoring probes are published at
[uptimerobot.com/inc/files/ips/IPv4andIPv6.txt](https://uptimerobot.com/inc/files/ips/IPv4andIPv6.txt).
IPScout downloads this list and checks whether the target IP is within those ranges.
