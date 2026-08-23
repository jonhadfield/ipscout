# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed
- `--use-test-data` now works for an installed binary. The providers read their test data
  from a path relative to the directory containing go.mod, so outside a source checkout
  every provider silently returned no result. The test data is now embedded in the binary
  and extracted to the user cache when the source tree is unavailable; running from a
  checkout is unchanged

## [0.9.0] - 2026-08-22
### Added
- Anthropic and UptimeRobot providers, covering the Anthropic crawler prefixes and the
  UptimeRobot monitoring probe ranges
- Blocklist.de, CINS Army List, DShield, Emerging Threats and Spamhaus DROP threat feed
  providers, reporting whether the host appears on each blocklist
### Changed
- bump ip-fetcher to v0.0.21, which supplies the seven new provider sources
- widen the existing nolint directives in ui/annotated.go, ui/ptr.go and ui/shodan.go to cover
  staticcheck SA4006, which a newer staticcheck now reports for the same assignments

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

[Unreleased]: https://github.com/jonhadfield/ipscout/compare/0.2.10...HEAD
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
