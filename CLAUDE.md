# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IPScout is a Go-based CLI tool for security analysts to enrich IP addresses with their origin and threat ratings. It queries multiple reputation and hosting providers concurrently, caches results, and presents data in table or JSON format.

## Development Commands

### Building
- `make build` - Build single binary to `.local_dist/ipscout`
- `make build-all` - Build for all platforms to `.local_dist/`
- `go build ./...` - Standard Go build

### Testing
- `make test` - Run full test suite with coverage (requires provider credentials)
- `go test ./...` - Run tests without coverage

### Code Quality
- `make lint` - Run golangci-lint
- `make fmt` - Format code with goimports and gofumpt
- `make critic` - Run gocritic checks
- `make ci` - Run lint and test together

### Installation
- `make install` - Install to GOPATH
- `make mac-install` - Install to /usr/local/bin (macOS)
- `make linux-install` - Install to /usr/local/bin (Linux, requires sudo)

## Architecture

### Core Components

**Main Entry Point**: `main.go` → `cmd/` package
- `cmd/root.go` - Main CLI command structure using Cobra
- `cmd/ui.go` - Terminal UI mode using tview
- `cmd/cache.go`, `cmd/config.go`, `cmd/rate.go` - Subcommands

**Processing Pipeline**: `process/process.go`
- Orchestrates provider queries concurrently
- Handles caching and result aggregation

**Provider System**: `providers/` directory
- Each provider in its own subdirectory (e.g. `providers/abuseipdb/`)
- Common interface defined in `providers/providers.go`
- Supports 20+ providers including AWS, Azure, VirusTotal, Shodan, etc.

**Session Management**: `session/session.go`
- Global configuration and state management
- Provider-specific configurations

**Caching**: `cache/cache.go`
- BadgerDB-based caching for provider responses and metadata
- Configurable TTLs per provider

**Output**: `present/present.go`
- Table formatting using go-pretty
- JSON output support
- Configurable styling (ascii, cyan, red, yellow, green, blue)

### Key Patterns

1. **Provider Interface**: All providers implement `ProviderClient` interface with methods like `Enabled()`, `FindHost()`, `CreateTable()`

2. **Configuration**: Viper-based config system with defaults, YAML files, and environment variable overrides

3. **Concurrent Processing**: Providers are queried in parallel using goroutines

4. **Caching Strategy**: Two-level caching - provider metadata (IP ranges, etc.) and lookup results

## Provider Configuration

Providers are configured in `config.yaml` with structure:
```yaml
providers:
  [provider_name]:
    enabled: true/false
    output_priority: integer
    [provider-specific config]
```

API keys are read from environment variables:
- `ABUSEIPDB_API_KEY`
- `CRIMINAL_IP_API_KEY`
- `IPQS_API_KEY`
- `SHODAN_API_KEY`
- `VIRUSTOTAL_API_KEY`

## Special Features

- **Rating System**: `rate/` directory implements AI-assisted threat rating
- **Terminal UI**: Interactive mode via `ipscout ui` command
- **Test Data**: `--use-test-data` flag for testing without API calls
- **Port Filtering**: Filter results by specific ports/protocols
- **Age Filtering**: Only show data within specified age limits

## File Organization

- Provider implementations: `providers/[provider]/[provider].go`
- Test data: `providers/[provider]/testdata/`
- Configuration templates: `session/config.yaml`
- Rating configuration: `rate/defaultRatingConfig.json`
