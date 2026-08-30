# Repository Guidelines

IPScout is a command-line tool written in Go that enriches IP addresses with origin and threat rating information. It queries multiple reputation and hosting providers concurrently to gather intelligence about IP addresses.

## Project Structure & Module Organization

The Go CLI is split by responsibility to keep provider logic isolated from orchestration. Key directories: `cmd/` hosts Cobra entrypoints, `providers/` contains subpackages for each reputation source, and `process/`, `manager/`, `rate/`, and `session/` coordinate lookups, caching, and scoring. Shared helpers and defaults live under `helpers/` and `constants/`, while `ui/` formats terminal output and holds related fixtures. Docs, examples, and release assets sit in `docs/`, `examples/`, and `.local_dist/`. Tests reside beside their packages as `_test.go` files.

## Build, Test, and Development Commands

- `go run . <host>` runs the CLI against a target host using your local config.
- `make build` emits a static binary at `.local_dist/ipscout`; `make build-all` cross-compiles for
  release. `make build-docker` builds the Docker image.
- `go test ./...` runs fast unit tests. `make test` aggregates coverage into `coverage.txt` and hits
  live provider APIs, so ensure credentials are configured first.
- `make fmt` applies `goimports` and `gofumpt`; `make lint` wraps `golangci-lint` (68+ linters);
  `make ci` chains lint and test for PR-ready validation.
- `make smoke` builds the release archives without publishing and exercises the packaged binary from
  a temp directory with a throwaway HOME. `make release` depends on it, so a failing smoke check
  aborts the release before anything is published.
- `make mac-install` / `make linux-install` install the binary to /usr/local/bin.
- Releasing is documented in README's "Releasing" section: write the changelog entry, push the
  annotated tag, then `make release`.

## Architecture Overview

The codebase follows a modular architecture with clear separation of concerns:

### Core Components

1. **Providers** (`/providers/`): Each provider (AbuseIPDB, AWS, Azure, Shodan, etc.) is implemented as a separate package with:
   - Provider struct implementing the Provider interface
   - `Fetch()` method for querying the provider's API
   - Result types specific to each provider
   - Unit tests for each provider

2. **Session Management** (`/session/`): Handles configuration loading, provider initialization, and API key management. Configuration is loaded from `$HOME/.config/ipscout/config.yaml`.

3. **Processing** (`/process/`): Core logic for:
   - Concurrent provider queries
   - Result aggregation
   - Error handling and retries
   - Cache integration

4. **Presentation** (`/present/`): Output formatting supporting:
   - Table output with multiple styles (ASCII, modern, light, bold, etc.)
   - JSON output for programmatic use

5. **Rating System** (`/rate/`): AI-powered host rating using OpenAI to analyze provider data and generate security assessments.

### Key Patterns

- **Interface-based design**: All providers implement a common Provider interface
- **Concurrent processing**: Uses goroutines and channels for parallel provider queries
- **Error handling**: Consistent error wrapping and logging throughout
- **Configuration**: Viper-based configuration with environment variable support
- **Caching**: Badger DB for persistent caching of provider responses

### ip-fetcher Dependency

Many providers fetch their IP-range data through the `github.com/jonhadfield/ip-fetcher` library, which is injected the session's HTTP client (`<client>.Client = c.HTTPClient`).

- **The released module is the source of truth, not a local checkout.** `go.mod` pins a `v`-prefixed release tag (e.g. `v0.0.16`), not a pseudo-version. A local `../ip-fetcher` checkout can differ in behaviour, and the released code can contradict its own naming: as of v0.0.29 the shared `bgpview` fetcher tries RIPE stat first and falls back to BGPView, while its `DefaultURL`/`FallbackURL` constants still name the older BGPView-first order. Read the call flow in the pinned module under `GOMODCACHE`, not the local repo and not the constant names.
- **To pick up ip-fetcher changes:** cut a new `v`-prefixed release tag in the ip-fetcher repo, then `go get github.com/jonhadfield/ip-fetcher@vX.Y.Z` and `go mod tidy` here. Don't reintroduce pseudo-versions.
- The `replace` directive in `go.mod` is for local dev only and must never be committed enabled.

### Adding New Providers

1. Create new package in `/providers/newprovider/` implementing the ProviderClient interface
   (`Enabled`, `Priority`, `Initialise`, `FindHost`, `CreateTable`, `ExtractThreatIndicators`, `RateHostData`)
2. Add the provider struct to `session.Providers` in `/session/session.go`
3. Add an entry to `registry.All()` in `/registry/registry.go` — the single source of truth used by
   process, rate and config. Set `DefaultEnabled: true` if the provider needs no configuration
   (no API key, paths, URLs or resource IDs) so it is enabled even when absent from user config
4. Add a default output priority constant in `/constants/constants.go` and wire config reading into
   `initProviderConfig` in BOTH `cmd/root.go` and `ui/root.go`
5. Add the provider to `session/config.yaml` (a registry guard test fails if a `DefaultEnabled`
   provider is missing from the shipped default config)
6. Add the TUI integration: a fetch/table file in `/ui/` plus the const, icon, fetch-map and
   provider-list entries in `/ui/main.go`
7. Bump `expectedProviderCount` in `/registry/registry_test.go` and add the provider to README.md
8. Write unit tests for the provider (see Testing Strategy)

### API Key Management

API keys are managed through environment variables or configuration file:

- Environment variables (no prefix): `ABUSEIPDB_API_KEY`, `CRIMINAL_IP_API_KEY`, `IPQS_API_KEY`,
  `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY` — read via `readProviderAuthKeys`; a keyed provider with
  no key is force-disabled
- Config file: `providers.<name>.api_key` is only read for ipapi, ipqs and shodan; the other keyed
  providers take keys from the environment variables above

## Coding Style & Naming Conventions

Honor standard Go tab indentation and keep files `gofumpt`-clean. Imports must be organized with `goimports`. Exported types and funcs use PascalCase; unexported symbols stay lowerCamelCase. File names follow snake_case with `_test.go` for tests. Prefer small, composable functions and propagate errors rather than logging inside libraries.

## Testing Guidelines

Place new tests in the same package, favor table-driven cases, and reuse testify assertions where they already exist. Run focused packages with `go test ./providers/shodan -run TestLookup` during development, then refresh coverage with `make test` before merging. Update or add fixtures under the relevant provider or `ui/` subdirectory to keep deterministic outputs.

- Unit tests for each provider with mocked HTTP responses
- Integration tests for core processing logic
- Table-driven tests for complex scenarios
- Coverage target: Maintain high coverage (currently ~80%+)
- Unit tests run inside the repository, so they cannot see problems that depend on the
  binary being somewhere else. `scripts/smoke.sh` covers that gap by running the packaged
  binary with no go.mod above it and no existing config; add a check there when a bug
  could only have been caught that way

## Commit & Pull Request Guidelines

Commits mirror the current history: short imperative subjects such as `add vultr` or `bump dependencies`, optional detail in the body when context helps. Keep subjects under ~65 characters. Pull requests should link issues, note manual test commands, and add screenshots for `ui/` changes. Tag maintainers responsible for the touched provider or subsystem.

## Security & Configuration Tips

Provider credentials live in `~/.config/ipscout/config.yaml`; never commit real keys or populated cache files. Sanitize artifacts before attaching them to issues. Use `make clean` to drop local build outputs, and inspect `app.log` for sensitive data before sharing logs.
