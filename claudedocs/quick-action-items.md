# Quick Action Items for IPScout

**Generated**: 2026-01-26
**Priority-sorted list of improvements**

---

## 🔴 Critical (Do First)

### 1. Security & Dependencies (Est: 2-3 days)
```bash
# Run security scan
govulncheck ./...

# Check for outdated dependencies
go list -m -u all | grep '\['

# Update deprecated Azure packages
# Replace: github.com/Azure/go-autorest/*
# With: Modern Azure SDK packages
```

**Impact**: Reduces security vulnerabilities
**Risk**: High if delayed

---

### 2. Test Coverage - Core Packages (Est: 3-4 days)

**0% Coverage Packages** (Priority order):
1. `main.go` - Main package entry point
2. `config/` - Configuration management
3. `helpers/` - Helper utilities
4. `manager/` - Manager functionality
5. `present/` - Presentation layer

**Action**:
```bash
# Example: Add tests for config package
touch config/config_test.go

# Run tests with coverage
go test -cover ./config
```

**Impact**: Catches bugs early, enables confident refactoring
**Risk**: Medium - untested code may have hidden bugs

---

## 🟡 Important (Do Soon)

### 3. Provider Test Coverage (Est: 5-7 days)

**Untested Providers** (start with most critical):
- `providers/abuseipdb/` - Reputation provider
- `providers/virustotal/` - Reputation provider
- `providers/shodan/` - Reputation provider
- `providers/criminalip/` - Reputation provider
- `providers/aws/` - Cloud provider
- `providers/azure/` - Cloud provider
- `providers/gcp/` - Cloud provider

**Pattern to follow**:
```go
// See: providers/alibaba/alibaba_test.go for example
func TestEnabled(t *testing.T) { }
func TestUnmarshalResponse(t *testing.T) { }
func TestLoadResultsFile(t *testing.T) { }
```

---

### 4. Improve Low Coverage Packages (Est: 2-3 days)

**Current → Target**:
- `process/`: 11.6% → 70%+
- `google/`: 9.9% → 70%+
- `ipqs/`: 14.0% → 70%+
- `virustotal/`: 15.4% → 70%+

---

### 5. Documentation (Est: 2-3 days)

**Files to Create**:
```bash
# Architecture documentation
touch docs/ARCHITECTURE.md

# Contribution guide
touch CONTRIBUTING.md

# Provider development guide
touch docs/PROVIDER_DEVELOPMENT.md

# Error handling patterns
touch docs/ERROR_HANDLING.md

# Testing guide
touch docs/TESTING_GUIDE.md
```

**Add godoc comments**:
```bash
# Check current godoc coverage
go doc -all github.com/jonhadfield/ipscout

# Add missing comments for exported functions
```

---

## 🟢 Nice to Have (Do Later)

### 6. Performance Benchmarks (Est: 2 days)
```bash
mkdir benchmarks
touch benchmarks/provider_bench_test.go
touch benchmarks/cache_bench_test.go

# Run benchmarks
go test -bench=. -benchmem ./benchmarks
```

---

### 7. Additional Output Formats (Est: 1-2 days)
- Add YAML output
- Add CSV export
- Add custom templates

---

### 8. Developer Experience (Est: 2-3 days)
- Add provider scaffolding generator
- Add VSCode/GoLand configurations
- Add Docker Compose for testing
- Add integration test environment

---

## ⚡ Quick Wins (Do Today - <1 hour each)

### Immediate Actions
```bash
# 1. Run security scan (5 min)
govulncheck ./...

# 2. Add .editorconfig (10 min)
cat > .editorconfig << 'EOF'
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true

[*.go]
indent_style = tab
indent_size = 4

[*.{yml,yaml,json}]
indent_style = space
indent_size = 2

[Makefile]
indent_style = tab
EOF

# 3. Add CODEOWNERS (15 min)
cat > .github/CODEOWNERS << 'EOF'
# Default owners for everything
* @jonhadfield

# Provider specific ownership
/providers/ @jonhadfield
/ui/ @jonhadfield
EOF

# 4. Add issue template (30 min)
mkdir -p .github/ISSUE_TEMPLATE
cat > .github/ISSUE_TEMPLATE/bug_report.md << 'EOF'
---
name: Bug Report
about: Report a bug in IPScout
title: '[BUG] '
labels: bug
---

## Bug Description
A clear description of the bug.

## Steps to Reproduce
1. Run command: `ipscout ...`
2. ...

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Environment
- IPScout version:
- OS:
- Go version:

## Additional Context
Any other relevant information.
EOF

# 5. Add PR template (15 min)
cat > .github/PULL_REQUEST_TEMPLATE.md << 'EOF'
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] No new linting issues
EOF

# 6. Add SECURITY.md (30 min)
cat > SECURITY.md << 'EOF'
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities to: security@example.com

Do not create public GitHub issues for security vulnerabilities.

We will respond within 48 hours and provide updates every 5 days.
EOF

# 7. Add codecov integration (1 hour)
# Sign up at codecov.io
# Add token to GitHub Secrets
cat > .github/workflows/codecov.yml << 'EOF'
name: Coverage

on: [push, pull_request]

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - name: Generate coverage
        run: make test
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.txt
EOF
```

---

## Daily Workflow Improvements

### Add to Makefile
```makefile
# Add these targets to your Makefile

.PHONY: security-check
security-check:  ## Run security vulnerability check
	@echo "Running security scan..."
	govulncheck ./...

.PHONY: test-coverage
test-coverage:  ## Run tests with coverage report
	@echo "Running tests with coverage..."
	go test -cover -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: deps-update
deps-update:  ## Check for dependency updates
	@echo "Checking for dependency updates..."
	go list -m -u all | grep '\['

.PHONY: deps-tidy
deps-tidy:  ## Clean up dependencies
	go mod tidy
	go mod verify

.PHONY: benchmark
benchmark:  ## Run benchmarks
	go test -bench=. -benchmem ./benchmarks/...

.PHONY: docs
docs:  ## Generate documentation
	@echo "Generating documentation..."
	go doc -all > docs/API.txt
	@echo "Documentation generated: docs/API.txt"

.PHONY: pre-commit
pre-commit: fmt lint test-coverage security-check  ## Run all checks before commit
	@echo "Pre-commit checks passed!"
```

---

## Testing Strategy

### 1. Unit Test Pattern
```go
// Standard test structure for providers
func TestProviderName_Method(t *testing.T) {
    tests := []struct {
        name    string
        input   interface{}
        want    interface{}
        wantErr bool
    }{
        {
            name: "valid input",
            input: "test",
            want: "expected",
            wantErr: false,
        },
        // Add more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### 2. Integration Test Pattern
```go
// Test with real HTTP calls (mark as integration)
func TestProvider_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }

    // Integration test implementation
}
```

### 3. Run Tests
```bash
# Unit tests only (fast)
go test -short ./...

# All tests including integration
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test -v ./providers/abuseipdb/
```

---

## Dependency Update Strategy

### Monthly Review Process
```bash
# 1. Check for updates
go list -m -u all > /tmp/deps-before.txt

# 2. Update indirect dependencies
go get -u ./...

# 3. Update direct dependencies (carefully)
go get -u github.com/spf13/cobra@latest
go get -u github.com/stretchr/testify@latest
# ... etc

# 4. Tidy
go mod tidy

# 5. Run tests
make test

# 6. Run linting
make lint

# 7. Check diff
go list -m all > /tmp/deps-after.txt
diff /tmp/deps-before.txt /tmp/deps-after.txt
```

---

## Success Criteria

### Week 1
- ✅ Security scan completed
- ✅ Deprecated dependencies replaced
- ✅ Core packages have tests (main, config, helpers, manager)
- ✅ Quick wins implemented

### Week 2-3
- ✅ All provider packages have basic tests
- ✅ Test coverage >70% overall
- ✅ Documentation files created

### Week 4+
- ✅ Benchmarks in place
- ✅ Performance optimizations implemented
- ✅ CI/CD enhancements deployed

---

## Need Help?

### Resources
- Full roadmap: `claudedocs/improvement-roadmap.md`
- Go testing: https://go.dev/doc/tutorial/add-a-test
- Table-driven tests: https://github.com/golang/go/wiki/TableDrivenTests
- Security: https://go.dev/security/vulndb

### Commands Reference
```bash
# Run specific tests
go test -v -run TestFunctionName ./package

# Get test coverage for specific package
go test -cover ./providers/abuseipdb

# Generate coverage HTML
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run benchmarks
go test -bench=. -benchmem

# Security scan
govulncheck ./...

# Lint
make lint

# Build
make build
```

---

**Remember**: Start with Priority 1 items, implement quick wins today, and work through the priorities systematically.
