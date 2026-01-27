# Azure SDK Migration Plan

**Date**: 2026-01-26
**Issue**: Deprecated `go-autorest` and `azure-storage-blob-go` packages in dependency chain

---

## Current Status

### Dependency Analysis

The deprecated Azure packages are **not directly used** by IPScout. They are pulled in as transitive dependencies from the `azwaf` package:

```
IPScout (clean, uses modern SDK)
  └─→ azwaf@v0.0.0-20251207163444-9426662ad4f7
       ├─→ azure-storage-blob-go@v0.15.0 ⚠️ DEPRECATED
       ├─→ azure-pipeline-go@v0.2.3 ⚠️ DEPRECATED (indirect)
       └─→ go-autorest/* (multiple) ⚠️ ALL DEPRECATED
```

### IPScout's Current Azure Usage

IPScout **already uses modern Azure SDK** packages:
- ✅ `github.com/Azure/azure-sdk-for-go/sdk/azcore v1.21.0`
- ✅ `github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.13.1`
- ✅ `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor v1.4.0`
- ✅ `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.2.0`
- ✅ `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage v1.8.1`

**No code changes needed in IPScout itself!**

---

## Problem Source: azwaf Package

### azwaf Dependencies (from github.com/jonhadfield/azwaf)

**Deprecated packages used by azwaf:**
```go
// From azwaf go.mod
require (
    github.com/Azure/azure-storage-blob-go v0.15.0  // ⚠️ DEPRECATED
)

require (
    github.com/Azure/azure-pipeline-go v0.2.3 // indirect ⚠️
    github.com/Azure/go-autorest v14.2.0+incompatible // indirect ⚠️
    github.com/Azure/go-autorest/autorest v0.11.30 // indirect ⚠️
    github.com/Azure/go-autorest/autorest/adal v0.9.24 // indirect ⚠️
    github.com/Azure/go-autorest/autorest/date v0.3.1 // indirect ⚠️
    github.com/Azure/go-autorest/autorest/to v0.4.1 // indirect ⚠️
    github.com/Azure/go-autorest/autorest/validation v0.3.2 // indirect ⚠️
    github.com/Azure/go-autorest/logger v0.2.2 // indirect ⚠️
    github.com/Azure/go-autorest/tracing v0.6.1 // indirect ⚠️
)
```

**Modern replacement:**
```go
// Should use:
github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.x.x
```

---

## Migration Strategy

Since `azwaf` is maintained by the same author (jonhadfield), you have three options:

### Option 1: Update azwaf Package (Recommended)

**Prerequisites:**
- Access to https://github.com/jonhadfield/azwaf repository
- Local clone of azwaf

**Steps:**

#### 1. Clone or navigate to azwaf repository
```bash
# If not already cloned
cd ~/Repositories
git clone https://github.com/jonhadfield/azwaf.git
cd azwaf
```

#### 2. Replace deprecated storage package

**Find usages:**
```bash
grep -r "azure-storage-blob-go" .
grep -r "azblob" . --include="*.go"
```

**Migration mapping:**
```go
// OLD (DEPRECATED)
import (
    "github.com/Azure/azure-storage-blob-go/azblob"
)

// NEW (MODERN SDK)
import (
    "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)
```

#### 3. Update go.mod
```bash
# Remove old package
go mod edit -droprequire=github.com/Azure/azure-storage-blob-go

# Add new package
go get github.com/Azure/azure-sdk-for-go/sdk/storage/azblob@latest

# Clean up
go mod tidy
```

#### 4. Update code

**Key changes in API:**

| Old API | New API |
|---------|---------|
| `azblob.NewPipeline()` | Use `azblob.NewClient()` with credential |
| `azblob.NewServiceURL()` | `azblob.NewClient()` |
| `azblob.NewContainerURL()` | `client.ServiceClient().NewContainerClient()` |
| `azblob.NewBlockBlobURL()` | `containerClient.NewBlockBlobClient()` |

**Example migration:**

```go
// OLD
import (
    "github.com/Azure/azure-storage-blob-go/azblob"
    "github.com/Azure/go-autorest/autorest/azure/auth"
)

func oldCode() {
    credential, _ := azblob.NewSharedKeyCredential(accountName, accountKey)
    p := azblob.NewPipeline(credential, azblob.PipelineOptions{})
    u, _ := url.Parse(fmt.Sprintf("https://%s.blob.core.windows.net", accountName))
    serviceURL := azblob.NewServiceURL(*u, p)
    containerURL := serviceURL.NewContainerURL("mycontainer")
}

// NEW
import (
    "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
    "github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

func newCode() error {
    credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
    if err != nil {
        return err
    }

    serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net", accountName)
    client, err := azblob.NewClientWithSharedKeyCredential(serviceURL, credential, nil)
    if err != nil {
        return err
    }

    // Use client directly
    return nil
}
```

#### 5. Test changes
```bash
go test ./...
```

#### 6. Commit and tag new version
```bash
git add .
git commit -m "Migrate from deprecated azure-storage-blob-go to modern Azure SDK

- Replace github.com/Azure/azure-storage-blob-go with
  github.com/Azure/azure-sdk-for-go/sdk/storage/azblob
- Remove all go-autorest dependencies
- Update blob storage API calls to modern SDK patterns
- All tests passing"

git tag v0.2.0  # or appropriate version
git push origin main --tags
```

#### 7. Update IPScout to use new azwaf version
```bash
cd ~/Repositories/ipscout
go get github.com/jonhadfield/azwaf@v0.2.0
go mod tidy
make test
make lint
```

---

### Option 2: Use Local azwaf Development (Temporary)

If you want to develop and test locally before publishing:

#### 1. Uncomment replace directive in go.mod
```go
// In ipscout/go.mod
replace github.com/jonhadfield/azwaf => ../azwaf
```

#### 2. Make changes in local azwaf
```bash
cd ../azwaf
# Make migration changes as described in Option 1
go mod tidy
```

#### 3. Test in IPScout
```bash
cd ../ipscout
go mod tidy
make test
make lint
```

#### 4. Once satisfied, publish azwaf and remove replace directive

---

### Option 3: Make Azure WAF Provider Optional (Short-term workaround)

If immediate azwaf updates aren't possible, document the limitation:

#### 1. Update README.md
```markdown
## Provider Notes

### Azure WAF

**Note**: The Azure WAF provider currently depends on deprecated Azure SDK packages
through the azwaf library. While functionality is not affected, a migration to
modern Azure SDK packages is planned.

To disable this provider if it causes dependency conflicts:

\`\`\`yaml
providers:
  azurewaf:
    enabled: false
\`\`\`
```

#### 2. Add warning in code
```go
// In providers/azurewaf/azurewaf.go
// Add deprecation notice
const DeprecationWarning = `
Azure WAF provider uses legacy Azure SDK packages.
Migration to modern SDK is in progress.
`
```

---

## Migration Checklist

### For azwaf Package
- [ ] Clone/access azwaf repository
- [ ] Find all usages of `azure-storage-blob-go`
- [ ] Replace with `azure-sdk-for-go/sdk/storage/azblob`
- [ ] Update API calls to modern patterns
- [ ] Update authentication to use modern credential types
- [ ] Remove `go-autorest` dependencies
- [ ] Run all tests
- [ ] Update documentation
- [ ] Create git tag for new version
- [ ] Push changes and tags

### For IPScout
- [ ] Update azwaf dependency to new version
- [ ] Run `go mod tidy`
- [ ] Run tests: `make test`
- [ ] Run linting: `make lint`
- [ ] Verify Azure WAF provider still works
- [ ] Update roadmap document
- [ ] Mark Azure migration task complete

---

## Testing Strategy

### Unit Tests
```bash
# Test azwaf changes
cd ~/Repositories/azwaf
go test ./...

# Test ipscout with new azwaf
cd ~/Repositories/ipscout
go test ./providers/azurewaf/...
```

### Integration Tests
```bash
# Test Azure WAF provider end-to-end
# Requires Azure credentials
export AZURE_SUBSCRIPTION_ID="..."
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."

./ipscout <test-ip>
```

### Dependency Verification
```bash
# Verify no deprecated packages remain
go list -m all | grep -E "go-autorest|azure-storage-blob-go|azure-pipeline-go"

# Should return empty
```

---

## Reference Links

### Modern Azure SDK Documentation
- **Azure Storage Blob Go SDK**: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/storage/azblob
- **Migration Guide**: https://github.com/Azure/azure-sdk-for-go/blob/main/documentation/MIGRATION_GUIDE.md
- **Authentication**: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity

### Deprecated Packages
- ~~azure-storage-blob-go~~: https://github.com/Azure/azure-storage-blob-go (archived)
- ~~go-autorest~~: https://github.com/Azure/go-autorest (deprecated)

### Related Issues
- Azure SDK Migration Guide: https://github.com/Azure/azure-sdk-for-go/blob/main/documentation/MIGRATION_GUIDE.md
- Breaking Changes: https://github.com/Azure/azure-sdk-for-go/blob/main/documentation/CHANGELOG.md

---

## Expected Outcomes

### After Migration
- ✅ Zero deprecated dependencies
- ✅ Modern Azure SDK patterns throughout
- ✅ Better security with latest SDK updates
- ✅ Improved authentication options
- ✅ Future-proof against Azure changes
- ✅ All tests passing
- ✅ Zero linting issues maintained

### Risks
- **Low**: Azure WAF provider functionality may need minor adjustments
- **Mitigation**: Comprehensive testing before release
- **Rollback**: Keep old azwaf version tagged for easy revert

---

## Timeline Estimate

| Task | Time | Priority |
|------|------|----------|
| Research azwaf storage usage | 30 min | High |
| Update azwaf code | 2-3 hours | High |
| Test azwaf changes | 1 hour | High |
| Update ipscout dependency | 30 min | High |
| Integration testing | 1 hour | High |
| Documentation updates | 1 hour | Medium |
| **Total** | **6-7 hours** | - |

---

## Next Steps

1. **Immediate**: Check if local azwaf repository exists
2. **Then**: Follow Option 1 (recommended) or Option 2 (local dev)
3. **Test**: Verify all functionality works with modern SDK
4. **Document**: Update this plan with actual changes made
5. **Complete**: Mark Azure migration task complete in roadmap

---

## Questions?

- Check azwaf repository: https://github.com/jonhadfield/azwaf
- Azure SDK documentation: https://github.com/Azure/azure-sdk-for-go
- IPScout issues: https://github.com/jonhadfield/ipscout/issues

---

**Status**: Ready to begin migration
**Owner**: jonhadfield (repository maintainer)
**Blocking**: None - modern SDK already in use for other Azure providers
