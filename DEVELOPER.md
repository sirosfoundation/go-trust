# Developer Guide

This guide covers the development workflow, tooling, and best practices for contributing to go-trust.

## Table of Contents

- [Quick Start](#quick-start)
- [Development Environment](#development-environment)
- [Available Make Targets](#available-make-targets)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Git Workflow](#git-workflow)
- [VS Code Setup](#vs-code-setup)
- [Debugging](#debugging)
- [Performance](#performance)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/sirosfoundation/go-trust.git
cd go-trust

# Set up development environment (installs tools, sets up git hooks)
make setup

# Run tests
make test

# Build the binary
make build

# Run the server (with test certificate bundle)
./gt --etsi-cert-bundle /path/to/certs.pem
```

## Development Environment

### Requirements

- **Go**: Version specified in `go.mod` (check with `make check-go-version`)
- **Git**: For version control and hooks

### One-Time Setup

Run the setup script to configure your development environment:

```bash
make setup
```

This will:
- Install development tools (linters, formatters, etc.)
- Set up Git pre-commit hooks
- Verify Go version
- Download dependencies
- Run initial tests

### Manual Setup

If you prefer manual setup:

```bash
# Install development tools
make tools

# Install Git hook manually
ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x scripts/pre-commit.sh

# Download dependencies
go mod download
```

## Available Make Targets

### Building

```bash
make build          # Build the binary (output: ./gt)
make install        # Install to $GOPATH/bin
make clean          # Remove build artifacts
```

### Testing

```bash
make test           # Run all tests with race detection
make test-all       # Run all tests including integration tests
make bench          # Run all benchmarks
make bench-api      # Run API benchmarks only
```

### Code Quality

```bash
make fmt            # Format all Go code
make vet            # Run go vet
make lint           # Run all linters (golangci-lint, gosec, staticcheck)
make quick          # Quick checks (fmt + vet) before commit
```

### Coverage

```bash
make coverage       # Generate coverage report
make coverage-html  # Generate and view HTML coverage report
make check-coverage # Run coverage with threshold checks
```

### Development Workflow

```bash
make all            # Run all checks and build (CI pipeline)
make ci             # Alias for 'all'
make quick          # Fast pre-commit checks
make watch          # Watch for changes and run tests (requires entr)
```

### Tools

```bash
make tools          # Install development tools
make vscode         # Install VS Code dependencies (Linux/apt)
```

### Other

```bash
make help           # Show all available targets
make run ARGS='...' # Run the built binary with arguments
make docker         # Build Docker image
```

## Testing

### Running Tests

```bash
# All tests with coverage
make test

# Specific package
go test ./pkg/api -v

# Specific test
go test ./pkg/api -run TestHealthEndpoint -v

# With race detection (default)
go test -race ./...

# Integration tests
make test-integration
```

### Writing Tests

- Use table-driven tests for multiple scenarios
- Always include edge cases and error paths
- Use `testify/assert` for assertions
- Name tests descriptively: `Test<Function>_<Scenario>`
- Add comments explaining complex test setups

Example:

```go
func TestMyFunction_WithValidInput(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"empty", "", "", false},
        {"valid", "test", "TEST", false},
        {"error", "!", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := MyFunction(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            assert.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

### Integration Tests

The project includes comprehensive integration tests that start real HTTP servers and test all API endpoints end-to-end. These tests are located in `cmd/gt/integration_test.go` and use the `integration` build tag.

#### Running Integration Tests

```bash
# Via make (recommended)
make test-integration

# Directly with go test
go test -tags=integration -v ./cmd/gt/...
```

#### What's Tested

Integration tests cover:

- **Health endpoints**: `/healthz` and `/readyz` for liveness/readiness probes
- **Metrics endpoint**: `/metrics` for Prometheus metrics
- **AuthZEN discovery**: `/.well-known/authzen-configuration`
- **Registry information**: `/registries` endpoint
- **Evaluation endpoint**: `/evaluation` with various scenarios:
  - Valid requests with mock registries
  - Trusted certificates (generated test CA)
  - Untrusted certificates
  - Invalid requests (missing body, malformed JSON)
- **Concurrent requests**: Tests server under concurrent load
- **Graceful shutdown**: Tests clean server shutdown

#### Writing Integration Tests

Integration tests use a helper function `startTestServer` that configures and starts a real HTTP server:

```go
func TestMyIntegration(t *testing.T) {
    // Start server with generated test certificates and trigger initial refresh
    ts := startTestServer(t, withGeneratedCerts(), withRefresh())
    defer ts.Close(t)

    // Make HTTP requests to ts.baseURL
    resp, err := ts.client.Get(ts.baseURL + "/healthz")
    require.NoError(t, err)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

Available options for `startTestServer`:

- `withGeneratedCerts()` - Generate a test CA and certificate bundle
- `withRefresh()` - Trigger initial registry refresh (for readiness)
- `withMockRegistry(registry)` - Use a mock registry implementation
- `withLogLevel(level)` - Set server log level

### Coverage Goals

- **Overall**: >80%
- **Critical packages** (api, registry, authzen): >85%
- Run `make check-coverage` to verify

## Code Quality

### Pre-Commit Hook

A Git pre-commit hook runs automatically before each commit:

- Checks code formatting
- Runs `go vet`
- Runs tests for changed packages
- Checks for common issues

To bypass (not recommended):
```bash
git commit --no-verify
```

### Manual Checks

Before committing:

```bash
# Quick checks
make quick

# Full checks
make all
```

### Code Style

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting (automatic with `make fmt`)
- Run `golangci-lint` regularly
- Keep functions small and focused
- Write clear comments for exported functions
- Use meaningful variable names

### EditorConfig

The project includes `.editorconfig` for consistent formatting:

- Tabs for Go files (tab size: 4)
- LF line endings
- UTF-8 encoding
- Trim trailing whitespace

## Git Workflow

### Branching

```bash
# Create feature branch
git checkout -b feature/my-feature

# Work on your changes
...

# Run checks
make quick

# Commit (pre-commit hook runs automatically)
git commit -m "feat: Add new feature"

# Push
git push origin feature/my-feature
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

Examples:
```
feat: Add Prometheus metrics endpoints
fix: Correct certificate validation logic
docs: Update API documentation
test: Add tests for pipeline error handling
```

## VS Code Setup

### Recommended Extensions

Open the project in VS Code and install recommended extensions when prompted:

- Go (golang.go)
- EditorConfig (editorconfig.editorconfig)
- Makefile Tools (ms-vscode.makefile-tools)
- GitHub Actions (github.vscode-github-actions)
- YAML (redhat.vscode-yaml)
- Docker (ms-azuretools.vscode-docker)
- GitLens (eamodio.gitlens)

### Settings

Project settings are pre-configured in `.vscode/settings.json`:

- Format on save enabled
- Organize imports on save
- Go language server (gopls) with static analysis
- Test flags: `-v -race -count=1`
- Coverage decorations enabled

### Tasks

Press `Ctrl+Shift+B` (or `Cmd+Shift+B` on Mac) to see available tasks:

- **Build** - Compile the project
- **Test All** - Run all tests
- **Test Current Package** - Test the package you're editing
- **Lint** - Run linters
- **Coverage** - Generate coverage report

### Keyboard Shortcuts

- `F5` - Start debugging
- `Ctrl+Shift+B` - Run build task
- `Ctrl+Shift+T` - Run tests

## Debugging

### VS Code Debugging

Multiple debug configurations are available in `.vscode/launch.json`:

1. **Launch go-trust server** - Run server with example configuration
2. **Launch go-trust (custom args)** - Run with custom arguments
3. **Test Current File** - Debug tests in current file
4. **Test Current Package** - Debug all tests in package
5. **Test All Packages** - Debug entire test suite

Press `F5` to start debugging with the default configuration.

### Command Line Debugging

```bash
# Build with debug symbols
go build -gcflags="all=-N -l" -o gt-debug ./cmd/gt

# Run with delve
dlv exec ./gt-debug -- --etsi-cert-bundle /path/to/certs.pem --log-level debug
```

### Logging

Use structured logging:

```go
logger.Debug("Processing TSL",
    logging.F("tsl_id", id),
    logging.F("url", url))
```

Log levels:
- `debug` - Detailed information for debugging
- `info` - General informational messages
- `warn` - Warning messages
- `error` - Error messages
- `fatal` - Fatal errors (exits program)

## Performance

### Benchmarks

```bash
# Run all benchmarks
make bench

# Run specific benchmark
go test ./pkg/api -bench=BenchmarkMetricsMiddleware -benchmem

# Compare benchmarks
go test ./pkg/api -bench=. -benchmem > old.txt
# ... make changes ...
go test ./pkg/api -bench=. -benchmem > new.txt
benchcmp old.txt new.txt
```

### Profiling

```bash
# CPU profiling
go test ./pkg/api -cpuprofile=cpu.prof -bench=.
go tool pprof cpu.prof

# Memory profiling
go test ./pkg/api -memprofile=mem.prof -bench=.
go tool pprof mem.prof
```

### Performance Guidelines

- Minimize allocations in hot paths
- Use sync.Pool for frequently allocated objects
- Prefer value receivers for small structs
- Avoid unnecessary string conversions
- Use buffered channels appropriately
- Profile before optimizing

## Common Tasks

### Adding a New API Endpoint

1. Add handler in `pkg/api/api.go`
2. Register route in `RegisterAPIRoutes()`
3. Add tests in `pkg/api/api_test.go`
4. Update API documentation in `cmd/main.go`
5. Consider metrics (if appropriate)

### Adding a New Registry Type

1. Create registry in `pkg/registry/yourregistry/`
2. Implement `TrustRegistry` interface
3. Add tests
4. Register in main.go
5. Update documentation

### Updating Dependencies

```bash
# Update all dependencies
make deps

# Clean up go.mod
make tidy

# Verify
go mod verify
```

## Getting Help

- Check `make help` for available commands
- Read existing tests for examples
- Check [Go documentation](https://golang.org/doc/)
- Review [project README](README.md)
- Open an issue for questions

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

---

**Happy coding!** 🎉
