.PHONY: build test lint lint-forbidden-apis clean conformance trace-map sdk-test sdk-run

BINARY_NAME := epack-collector-aws
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
EPACK_VERSION = $(shell go list -m -f '{{.Version}}' github.com/locktivity/epack)
# Variables the collector reads credentials from, as conformance-secrets in
# .github/workflows/ci.yaml lists them. Conformance sets each to a canary
# value, fails if any output prints it, and checks that the rejected
# credential exits 3: with no config, the canary access keys reach STS.
CONFORMANCE_SECRETS := AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN
# Keeps a profile in the developer's environment, which the AWS SDK ranks
# above access keys, from signing a local run in to a real account.
CONFORMANCE_ENV := AWS_PROFILE= AWS_SESSION_TOKEN= AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true

# Build the collector binary for the current platform
build:
	go build -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME) ./cmd/$(BINARY_NAME)

# Build for all platforms
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME)-linux-amd64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME)-linux-arm64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME)-darwin-amd64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/$(BINARY_NAME)

# Run tests
test:
	go test -race -v ./...

# Lint code (downloads golangci-lint binary to match CI)
GOLANGCI_LINT_VERSION := v2.9.0
GOLANGCI_LINT := ./bin/golangci-lint

$(GOLANGCI_LINT):
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b ./bin $(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT) lint-forbidden-apis
	$(GOLANGCI_LINT) run ./...

# Fail the build if collector source references secret-reading AWS APIs.
lint-forbidden-apis:
	./scripts/check-forbidden-apis.sh

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*

# Conformance at the epack version go.mod pins, as CI runs it.
conformance: build
	$(CONFORMANCE_ENV) go run -tags conformance github.com/locktivity/epack/cmd/epack-conformance@$(EPACK_VERSION) collector ./$(BINARY_NAME) --level standard \
		$(if $(wildcard testdata/conformance.json),--config testdata/conformance.json) $(foreach s,$(CONFORMANCE_SECRETS),--secret $(s))

# Rewrites docs/schema/trace-map.json from the collectortest suites and the
# source, at the epack version go.mod pins, as CI checks it. Commit the result.
trace-map:
	go run -tags components github.com/locktivity/epack/cmd/epack@$(EPACK_VERSION) sdk map

# SDK development commands (requires epack with components build)
sdk-test: build
	epack sdk test ./$(BINARY_NAME)

sdk-run: build
	epack sdk run ./$(BINARY_NAME)
