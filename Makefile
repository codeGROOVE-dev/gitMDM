.PHONY: all build server agent clean test lint run-server run-agent help

GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

SERVER_BINARY=./out/gitmdm-server
AGENT_BINARY=./out/gitmdm-agent
SERVER_PATH=./cmd/server
AGENT_PATH=./cmd/agent

BUILD_FLAGS=-ldflags="-s -w" -trimpath

all: build

build: server agent

server:
	$(GOBUILD) $(BUILD_FLAGS) -o $(SERVER_BINARY) $(SERVER_PATH)

agent:
	$(GOBUILD) $(BUILD_FLAGS) -o $(AGENT_BINARY) $(AGENT_PATH)

clean:
	$(GOCLEAN)
	rm -f $(SERVER_BINARY)
	rm -f $(AGENT_BINARY)

test:
	$(GOTEST) -v ./...

deps:
	$(GOMOD) download
	$(GOMOD) tidy

run-server: server
	$(SERVER_BINARY) -git=/tmp/gitmdm-repo

run-agent: agent
	$(AGENT_BINARY) -server=http://localhost:8080

build-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(SERVER_BINARY)-linux-amd64 $(SERVER_PATH)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(AGENT_BINARY)-linux-amd64 $(AGENT_PATH)

build-darwin:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(SERVER_BINARY)-darwin-amd64 $(SERVER_PATH)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(AGENT_BINARY)-darwin-amd64 $(AGENT_PATH)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(BUILD_FLAGS) -o $(SERVER_BINARY)-darwin-arm64 $(SERVER_PATH)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(BUILD_FLAGS) -o $(AGENT_BINARY)-darwin-arm64 $(AGENT_PATH)

build-freebsd:
	GOOS=freebsd GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(SERVER_BINARY)-freebsd-amd64 $(SERVER_PATH)
	GOOS=freebsd GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(AGENT_BINARY)-freebsd-amd64 $(AGENT_PATH)

build-openbsd:
	GOOS=openbsd GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(SERVER_BINARY)-openbsd-amd64 $(SERVER_PATH)
	GOOS=openbsd GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(AGENT_BINARY)-openbsd-amd64 $(AGENT_PATH)

build-all: build-linux build-darwin build-freebsd build-openbsd

ko-build:
	ko build --bare ./cmd/server

ko-publish:
	ko build ./cmd/server

help:
	@echo "Available targets:"
	@echo "  make build       - Build both server and agent"
	@echo "  make server      - Build server binary"
	@echo "  make agent       - Build agent binary"
	@echo "  make clean       - Remove binaries"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Run linters"
	@echo "  make deps        - Download dependencies"
	@echo "  make run-server  - Build and run server locally"
	@echo "  make run-agent   - Build and run agent locally"
	@echo "  make build-all   - Build for all platforms"
	@echo "  make ko-build    - Build server container with ko"
	@echo "  make ko-publish  - Publish server container with ko"

# BEGIN: lint-install - POSIX-compliant version
# Works with both BSD make and GNU make

.PHONY: lint
lint: _lint

# Use simple assignment for maximum compatibility
LINT_ARCH != uname -m || echo x86_64
LINT_OS != uname || echo Darwin
LINT_ROOT = .

LINTERS =
FIXERS =

GOLANGCI_LINT_CONFIG = $(LINT_ROOT)/.golangci.yml
GOLANGCI_LINT_VERSION = v2.3.1
GOLANGCI_LINT_BIN = $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)

$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $(GOLANGCI_LINT_BIN)

LINTERS += golangci-lint-lint
golangci-lint-lint: $(GOLANGCI_LINT_BIN)
	find . -name go.mod -execdir $(GOLANGCI_LINT_BIN) run -c $(GOLANGCI_LINT_CONFIG) \;

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	find . -name go.mod -execdir $(GOLANGCI_LINT_BIN) run -c $(GOLANGCI_LINT_CONFIG) --fix \;

YAMLLINT_VERSION = 1.37.1
YAMLLINT_ROOT = $(LINT_ROOT)/out/linters/yamllint-$(YAMLLINT_VERSION)
YAMLLINT_BIN = $(YAMLLINT_ROOT)/dist/bin/yamllint

$(YAMLLINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yamllint-*
	curl -sSfL https://github.com/adrienverge/yamllint/archive/refs/tags/v$(YAMLLINT_VERSION).tar.gz | tar -C $(LINT_ROOT)/out/linters -zxf -
	cd $(YAMLLINT_ROOT) && (pip3 install --target dist . || pip install --target dist .)

LINTERS += yamllint-lint
yamllint-lint: $(YAMLLINT_BIN)
	PYTHONPATH=$(YAMLLINT_ROOT)/dist $(YAMLLINT_BIN) .

.PHONY: _lint $(LINTERS)
_lint: $(LINTERS)

.PHONY: fix $(FIXERS)
fix: $(FIXERS)

# END: lint-install