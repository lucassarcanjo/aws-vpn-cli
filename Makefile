BINARY := awsvpn
PKG    := github.com/larcanjo/awsvpn
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date +%Y-%m-%d)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) \
           -X $(PKG)/internal/version.Commit=$(COMMIT) \
           -X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build install test vet vuln tidy vendor clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

install:
	go install -ldflags "$(LDFLAGS)" .

test:
	go test ./...

vet:
	go vet ./...

# Requires: go install golang.org/x/vuln/cmd/govulncheck@latest
vuln:
	govulncheck ./...

tidy:
	go mod tidy

vendor:
	go mod vendor

clean:
	rm -rf bin
