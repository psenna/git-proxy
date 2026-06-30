# git-proxy development Makefile.
# Targets mirror the CI commands in .github/workflows/ci.yml so that
# `make <target>` locally reproduces what the pipeline runs.

GO ?= go
GOLANGCI_LINT ?= golangci-lint
GOVULNCHECK ?= govulncheck

.PHONY: all vet test lint build vulncheck cover clean

all: lint build test vulncheck

## vet: run go vet across all packages
vet:
	$(GO) vet ./...

## test: run go vet then the race-enabled test suite with coverage
test: vet
	$(GO) test -race -coverprofile=cover.out ./...

## lint: run golangci-lint with the project config
lint:
	$(GOLANGCI_LINT) run

## build: compile all packages and commands
build:
	$(GO) build ./...

## vulncheck: scan the module for known vulnerabilities
vulncheck:
	$(GOVULNCHECK) ./...

## cover: display coverage summary from the last test run
cover:
	$(GO) tool cover -func=cover.out

clean:
	rm -f cover.out