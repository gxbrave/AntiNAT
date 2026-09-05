SHELL := /usr/bin/env bash

MODULE := github.com/gxbrave/AntiNAT
VERSION ?= dev
COMMIT ?= unknown
DATE ?= unknown
LDFLAGS := -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE)/internal/buildinfo.Date=$(DATE)

.PHONY: all test vet build cross-build verify-evidence verify-evidence-parity check clean

all: check build

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/antinat-controller ./cmd/antinat-controller
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/antinat-agent ./cmd/antinat-agent

cross-build:
	GOOS=windows GOARCH=amd64 go build ./cmd/...

verify-evidence:
	GOWORK=off go test ./scripts -run TestValidateAcceptsValidEvidenceFixture -count=1

verify-evidence-parity:
	python3 scripts/verify-evidence-parity.py

check: test vet

clean:
	rm -rf bin
