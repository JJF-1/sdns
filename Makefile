GO ?= go
BIN = sdns
MODULE := $(shell $(GO) list -m)
PKGS := $(shell $(GO) list ./... | grep -v -x "$(MODULE)")

all: generate tidy test build

.PHONY: test
test:
	$(GO) test -v -race -covermode=atomic -coverprofile=coverage.out $(PKGS)

.PHONY: generate
generate:
	$(GO) generate ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: build
build:
	$(GO) build

.PHONY: clean
clean:
	rm -f $(BIN)
	rm -f coverage.out
