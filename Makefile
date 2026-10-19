GO       ?= go
EXAMPLE  := examples/sqlite
FUZZTIME ?= 60s

# The SQLite example is its own module so the driver stays out of the main
# go.mod. On macOS, binaries that link CoreFoundation (the driver does) must
# carry an LC_UUID load command; older Go linkers, such as Go 1.22.2's, omit
# it and the macOS 26 loader refuses the binary. The system linker adds it.
ifeq ($(shell uname -s),Darwin)
EXAMPLE_FLAGS := -ldflags=-linkmode=external
endif

.PHONY: all test race bench fuzz lint example

all: lint test race

test:
	$(GO) test ./...
	cd $(EXAMPLE) && $(GO) test $(EXAMPLE_FLAGS) ./...

race:
	$(GO) test -race ./...
	cd $(EXAMPLE) && $(GO) test -race $(EXAMPLE_FLAGS) ./...

bench:
	$(GO) test -run='^$$' -bench=. -benchmem ./...

fuzz:
	$(GO) test ./redact -run='^$$' -fuzz=FuzzRedact -fuzztime=$(FUZZTIME)

lint:
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	$(GO) vet ./...
	cd $(EXAMPLE) && $(GO) vet ./...

example:
	cd $(EXAMPLE) && $(GO) run $(EXAMPLE_FLAGS) .
