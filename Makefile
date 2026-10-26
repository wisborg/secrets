# secrets -- the standard way to work with this code. Every target is a
# plain `go` invocation; `make` on its own lists them.

PKG ?=
RUN ?=

.DEFAULT_GOAL := help

## help: list these targets
help:
	@echo "secrets targets:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | awk -F': ' '{printf "  %-8s %s\n", $$1, $$2}'

## gates: gofmt, vet and test -- what must pass before a commit
gates:
	@printf 'gofmt: '
	@out=$$(gofmt -l $$(go list -f '{{.Dir}}' ./...)); \
	  if [ -n "$$out" ]; then echo "FAILED"; echo "$$out"; exit 1; else echo "clean"; fi
	@printf 'vet:   '
	@if go vet ./... >/dev/null 2>&1; then echo "clean"; else echo "FAILED"; go vet ./...; exit 1; fi
	@printf 'test:  '
	@if go test ./... >/dev/null 2>&1; then echo "all packages ok"; else echo "FAILED"; go test ./...; exit 1; fi

## test: run the tests, or narrow with PKG= and RUN=
test:
	go test $(if $(PKG),$(PKG),./...) $(if $(RUN),-run $(RUN),) -count=1

## race: the tests under the race detector, as CI runs them
race:
	go test -race ./... -count=1

.PHONY: help gates test race
