#!/bin/sh
# Full verify-after-changes checklist. make check runs this, then generate.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

GOVULNCHECK_VERSION=${GOVULNCHECK_VERSION:-v1.9.0}
GOLANGCI_LINT_VERSION=${GOLANGCI_LINT_VERSION:-v2.15.0}

echo "== gofmt -s =="
unformatted=$(gofmt -s -l .)
if [ -n "$unformatted" ]; then
	printf '%s\n' "$unformatted"
	echo "gofmt -s: files above are not formatted" >&2
	exit 1
fi

echo "== go fix =="
before=$(git diff -- '*.go')
go fix ./...
after=$(git diff -- '*.go')
if [ "$before" != "$after" ]; then
	echo "go fix rewrote files; apply or revert the leftover work" >&2
	git diff -- '*.go'
	exit 1
fi

echo "== go vet =="
go vet ./...

echo "== go test =="
go test ./...

echo "== go build =="
go build -o /tmp/rpctl-check ./cmd/rpctl

echo "== golangci-lint =="
if command -v golangci-lint >/dev/null 2>&1; then
	golangci-lint run
else
	go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}" run
fi

echo "== govulncheck =="
if command -v govulncheck >/dev/null 2>&1; then
	govulncheck ./...
else
	go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...
fi
