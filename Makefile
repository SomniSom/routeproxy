.PHONY: test build tidy check verify cover completion image deploy fmt fix vet lint vuln

IMAGE ?= ghcr.io/somnisom/routeproxy:latest
COMPOSE_PULL := docker compose -f docker-compose.yml -f deploy/compose.pull.yml

build:
	go build -o rpctl ./cmd/rpctl

test:
	go test ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

tidy:
	go mod tidy

fmt:
	@unformatted=$$(gofmt -s -l .); if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi

fix:
	go fix ./...

vet:
	go vet ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

verify:
	sh scripts/check.sh

completion:
	mkdir -p contrib/completions
	go run ./cmd/rpctl completion bash > contrib/completions/rpctl.bash
	go run ./cmd/rpctl completion zsh > contrib/completions/_rpctl

image:
	docker build -t $(IMAGE) .

deploy:
	$(COMPOSE_PULL) pull
	$(COMPOSE_PULL) up -d --no-build

check: verify build
	./rpctl generate -config config.example.yaml
	@if command -v sing-box >/dev/null; then sing-box check -c generated/config.json; else echo "sing-box not installed, skip"; fi
