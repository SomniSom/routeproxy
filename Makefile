.PHONY: test build tidy check cover completion image deploy

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

completion:
	mkdir -p contrib/completions
	go run ./cmd/rpctl completion bash > contrib/completions/rpctl.bash
	go run ./cmd/rpctl completion zsh > contrib/completions/_rpctl

image:
	docker build -t $(IMAGE) .

deploy:
	$(COMPOSE_PULL) pull
	$(COMPOSE_PULL) up -d --no-build

check: build
	./rpctl generate -config config.example.yaml
	@if command -v sing-box >/dev/null; then sing-box check -c generated/config.json; else echo "sing-box not installed, skip"; fi
