.PHONY: test build tidy check cover completion

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

check: build
	./rpctl generate -config config.example.yaml
	@if command -v sing-box >/dev/null; then sing-box check -c generated/config.json; else echo "sing-box not installed, skip"; fi
