FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /out/rpctl ./cmd/rpctl

FROM debian:bookworm-slim
ARG SING_BOX_VERSION=1.12.10
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar \
 && curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz" \
    | tar -xz -C /tmp \
 && mv /tmp/sing-box-*/sing-box /usr/local/bin/sing-box \
 && rm -rf /var/lib/apt/lists/* /tmp/sing-box-*
COPY --from=build /out/rpctl /usr/local/bin/rpctl
WORKDIR /etc/routeproxy
ENTRYPOINT ["/usr/local/bin/rpctl"]
CMD ["checker"]
