# routeproxy

[Русский](README.md)

Console split proxy: **sing-box** as the dataplane and **`rpctl`** as the control plane. No VPN client or GUI on the server. homeproxy is not used at runtime.

Clients talk to a **mixed inbound** (SOCKS5 + HTTP on one port). Telegram Desktop should use `socks5h://`. On Android the same YAML builds a TUN profile for [SFA](https://sing-box.sagernet.org/clients/android/).

Do not commit `config.yaml`. Copy [`config.example.yaml`](config.example.yaml) and keep real UUIDs, keys, and tokens local. Generated sing-box JSON (`generated/`, `sfa.json`) is also gitignored.

## Architecture

```
client ── SOCKS5h/HTTP :listen ──► sing-box
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                      ru/direct    telegram       auto
                                      │         (urltest)
                                      ▼
                               VLESS / SSH / WG / SOCKS

rpctl checker :1443+ ── TCP failover MTProto ──► Bot API (optional)
rpctl generate / generate-sfa / why / add / completion
```

- **sing-box** forwards traffic from the generated JSON.
- **`rpctl generate`** builds that JSON from YAML: mixed inbound, split DNS, remote `.srs` rule-sets, urltest.
- **`rpctl generate-sfa`** uses the same routing with a `tun` inbound for Android VpnService.
- **`rpctl checker`** is not the dataplane; it only failovers MTProto (and reserve SOCKS) for a local Bot API.

## Zones

Rules are first-match:

1. sniff + hijack DNS
2. `routing.exceptions` (exact domain / suffix / CIDR → named outbound or zone)
3. private IPs → `direct`
4. google / youtube / instagram / twitter / facebook / discord → `auto`
5. Telegram (geosite-telegram) → `telegram`
6. `.ru` / `.рф` / `.xn--p1ai` / `.su` → `ru`
7. geosite-category-ru + geoip-ru → `ru`
8. everything else → `auto` (urltest)

`routing.ru: direct` sends all RU traffic direct (homeproxy-style). `routing.ru: ru` sends it through proxies with `purpose: [ru]` (rotators and the like).

Rotator for **specific** RU domains, rest of RU still direct:

```yaml
proxies:
  - name: ru-rotate
    purpose: [ru]
    type: socks
    server: rotator.example.com
    port: 1080
    username: user
    password: secret

routing:
  ru: direct
  exceptions:
    - match_domain_suffix: example.ru
      outbound: ru-rotate   # proxy name, not the ru zone
```

`outbound: ru` with `routing.ru: direct` resolves back to direct.

The SOCKS gateway rotates the egress IP, not routeproxy. Several `purpose: [ru]` proxies plus `routing.ru: ru` is a 3-minute urltest, not IP rotation.

## Ports

| Listen | Process | Used by |
|--------|---------|---------|
| `listen` in YAML (example `:1080`, Docker often `:8079`) | sing-box mixed | browsers, curl, Telegram Desktop (`socks5h://HOST:PORT`) |
| `checker.listen` `:1443` (+ `:1444`…) | `rpctl checker` | avbor telegram-bot-api, one secret per port |
| `checker.status_addr` `:18080` | `/healthz` `/metrics` | monitoring |

Always use **`socks5h://`** so DNS stays inside the split.

## YAML

Copy [`config.example.yaml`](config.example.yaml) → `config.yaml` (gitignored). Fields:

| Key | Meaning |
|-----|---------|
| `listen` | mixed SOCKS+HTTP |
| `generated_path` / `cache_dir` | sing-box JSON and cache.db |
| `proxies[]` | `vless`, `trojan`, `socks`, `http`, `ssh`, `wireguard` |
| `proxies[].purpose` | `auto`, `telegram`, `ru` |
| `proxies[].url` | `vless://`, `tg://socks`, `socks5://`, `t.me/socks` |
| `proxies[].transport` | `grpc` + `service_name` for VLESS Reality |
| `proxies[].config_file` | wg-quick `.conf` (keys are inlined into JSON) |
| `telegram_mtproto` | `t.me/proxy` / `tg://proxy` links |
| `routing.exceptions` | per-site override |
| `dns.direct_names` | resolve node hostnames via bootstrap, not auto |
| `alerts` | Telegram and SMTP together |
| `bot_api` | TDLib env when MTProto dies |
| `apply.commands` | commands run by `rpctl apply` |

`ROUTEPROXY_CONFIG` or `-config` sets the path. Defaults: `./config.yaml`, then `/etc/routeproxy/config.yaml`.

## Build

Go 1.23+ and [sing-box](https://github.com/SagerNet/sing-box/releases) 1.12+ on `PATH` (for `check` / `apply`).

```bash
go test ./...
go build -o rpctl ./cmd/rpctl
cp config.example.yaml config.yaml
./rpctl generate
./rpctl why ya.ru
./rpctl generate-sfa
```

Makefile: `make test`, `make build`, `make cover`, `make completion`, `make check`.

## rpctl commands

```
rpctl generate              YAML → sing-box JSON (mixed SOCKS)
rpctl generate-sfa          YAML → SFA JSON (TUN)
rpctl check                 generate + sing-box check
rpctl apply                 generate, check, apply.commands
rpctl add <url>             vless://, tg://socks, t.me/proxy, socks5://
rpctl telegram-urls         local SOCKS + MTProto links
rpctl why <host>            which outbound and why
rpctl probe                 GET checker /healthz
rpctl checker               MTProto TCP failover
rpctl completion bash|zsh   emit a completion script
rpctl help
```

Shared flag: `-config PATH`. `generate-sfa` also has `-out PATH` (`-` = stdout). `add`: `-purpose auto,telegram`, `-name NAME`.

```bash
./rpctl add 'https://t.me/proxy?server=...&port=443&secret=ee...'
./rpctl add 'tg://socks?server=...&port=1080&user=u&pass=p' -purpose auto,telegram
./rpctl generate-sfa -out ~/sfa.json
```

## Bash / zsh completion

Scripts are **generated from the command catalog** (`internal/cli`), not hand-edited.

```bash
make completion    # contrib/completions/rpctl.bash and contrib/completions/_rpctl
```

Or without files:

```bash
# bash
eval "$(rpctl completion bash)"
# or
source contrib/completions/rpctl.bash

# zsh
eval "$(rpctl completion zsh)"
# or
fpath+=("$PWD/contrib/completions")
autoload -U compinit && compinit
```

`TestContribMatchesGenerator` fails if committed scripts drift — run `make completion` again.

## Docker

`network_mode: host`. In container `config.yaml`:

- `listen: "0.0.0.0:8079"` (or another free port)
- `generated_path` / `cache_dir` as in [`deploy/config.docker.yaml`](deploy/config.docker.yaml)

```bash
docker compose up --build -d
```

The checker is off by default (`profiles: [checker]`):

```bash
docker compose --profile checker up -d
```

WireGuard endpoints need `cap_add: [NET_ADMIN]` and `/dev/net/tun` on the `routeproxy` service (already in compose). `--privileged` is not required. On the host: `sudo modprobe tun` if `/dev/net/tun` is missing.

If homeproxy already owns `:8079`, stop it first. If it is still enabled, it will steal the port after reboot — `systemctl disable homeproxy` when you stay on routeproxy.

SSH: mount the key into the container (`/etc/routeproxy/ssh`). WG: `/etc/wireguard/*.conf`; a missing file skips that outbound with a warning.

## systemd

```bash
sudo install -m 755 rpctl /usr/local/bin/rpctl
sudo install -m 755 "$(command -v sing-box)" /usr/local/bin/sing-box
sudo mkdir -p /etc/routeproxy /var/lib/routeproxy
sudo cp config.yaml /etc/routeproxy/config.yaml
# YAML: generated_path / cache_dir → /var/lib/routeproxy/...
sudo cp deploy/routeproxy.service deploy/routeproxy-checker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now routeproxy
# sudo systemctl enable --now routeproxy-checker   # if you need Bot API
```

```yaml
apply:
  commands:
    - ["systemctl", "restart", "routeproxy"]
```

The `routeproxy` unit has no `CAP_NET_ADMIN`. For a WG endpoint use Docker+TUN or add the capability to the unit.

## Android (SFA)

Same YAML, different inbound: TUN via VpnService, not SOCKS.

```bash
./rpctl generate-sfa                  # generated/sfa.json
./rpctl generate-sfa -out ~/sfa.json
```

SFA: [Play Store `io.nekohasekai.sfa`](https://play.google.com/store/apps/details?id=io.nekohasekai.sfa) or `SFA-*.apk` from [sing-box releases](https://github.com/SagerNet/sing-box/releases). Profiles → + → Import from file.

The SSH key is inlined into the JSON. If `private_key_path` is unreadable on this machine, that outbound is skipped (`warn:`). WG is read from `.conf` the same way as desktop generate. Run the generator where the keys are readable (`docker exec routeproxy rpctl generate-sfa` if the key is mounted in the container).

## Telegram

**Desktop client:** SOCKS5 `HOST:listen`, “for all connections”. The slot does not change. On Android with SFA, SOCKS is unnecessary — traffic goes through the VPN.

**Bot API** (TDLib-proxy image, [avbor/docker-telegram-bot-api](https://github.com/avbor/docker-telegram-bot-api)):

```
--tdlib-proxy-type=mtproto
--proxy-server=127.0.0.1
--proxy-port=1443
--proxy-secret=<group secret>
```

The secret must match `telegram_mtproto`. The checker TCP-forwards to the first healthy node. If every MTProto node is down longer than `alerts.mtproto_dead_for`, the checker writes SOCKS into `bot_api.env_file` and restarts Bot API when `restart_command` is set.

## Alerts

Cloud Telegram (`api.telegram.org` via SOCKS `listen`, `via: auto`) **and** SMTP from the config fire on the same event: one healthy MTProto left, zero, fallback/restore. Not via the local Bot API.

## Tests

```bash
go test ./...
make cover
```

Coverage includes the generator (mixed, SFA/TUN, gRPC/Reality, WG-quick, missing-file skips), `rpctl why`, URL parser, checker registry/healthz/metrics, SOCKS fallback, completion (bash/zsh + stale contrib), and TUN/CAP_NET_ADMIN host checks.

Optional live check: [`testdata/README.md`](testdata/README.md).

`sing-box check` tests skip when the binary is missing.

## Debugging

```bash
./rpctl why nalog.ru
./rpctl why google.com
./rpctl why example.su
./rpctl why rotator.test
```

Geo lists lie — pin a site with `routing.exceptions`.

## homeproxy

Not a dependency. The old SOCKS `:8079` can be a temporary `type: socks` upstream. Typical move: SSH `node-c` → `purpose: [auto]`, WG Sweden/Latvia → `type: wireguard` + `config_file`, `.ru` → `routing.ru: direct`, per-site directs → exceptions.
