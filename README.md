# routeproxy

[English](README.en.md)

Консольный split-прокси: **sing-box** как dataplane и **`rpctl`** как контроль. Без VPN-клиента и GUI на сервере. homeproxy в runtime не используется.

Клиенты ходят в **mixed inbound** (SOCKS5 + HTTP на одном порту). Telegram Desktop — через `socks5h://`. На Android тот же YAML собирается в TUN-профиль для [SFA](https://sing-box.sagernet.org/clients/android/).

## Как устроено

```
клиент ── SOCKS5h/HTTP :listen ──► sing-box
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                      ru/direct    telegram       auto
                                      │         (urltest)
                                      ▼
                               VLESS / SSH / WG / SOCKS

rpctl checker :1443+ ── TCP failover MTProto ──► Bot API (опционально)
rpctl generate / generate-sfa / why / add / completion
```

- **sing-box** проксирует трафик по сгенерированному JSON.
- **`rpctl generate`** собирает JSON из YAML: mixed inbound, split DNS, remote `.srs`, urltest.
- **`rpctl generate-sfa`** — тот же роутинг, inbound `tun` для VpnService.
- **`rpctl checker`** — не dataplane; только MTProto (и reserve SOCKS) для local Bot API.

## Зоны

Порядок правил (раньше — важнее):

1. sniff + hijack DNS
2. `routing.exceptions` (конкретный домен / суффикс / CIDR → outbound по имени или зоне)
3. private IP → `direct`
4. google / youtube / instagram / twitter / facebook / discord → `auto`
5. Telegram (geosite-telegram) → группа `telegram`
6. `.ru` / `.рф` / `.xn--p1ai` / `.su` → зона `ru`
7. geosite-category-ru + geoip-ru → зона `ru`
8. остальное → `auto` (urltest)

`routing.ru: direct` — весь RU напрямую (как homeproxy). `routing.ru: ru` — через прокси с `purpose: [ru]` (ротатор и т.п.).

Исключение на **отдельные** RU-домены через ротатор, остальной RU напрямую:

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
      outbound: ru-rotate   # имя прокси, не зона ru
```

`outbound: ru` при `routing.ru: direct` снова уйдёт в direct.

Ротацию внешнего IP делает SOCKS-шлюз, не routeproxy. Несколько `purpose: [ru]` + `routing.ru: ru` — это urltest раз в 3 минуты, не смена IP.

## Порты

| Слушать | Кто | Для кого |
|---------|-----|----------|
| `listen` в YAML (пример `:1080`, Docker часто `:8079`) | sing-box mixed | браузер, curl, Telegram Desktop (`socks5h://HOST:PORT`) |
| `checker.listen` `:1443` (+ `:1444`…) | `rpctl checker` | avbor telegram-bot-api, один secret на порт |
| `checker.status_addr` `:18080` | `/healthz` `/metrics` | мониторинг |

Клиентам указывайте **`socks5h://`**, иначе DNS обойдёт split.

## Схема YAML

Скопируйте [`config.example.yaml`](config.example.yaml) → `config.yaml` (файл в `.gitignore`). Поля:

| Ключ | Смысл |
|------|--------|
| `listen` | mixed SOCKS+HTTP |
| `generated_path` / `cache_dir` | JSON и cache.db sing-box |
| `proxies[]` | `vless`, `trojan`, `socks`, `http`, `ssh`, `wireguard` |
| `proxies[].purpose` | `auto`, `telegram`, `ru` |
| `proxies[].url` | `vless://`, `tg://socks`, `socks5://`, `t.me/socks` |
| `proxies[].transport` | `grpc` + `service_name` для VLESS Reality |
| `proxies[].config_file` | wg-quick `.conf` (ключи вшиваются в JSON) |
| `telegram_mtproto` | ссылки `t.me/proxy` / `tg://proxy` |
| `routing.exceptions` | точечный override |
| `dns.direct_names` | резолв имён узлов через bootstrap, не через auto |
| `alerts` | Telegram + SMTP одновременно |
| `alerts.forbid_direct` | запрет ISP/`direct` для алертов (включая ретрай 429) |
| `bot_api` | env для TDLib при падении MTProto |
| `apply.commands` | что выполнить в `rpctl apply` |

`ROUTEPROXY_CONFIG` или `-config` задаёт путь. Поиск по умолчанию: `./config.yaml`, затем `/etc/routeproxy/config.yaml`.

## Сборка

Нужны Go 1.23+ и [sing-box](https://github.com/SagerNet/sing-box/releases) 1.12+ в `PATH` (для `check` / `apply`).

```bash
go test ./...
go build -o rpctl ./cmd/rpctl
cp config.example.yaml config.yaml
./rpctl generate
./rpctl why ya.ru
./rpctl generate-sfa
```

Makefile: `make test`, `make build`, `make cover`, `make completion`, `make check`.

## Команды rpctl

```
rpctl generate              YAML → sing-box JSON (mixed SOCKS)
rpctl generate-sfa          YAML → SFA JSON (TUN)
rpctl check                 generate + sing-box check
rpctl apply                 generate, check, apply.commands
rpctl add <url>             vless://, tg://socks, t.me/proxy, socks5://
rpctl telegram-urls         локальный SOCKS + MTProto-ссылки
rpctl why <host>            какой outbound и почему
rpctl probe                 GET /healthz чекера
rpctl checker               MTProto TCP-failover
rpctl completion bash|zsh   скрипт автодополнения в stdout
rpctl help
```

Общий флаг: `-config PATH`. У `generate-sfa` ещё `-out PATH` (`-` = stdout). У `add`: `-purpose auto,telegram`, `-name NAME`.

```bash
./rpctl add 'https://t.me/proxy?server=...&port=443&secret=ee...'
./rpctl add 'tg://socks?server=...&port=1080&user=u&pass=p' -purpose auto,telegram
./rpctl generate-sfa -out ~/sfa.json
```

## Автодополнение bash / zsh

Скрипты **генерируются из каталога команд** (`internal/cli`), а не правятся руками.

```bash
make completion    # contrib/completions/rpctl.bash и contrib/completions/_rpctl
```

Либо без файлов:

```bash
# bash
eval "$(rpctl completion bash)"
# или
source contrib/completions/rpctl.bash

# zsh
eval "$(rpctl completion zsh)"
# или
fpath+=("$PWD/contrib/completions")
autoload -U compinit && compinit
```

Тест `TestContribMatchesGenerator` падает, если committed-скрипты отстали от генератора — снова `make completion`.

## Docker

`network_mode: host`. В `config.yaml` для контейнера:

- `listen: "0.0.0.0:8079"` (или другой свободный порт)
- `generated_path` / `cache_dir` как в [`deploy/config.docker.yaml`](deploy/config.docker.yaml)

Локальная сборка:

```bash
docker compose up --build -d
```

CI на `main` собирает образ и публикует в [GHCR](https://github.com/SomniSom/routeproxy/pkgs/container/routeproxy): `ghcr.io/somnisom/routeproxy:latest` и `sha-<short>`. После этого на хосте без пересборки:

```bash
make deploy
# или
docker compose -f docker-compose.yml -f deploy/compose.pull.yml pull
docker compose -f docker-compose.yml -f deploy/compose.pull.yml up -d --no-build
```

Первый pull с GHCR: пакет должен быть **Public** (пакет → Package settings → Change visibility). Для приватного: `echo $GITHUB_TOKEN | docker login ghcr.io -u USER --password-stdin`.

Удалённый деплой по SSH: Actions → ci → Run workflow → Deploy. Тянется тег `sha-<short>` этого запуска, не обязательно `:latest`. Секреты: `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`, `DEPLOY_PATH` (каталог с compose и `config.yaml` на хосте).

Чекер по умолчанию не стартует (`profiles: [checker]`):

```bash
docker compose --profile checker up -d
```

WireGuard endpoint: контейнеру `routeproxy` нужны `cap_add: [NET_ADMIN]` и `/dev/net/tun` (уже в compose). `--privileged` не нужен. На хосте: `sudo modprobe tun`, если нет `/dev/net/tun`.

Если порт занят homeproxy (`:8079`), его сервис нужно остановить, иначе bind не встанет. После ребута enabled homeproxy снова займёт порт — `systemctl disable homeproxy`, если оставляете routeproxy.

SSH: ключ монтируется в контейнер (`/etc/routeproxy/ssh`). WG: `/etc/wireguard/*.conf`; нет файла — generate пропускает outbound с предупреждением.

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
# sudo systemctl enable --now routeproxy-checker   # если нужен Bot API
```

```yaml
apply:
  commands:
    - ["systemctl", "restart", "routeproxy"]
```

Юнит `routeproxy` без `CAP_NET_ADMIN`. Для WG endpoint либо Docker с TUN, либо добавить capability в unit.

## Android (SFA)

Тот же YAML, другой inbound: TUN через VpnService, не SOCKS.

```bash
./rpctl generate-sfa                  # generated/sfa.json
./rpctl generate-sfa -out ~/sfa.json
```

SFA: [Play Store `io.nekohasekai.sfa`](https://play.google.com/store/apps/details?id=io.nekohasekai.sfa) или APK `SFA-*.apk` из [релизов sing-box](https://github.com/SagerNet/sing-box/releases). Profiles → + → Import from file.

SSH-ключ вшивается в JSON. Если `private_key_path` на этой машине не читается, outbound пропускается (`warn:`). WG берётся из `.conf`, как в обычном generate. Генерируйте там, где ключи доступны (`docker exec routeproxy rpctl generate-sfa`, если ключ смонтирован в контейнер).

## Telegram

**Клиент (Desktop):** SOCKS5 `HOST:listen`, «для всех соединений». Слот не меняется. На Android при SFA SOCKS не нужен — трафик идёт в VPN.

**Bot API** (образ с TDLib-прокси, [avbor/docker-telegram-bot-api](https://github.com/avbor/docker-telegram-bot-api)):

```
--tdlib-proxy-type=mtproto
--proxy-server=127.0.0.1
--proxy-port=1443
--proxy-secret=<secret группы>
```

Secret = `telegram_mtproto`. Чекер форвардит TCP на первый живой узел. Если все MTProto мертвы дольше `alerts.mtproto_dead_for`, checker пишет SOCKS в `bot_api.env_file` и при заданном `restart_command` перезапускает Bot API.

## Алерты

Telegram (`api.telegram.org` через SOCKS `listen`, `via: auto`) **и** SMTP из конфига — оба канала на одно событие: остался 1 живой MTProto, ноль, fallback/restore. Не через local Bot API. HTTP 429 от Telegram повторяется через другой `via` (`auto` ↔ `direct`). `alerts.forbid_direct: true` полностью запрещает `direct`: алерты только через SOCKS, 429 на `direct` не уходит.

## Тесты

```bash
go test ./...
make cover
```

Покрытие: генератор (mixed, SFA/TUN, gRPC/Reality, WG-quick, skip missing files), `rpctl why`, парсер URL, checker registry/healthz/metrics, fallback SOCKS, completion (bash/zsh + stale contrib), hostcheck TUN/CAP_NET_ADMIN.

Опциональный live-check: [`testdata/README.md`](testdata/README.md).

`sing-box check` в тестах пропускается, если бинарника нет.

## Отладка

```bash
./rpctl why nalog.ru
./rpctl why google.com
./rpctl why example.su
./rpctl why rotator.test
```

Geo-листы врут — правьте сайт через `routing.exceptions`.

## homeproxy

Не зависимость. Старый SOCKS `:8079` можно временно указать как `type: socks`. Перенос типичный: SSH `node-c` → `purpose: [auto]`, WG Sweden/Latvia → `type: wireguard` + `config_file`, `.ru` → `routing.ru: direct`, точечные direct — exceptions.
