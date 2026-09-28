# Optional live check

Mock SOCKS + checker:

```bash
docker compose -f testdata/docker-compose.integration.yml up --build
curl -sS http://127.0.0.1:18081/healthz
```

[Русский](README.md)
