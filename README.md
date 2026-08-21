# go-secretseal

应用层信封加密密封盒：DEK 封进密钥环、Seal/Open、密钥轮换与吊销、附加 AEAD。配套 `seald` 管理页。

## Build / Test

```bash
go build ./...
go test ./... -count=1
```

## Daemon

```bash
go run ./cmd/seald -addr :8104 -web web
```
