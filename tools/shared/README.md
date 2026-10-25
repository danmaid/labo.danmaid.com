# shared

Cisco コンソール共有を起点にした汎用ストリーム共有基盤の MVP 実装です。

## 使い方

```bash
go run ./cmd/shared -config examples/config.yaml
```

## health

```bash
curl http://localhost:8080/healthz
```

## endpoint 生成

```bash
curl -X POST http://localhost:8080/api/v1/endpoint/ssh -d '{"args":"-tt user@host"}'
```

## websocket 接続

```bash
# 任意のクライアントで /api/v1/ws/{id} へ接続
# 例: websocket-id = ws-1
```

## topology 起動

```bash
curl -X POST http://localhost:8080/api/v1/topology/ssh -d '{"ssh-id":"ssh-1","websocket-id":"ws-1"}'
```

## ビルド

```bash
go build ./...
```
