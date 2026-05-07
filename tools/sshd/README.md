# Minimal SSH Session Broker (MVP)

このプロジェクトは小規模な SSH セッションブローカーであり、`ssh(1)` の代替を目指すものではありません。
設計では、責務を明確に分離し、挙動を追いやすくすることを重視しています。

## 設計方針

サーバは責務を次の 2 つのプレーンに分けています。

- 制御プレーン: REST API のみ
- データプレーン: WebSocket によるバイト列ストリームのみ

SSH 接続そのものは、サーバ側で長寿命のリソースとして管理します。

## セッションモデル

- `POST /sessions` は 1 本の SSH TCP 接続と、PTY 付きの 1 つのシェルチャネルを作成します。
- 複数のクライアントが同じサーバ側 PTY にアタッチできます。
- PTY は各クライアントに属するのではなく、SSH セッションに属します。
- クライアントは、出力を見るためのビューであり、必要に応じて入力も送れる存在です。

サーバは意図的に複数の同時 writer を許可しています。
writer の調停は UI や運用上の責務とみなし、MVP の対象外としています。

## 認証と認可 (MVP)

2 種類のトークンを意図的に分離しています。

1. REST 認証トークン (identity)
- REST エンドポイントでのみ使います。
- 呼び出し元が誰であるかを表します。
- MVP ではメモリ上で照合します。

2. `attach_token` (capability)
- WebSocket でアタッチする際にのみ使います。
- 短寿命かつ使い切りです。
- 1 つのセッションに対して、1 つのモード (`writer` / `readonly`) の権限を与えます。

この 2 つは同じ意味ではなく、相互に置き換えられません。

## HTTP ステータス一覧

制御プレーンでは、認証・権限・上流 SSH 側の失敗をクライアントが判別しやすいように、限定した HTTP ステータスを使っています。

- `400 Bad Request`
	- リクエスト項目が不足している、または不正です。
	- 典型例: `host is required`, `username is required`, `password is required`

- `401 Unauthorized`
	- REST の Bearer トークンが無い、または不正です。
	- 典型例: `invalid auth token`

- `403 Forbidden`
	- REST 呼び出し元は認証済みですが、対象セッションの所有者ではありません。
	- 典型例: `not allowed for this session`

- `422 Unprocessable Content`
	- HTTP リクエスト自体は正しいものの、SSH 認証に失敗しました。
	- 典型例: `ssh dial failed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain`

- `502 Bad Gateway`
	- ブローカーが上流の SSH 接続または SSH セッション確立を完了できませんでした。
	- 典型例として、DNS 解決失敗、タイムアウト、接続拒否、SSH ではない応答、PTY / シェル開始失敗などがあります。

失敗時のレスポンス本文は、次の形式の JSON です。

```json
{
	"error": "..."
}
```

## API リファレンス

### GET /healthz

ヘルスチェック。認証不要。

**レスポンス** `200 OK`
```json
{ "status": "ok" }
```

---

### POST /sessions

SSH セッションを作成します。接続と PTY の確立まで同期的に行います。

**認証**: `Authorization: Bearer <token>` (REST トークン)

**リクエストボディ**

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `host` | string | ✓ | SSH サーバのホスト名または IP |
| `port` | number | ✓ | SSH ポート番号 |
| `username` | string | ✓ | SSH ユーザ名 |
| `password` | string | ✓ | SSH パスワード |
| `pty_cols` | number | | PTY の列数 (省略時 80) |
| `pty_rows` | number | | PTY の行数 (省略時 24) |

**レスポンス** `201 Created`
```json
{
  "session_id": "<uuid>",
  "writer_ws_url": "ws://host/ws/<session_id>?attach_token=<token>"
}
```

返却される `writer_ws_url` の `attach_token` は一度限り有効な writer トークンです。

**エラー**: `400` (入力不足) / `401` (REST トークン不正) / `422` (SSH 認証失敗) / `502` (接続失敗)

---

### DELETE /sessions/{session_id}

セッションを終了して削除します。

**認証**: `Authorization: Bearer <token>` (REST トークン、セッション所有者のみ)

**レスポンス** `200 OK`
```json
{ "status": "deleted" }
```

**エラー**: `401` / `403` (非所有者) / `404` (セッション不存在)

---

### POST /sessions/{session_id}/attach-tokens

追加の `attach_token` を発行します。デフォルトは readonly です。

**認証**: `Authorization: Bearer <token>` (REST トークン、セッション所有者のみ)

**リクエストボディ**

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `mode` | string | | `"readonly"` (省略時) または `"writer"` |
| `ttl_seconds` | number | | トークン有効期間 (秒、最大 300) |

**レスポンス** `201 Created`
```json
{
  "session_id": "<session_id>",
  "mode": "readonly",
  "ws_url": "ws://host/ws/<session_id>?attach_token=<token>"
}
```

**エラー**: `400` / `401` / `403`

---

### POST /sessions/{session_id}/resize

セッションの PTY サイズを変更します。

**認証**: `Authorization: Bearer <token>` (REST トークン、セッション所有者のみ)

**リクエストボディ**

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `cols` | number | ✓ | 列数 |
| `rows` | number | ✓ | 行数 |

**レスポンス** `200 OK`
```json
{ "status": "resized" }
```

**エラー**: `400` / `401` / `403`

---

### GET /ws/{session_id}?attach_token={token}

WebSocket アタッチ。`attach_token` は `attach-tokens` エンドポイントで発行した使い切りトークンです。

トークンが writer 権限を持つ場合、送信バイト列はそのままリモート PTY への入力となります。
readonly の場合、送信バイト列はサーバ側で無視されます。

**エラー**: `401` (トークン不正・使用済み) / `404` (セッション不存在)

---

## WebSocket アタッチフロー

ブラウザの WebSocket クライアントは、任意のヘッダを安定して付けられないことがあります。
そのため REST 側で `attach_token` を発行し、認可済み URL を返します。

`wss://host/ws/{session_id}?attach_token=XXXX`

WebSocket ハンドラの役割は意図的に限定しています。

- `attach_token` を検証する
- セッションとモード (`writer` / `readonly`) を解決する
- 正常に消費できたトークンを無効化する
- 生のバイト列をストリームする

ここでは REST のような完全な認証処理は行いません。

## Writer / Readonly モデル

- セッション作成時に返る最初のトークンは writer です。
- 追加で発行するアタッチトークンは、デフォルトで readonly です。
- 制御プレーン経由で追加の writer アタッチも許可できます。
- 複数 writer は設計上許可されています。

## PTY とリサイズ

- アタッチしている全クライアントは同じ PTY 出力を見ます。
- リサイズはセッション操作 (`session.Resize(cols, rows)`) として扱います。
- MVP では、リサイズは REST 制御プレーンから実行します。

このため、リサイズの責務は WebSocket のフレーミング詳細とは切り離されています。

## SSH 認証の対象範囲 (MVP)

現時点で対応しているもの:

- ユーザ名 / パスワード

現時点で対応していないもの:

- SSH 鍵
- Agent forwarding
- `known_hosts` 検証

認証処理はインターフェースの背後に抽象化されているため、今後方式を増やしても呼び出し側を大きく変えずに拡張できます。

## 非目標

初期版では、次の機能は意図的に実装していません。

- OAuth / JWT の検証
- SSH 鍵管理
- writer のロック / 調停
- SCP / SFTP
- tmux のような多重化

## 今後の拡張候補

自然な拡張ポイントとして、次のようなものがあります。

- SSH 認証方式の追加
- セッションメタデータの永続化
- attach_token 発行ポリシーの詳細化
- オリジンチェックの追加や、より厳密なネットワークハードニング

## 最小手動検証

以下は MVP フローの最小限のエンドツーエンド確認手順です。

1. サーバを起動する
2. REST 経由で SSH セッションを 1 つ作成する
3. WebSocket で writer クライアントを 1 つアタッチする
4. REST 経由で共有 PTY をリサイズする
5. 必要に応じて readonly クライアントをアタッチする

以下の例では、次を前提にしています。

- ブローカーは `http://localhost:8080` で動作している
- 初期 REST トークンは `dev-token`
- 到達可能な SSH サーバが `127.0.0.1:22` に存在する
- SSH アカウントは `demo` / `demo-password`

### 1. ブローカーを起動する

`tools/sshd` で次を実行します。

```powershell
go run .
```

listen address と bootstrap REST auth token を示すログが出力されれば起動成功です。

### 2. curl でセッションを作成する

```powershell
curl.exe -s -X POST "http://localhost:8080/sessions" ^
	-H "Authorization: Bearer dev-token" ^
	-H "Content-Type: application/json" ^
	--data-raw "{\"host\":\"127.0.0.1\",\"port\":22,\"username\":\"demo\",\"password\":\"demo-password\",\"pty_cols\":80,\"pty_rows\":24}"
```

期待されるレスポンスの形:

```json
{
	"session_id": "...",
	"writer_ws_url": "ws://localhost:8080/ws/...?..."
}
```

`session_id` と `writer_ws_url` を控えておきます。

代表的な失敗レスポンス:

- REST トークン不正 (`401 Unauthorized`)

```json
{
	"error": "invalid auth token"
}
```

- SSH 認証失敗 (`422 Unprocessable Content`)

```json
{
	"error": "ssh dial failed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"
}
```

- 上流 SSH 接続失敗 (`502 Bad Gateway`)

```json
{
	"error": "ssh dial failed: dial tcp 127.0.0.1:22: connect: connection refused"
}
```

### 3. WebSocket で writer クライアントをアタッチする

`wscat` がある場合は次を実行できます。

```powershell
npx wscat -c "<writer_ws_url>"
```

この最初のアタッチ URL は writable なので、入力した内容はそのままリモートの SSH PTY に転送されます。

`wscat` が無い場合は、ブラウザ側の WebSocket テスターや短い Node スクリプトでも構いません。
重要なのは、URL に認可済みの `attach_token` が含まれていることです。

### 4. REST で PTY をリサイズする

```powershell
curl.exe -s -X POST "http://localhost:8080/sessions/<session_id>/resize" ^
	-H "Authorization: Bearer dev-token" ^
	-H "Content-Type: application/json" ^
	--data-raw "{\"cols\":120,\"rows\":40}"
```

期待されるレスポンス:

```json
{
	"status": "resized"
}
```

これは、リサイズが WebSocket のフレーム仕様ではなく、制御プレーンの責務として扱われていることを示します。

### 5. readonly のアタッチトークンを発行する

```powershell
curl.exe -s -X POST "http://localhost:8080/sessions/<session_id>/attach-tokens" ^
	-H "Authorization: Bearer dev-token" ^
	-H "Content-Type: application/json" ^
	--data-raw "{\"mode\":\"readonly\"}"
```

期待されるレスポンスの形:

```json
{
	"session_id": "...",
	"mode": "readonly",
	"ws_url": "ws://localhost:8080/ws/...?..."
}
```

同じ WebSocket クライアントで `ws_url` に接続すると、writer クライアントと同じ PTY 出力を受け取れます。
一方で、この readonly クライアントから送った入力はサーバ側で無視されます。

### 6. セッションを削除する

```powershell
curl.exe -s -X DELETE "http://localhost:8080/sessions/<session_id>" ^
	-H "Authorization: Bearer dev-token"
```

期待されるレスポンス:

```json
{
	"status": "deleted"
}
```

## この README で確認できること

- REST がサーバ側 SSH リソースの作成と管理を担当していること
- WebSocket は既存セッションに対するアタッチ専用であること
- `attach_token` は呼び出し元の identity ではなく capability として機能すること
- writer / readonly の振る舞いがアタッチ済みクライアントごとに管理されること
- PTY リサイズが制御プレーン操作として扱われていること
