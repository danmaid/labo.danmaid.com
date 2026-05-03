# Minimal SSH Session Broker (MVP)

This project is a small SSH session broker, not a replacement for ssh(1).
Its design favors clarity and explicit separation of responsibilities.

## Design Intent

The server separates responsibilities into two planes:

- Control plane: REST API only
- Data plane: WebSocket byte streaming only

SSH is managed server-side as a long-lived resource.

## Session Model

- `POST /sessions` creates one SSH TCP connection and one shell channel with PTY.
- Multiple clients can attach to the same server-side PTY.
- PTY belongs to the SSH session, not to each client.
- Clients are only views and optional input devices.

The server allows multiple concurrent writers intentionally.
Writer arbitration is a UI/human-level concern and is out of scope for MVP.

## Authentication and Authorization (MVP)

Two token types are intentionally separate:

1. REST auth token (identity)
- Used only by REST endpoints.
- Represents who is calling.
- In-memory lookup in MVP.

2. attach_token (capability)
- Used only when attaching through WebSocket.
- Short-lived and one-time use.
- Grants permission for one session and one mode (writer/readonly).

These concepts are not interchangeable.

## WebSocket Attach Flow

Browser WebSocket clients cannot set arbitrary headers reliably.
For this reason, REST issues an attach_token and returns a fully authorized URL:

`wss://host/ws/{session_id}?attach_token=XXXX`

WebSocket handler behavior is intentionally narrow:

- Validate attach_token
- Resolve session and writable/readonly mode
- Invalidate token after successful consume
- Stream raw bytes

It does not perform full REST-style authentication.

## Writer and Readonly Model

- The initial token from session creation is writer.
- Additional attach tokens default to readonly.
- Optional writer attaches are allowed through control plane.
- Multiple writers are allowed by design.

## PTY and Resize

- All attached clients see the same PTY output.
- Resize is a session action (`session.Resize(cols, rows)`).
- In this MVP, resize is exposed via REST control plane.

Resize logic is kept separate from WebSocket framing details.

## SSH Authentication Scope (MVP)

Supported now:

- Username/password

Not supported now:

- SSH keys
- Agent forwarding
- known_hosts verification

Authentication is abstracted behind an interface so future methods can be added
without changing calling code.

## Non-goals

Initial version intentionally does not implement:

- OAuth or JWT validation
- SSH key management
- Writer locking/arbitration
- SCP or SFTP
- tmux-like multiplexing

## Future Extensions

Natural extension points include:

- Additional SSH auth strategies
- Persistent session metadata storage
- Fine-grained policy for attach token issuance
- Optional origin checks and stricter network hardening

## Minimal Manual Verification

This is a small end-to-end check for the MVP flow:

1. Start the server.
2. Create one SSH session through REST.
3. Attach one writer client through WebSocket.
4. Resize the shared PTY through REST.
5. Optionally attach a readonly client.

The examples below assume:

- The broker is running on `http://localhost:8080`
- The bootstrap REST token is `dev-token`
- A reachable SSH server exists at `127.0.0.1:22`
- The SSH account is `demo` / `demo-password`

### 1. Start the broker

From `tools/sshd`:

```powershell
go run .
```

You should see a log line showing the listen address and the bootstrap REST auth token.

### 2. Create a session with curl

```powershell
curl.exe -s -X POST "http://localhost:8080/sessions" ^
	-H "Authorization: Bearer dev-token" ^
	-H "Content-Type: application/json" ^
	--data-raw "{\"host\":\"127.0.0.1\",\"port\":22,\"username\":\"demo\",\"password\":\"demo-password\",\"pty_cols\":80,\"pty_rows\":24}"
```

Expected response shape:

```json
{
	"session_id": "...",
	"writer_ws_url": "ws://localhost:8080/ws/...?..."
}
```

Save both `session_id` and `writer_ws_url`.

### 3. Attach the writer client through WebSocket

If you have `wscat`:

```powershell
npx wscat -c "<writer_ws_url>"
```

Anything you type is forwarded to the remote SSH PTY because this first attach URL is writable.

If you do not have `wscat`, a browser-side WebSocket tester or a short Node script can be used instead.
The important part is that the URL already contains the authorized `attach_token`.

### 4. Resize the PTY through REST

```powershell
curl.exe -s -X POST "http://localhost:8080/sessions/<session_id>/resize" ^
	-H "Authorization: Bearer dev-token" ^
	-H "Content-Type: application/json" ^
	--data-raw "{\"cols\":120,\"rows\":40}"
```

Expected response:

```json
{
	"status": "resized"
}
```

This demonstrates that resize is handled on the control plane rather than as a WebSocket framing concern.

### 5. Issue a readonly attach token

```powershell
curl.exe -s -X POST "http://localhost:8080/sessions/<session_id>/attach-tokens" ^
	-H "Authorization: Bearer dev-token" ^
	-H "Content-Type: application/json" ^
	--data-raw "{\"mode\":\"readonly\"}"
```

Expected response shape:

```json
{
	"session_id": "...",
	"mode": "readonly",
	"ws_url": "ws://localhost:8080/ws/...?..."
}
```

Connect to `ws_url` with the same WebSocket client.
You should receive the same PTY output as the writer client, but any input from this readonly client is ignored by the server.

### 6. Delete the session

```powershell
curl.exe -s -X DELETE "http://localhost:8080/sessions/<session_id>" ^
	-H "Authorization: Bearer dev-token"
```

Expected response:

```json
{
	"status": "deleted"
}
```

## What This Confirms

- REST creates and manages the server-side SSH resource.
- WebSocket attaches only to an existing session.
- `attach_token` acts as a capability, not as caller identity.
- Writer and readonly behavior are tracked per attached client.
- PTY resize remains a control-plane action.
