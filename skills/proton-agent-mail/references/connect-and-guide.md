# Connect Proton Mail (agent → human)

Use this when the user is not already on Proton Bridge.

## What to tell them (plain)

You will install two local pieces. Mail stays on Proton. I (the agent) only get a token to a program on this computer. I never see your Proton password.

1. Proton Mail Bridge (official app)
2. This package (`proton-agent-mail`)

## Order

### 1. Bridge
- Install from https://proton.me/mail/bridge
- Sign in **in the Bridge app**, not in chat
- Confirm IMAP `127.0.0.1:1143` and SMTP `127.0.0.1:1025`
- `setup` reads the **Bridge** username + password from the Bridge CLI and stores them at mode 0600
- Do not paste those into the agent chat

Agent check: port 1143 and 1025 listening on loopback.

### 2. One command after they can type `login`

```
proton-agent-mail setup
```

The agent starts Bridge if needed, then **waits**. You tell the user to run `protonmail-bridge -c` → `login` in another window. When Bridge accepts the login, setup writes the Bridge login + token (mode 0600) and prints how to `serve`. It never prints passwords.

Agent check: `proton-agent-mail health` → ok, `backend` shown, `send_breaker: closed`.  
`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18765/inboxes` → **401**.

### 3. First mail
`proton-agent-mail list` — envelopes only.  
Read one non-sensitive id.  
Do not send until they ask.

## If they get stuck

| They see | You say |
|----------|---------|
| Bridge not running | Open Proton Bridge and wait until it says connected |
| 503 Retry-After on send | Bridge is refusing sends. Wait; never retry in a loop |
| 401 on list | Token env not loaded in that shell |
| Hang on list | Timeout 20s; check that Bridge is running and shows connected |

## Never ask in chat
Proton account password. Bridge password. `auth.raw`. Recovery codes.
