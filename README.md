<p align="center">
  <strong>proton-agent-mail</strong><br>
  <a href="https://github.com/PabloTheThinker/proton-agent-mail">GitHub</a>
  ·
  <a href="skills/proton-agent-mail/SKILL.md">Agent skill</a>
  ·
  <a href="SECURITY.md">Security</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://proton.me/mail/bridge"><img src="https://img.shields.io/badge/Proton-Bridge-6D4AFF?style=for-the-badge" alt="Proton Bridge"></a>
  <a href="https://agentskills.io"><img src="https://img.shields.io/badge/Agent_skill-SKILL.md-111111?style=for-the-badge" alt="Agent skill"></a>
</p>

**A local AgentMail-shaped inbox API for Proton Mail.** The AI agent talks to `127.0.0.1` with a bearer token. Proton Mail Bridge keeps the mailbox password. The model never sees it.

The human types `login` in Bridge. The agent watches until that login is accepted, stores the Bridge credentials (mode `0600`), and serves the API.

It is not Proton. It is not a cloud inbox factory. It is not Gmail.

<table>
<tr><td><b>AgentMail-shaped REST</b></td><td><code>/inboxes/…/messages</code> — list, read, threads, send. Same verbs an agent already knows from hosted AgentMail.</td></tr>
<tr><td><b>Hard wall</b></td><td>Bearer token + HMAC compare. Loopback bind. Envelope-first list. Body is a second call. Logs redact secrets.</td></tr>
<tr><td><b>User only logs in</b></td><td><code>proton-agent-mail setup</code> starts Bridge if present and waits. You run <code>login</code> in the Bridge CLI. Setup finishes when <code>info</code> has IMAP credentials.</td></tr>
<tr><td><b>Native Bridge client</b></td><td>Python's own IMAP and SMTP over loopback. No subprocess, no third-party mail client. One send is one SMTP attempt, so a refusal can never turn into a retry storm.</td></tr>
<tr><td><b>Skill included</b></td><td>Agents load <code>skills/proton-agent-mail/SKILL.md</code> and walk a human through connect — without asking for passwords in chat.</td></tr>
<tr><td><b>Stdlib only</b></td><td>No extra Python deps. MIT. Clone and run.</td></tr>
</table>

---

## Quick start

```bash
git clone https://github.com/PabloTheThinker/proton-agent-mail.git
cd proton-agent-mail
pip install -e .

# 1) Official Proton Mail Bridge installed (once)
#    https://proton.me/mail/bridge

# 2) Agent does the rest; you only log in
proton-agent-mail setup
# other terminal:
#   protonmail-bridge -c
#   login

export PROTON_AGENT_TOKEN_FILE="$HOME/.config/proton-agent-mail.token"
export PROTON_AGENT_FROM="You <you@your-domain>"
proton-agent-mail serve
proton-agent-mail health
proton-agent-mail list
```

`setup` writes the Bridge login (`~/.config/proton-agent-mail/bridge.json`) and the token file, both at mode `0600`. It never prints passwords. If Bridge is missing it exits `2` with the official download URL — no unofficial installer.

---

## Getting started

```bash
proton-agent-mail setup     # wait for Bridge login, store credentials
proton-agent-mail serve     # loopback API (default 127.0.0.1:18765)
proton-agent-mail health    # { ok, backend, send_breaker, inbox }
proton-agent-mail list      # envelopes only
proton-agent-mail read ID
proton-agent-mail send --to ADDR --subject '…' --body '…'
proton-agent-mail token     # mint a bearer; do not commit it
```

### Environment

| Variable | Meaning |
|----------|---------|
| `PROTON_AGENT_TOKEN` | Bearer (or use the file) |
| `PROTON_AGENT_TOKEN_FILE` | Token file, mode 0600 |
| `PROTON_AGENT_FROM` | `From:` on send |
| `PROTON_AGENT_INBOX` | Inbox id (`default`) |
| `PROTON_AGENT_PORT` | `18765` |
| `PROTON_AGENT_BIND` | `127.0.0.1` |
| `PROTON_AGENT_BRIDGE_FILE` | Bridge login, JSON `{user, password}`, mode 0600 (default `~/.config/proton-agent-mail/bridge.json`) |
| `PROTON_AGENT_SEND_AS` | Allowed senders, `Name <a@x>;Name <b@x>`; first is the default. An explicit `from` outside the list returns 400 |
| `PROTON_AGENT_FOLDERS` | Folders the agent may touch, e.g. `Jobs,Receipts`. Unset = every folder. The first entry is the default folder. Anything else returns 403 |
| `PROTON_AGENT_READONLY` | `1` blocks send, reply, label changes and `mark_read` with 403 (reading and attachment fetch still work) |
| `PROTON_AGENT_STATE` | State dir (events, refused recipients, send breaker) |
| `PROTON_AGENT_BREAKER` | Path of the shared send-breaker file |
| `PROTON_BRIDGE_HOST` / `PROTON_BRIDGE_IMAP_PORT` / `PROTON_BRIDGE_SMTP_PORT` | Loopback only (defaults `127.0.0.1`, `1143`, `1025`) |

Binding anything other than loopback requires `PROTON_AGENT_ALLOW_LAN=1`. Do not do that casually.

---

## How it works

```
human  --login only-->  Proton Mail Bridge
agent  --Bearer------>  proton-agent-mail   127.0.0.1:18765
                              |
                   BridgeClient (imaplib + smtplib)
                              |
                    Proton Bridge :1143 / :1025
                              |
                         Proton Mail
```

### HTTP

| Method | Path | Auth |
|--------|------|------|
| GET | `/health` | no |
| GET | `/inboxes` | yes |
| GET | `/inboxes/{id}/messages` | yes |
| GET | `/inboxes/{id}/messages/{id}` | yes |
| GET | `/inboxes/{id}/messages/{id}/attachments` | yes |
| GET | `/inboxes/{id}/messages/{id}/attachments/{n}` | yes |
| POST | `/inboxes/{id}/messages/{id}/attachments/fetch` | yes |
| GET | `/inboxes/{id}/threads` | yes |
| GET | `/quarantine/status` | yes |
| POST | `/inboxes/{id}/messages/send` | yes |
| POST | `/inboxes/{id}/messages/{id}/reply` | yes |

```json
{"to":"owner@example.com","subject":"Hello","text":"…"}
```

Send with attachments (paths or base64). Each file is scanned before SMTP:

```json
{
  "to": "owner@example.com",
  "subject": "Report",
  "text": "Attached.",
  "attachments": [{"filename": "photo.jpg", "path": "/safe/photo.jpg"}]
}
```

Replies read the original's real headers: they answer from the address the message was written to (if it is in `PROTON_AGENT_SEND_AS`), go to `Reply-To` first, and carry `In-Reply-To` and `References` so threads link.

### Handing an agent a slice of a mailbox

`PROTON_AGENT_FOLDERS=Jobs,Receipts` pins what the agent can reach, and `PROTON_AGENT_READONLY=1` takes away everything that changes the mailbox. Together they make "this agent may read the `Jobs` folder and nothing else" expressible.

- Every route that takes a folder enforces the scope: list, read, threads, attachments, reply, label changes, and the new-mail watcher. An out-of-scope folder returns `403 folder_forbidden` (not 404), so the boundary is visible in logs.
- A call with no `folder` uses the **first** listed folder, never silently `INBOX`.
- `GET /inboxes` advertises `folders`, `default_folder` and `read_only`, so an agent can learn its own scope instead of probing.
- Names are matched exactly (IMAP folder names are case-sensitive; only `INBOX` is folded). A malformed value stops the service at startup.
- Message ids only mean something inside one folder, so reads, replies and label changes carry the folder too.

### When Bridge pushes back

Bridge answers a burst of failed sends with `554 Too many failed send attempts` and then refuses every sender for minutes. So: one send is one SMTP attempt; a lockout opens a shared breaker and the API answers `503` with `Retry-After`; a refused recipient is remembered for 24 hours and answered `422` instead of being retried. Failed sends leave drafts in Bridge, so a pile of identical drafts means something is retrying.

Download one attachment's bytes. It is exported in memory, written to the quarantine, scanned, and served only if it came back `clean`:

```
GET /inboxes/default/messages/42/attachments/0?folder=INBOX
```

- The listing (`GET .../attachments`) returns `[{index, filename, content_type, size, inline}]`. `filename` is already sanitised; the sender's raw name never reaches the filesystem.
- The response is always `application/octet-stream` with `nosniff` and `attachment` disposition, never the sender's declared type. `X-Attachment-Scan` and `X-Attachment-Sha256` say what was checked.
- A refused file is never served: `422` (infected or blocked by policy), `413` (over `PROTON_AGENT_ATTACH_MAX_BYTES`, default 25 MiB), `502` (scanner failed), `404` (no such index).
- The folder scope applies, so an out-of-scope folder is `403` before anything is fetched.
- Treat the bytes as hostile. A PDF in an agent's context is a prompt-injection vector, like a message body; see [SECURITY.md](SECURITY.md).

Fetch inbound attachments into quarantine → ClamAV → `clean/` only if safe:

```json
POST .../messages/42/attachments/fetch
{"folder": "INBOX"}
```

---

## Documentation

| Doc | What |
|-----|------|
| [skills/proton-agent-mail/SKILL.md](skills/proton-agent-mail/SKILL.md) | What agents load |
| [skills/proton-agent-mail/references/connect-and-guide.md](skills/proton-agent-mail/references/connect-and-guide.md) | How the agent guides the human |
| [SECURITY.md](SECURITY.md) | Threat model and operator checklist |
| [LICENSE](LICENSE) | MIT |

Compatible with the [agentskills.io](https://agentskills.io) skill layout.

---

## Why not the others

| | This | Hosted AgentMail | Raw mail client in the agent |
|--|------|------------------|---------------------------|
| Proton | Yes, via official Bridge | No | Yes |
| Model sees mailbox password | No | N/A | Often yes |
| REST the agent already knows | Yes | Yes | No |
| Leaves your machine | Only through Bridge | Cloud | Depends |

Earlier versions drove Himalaya as a subprocess. It reconnected about 25 times a second when Bridge refused a send, which is exactly what triggers the lockout above, so the service now speaks IMAP and SMTP itself.

---

## Honesty

- Not a second Proton
- Not hosting other people’s mail
- Does not skip Bridge
- Does not print the Bridge password
- Does not ask for the Proton password in chat

---

## Tests

```bash
python3 -m unittest discover -s tests -q
```

---

## Contributing

Issues and PRs welcome. Keep operator paths, tokens, and live mailbox dumps out of the tree. Read [SECURITY.md](SECURITY.md) before filing anything that might contain credentials.

---

## License

[MIT](LICENSE) — © 2026 Pablo Navarro and contributors
