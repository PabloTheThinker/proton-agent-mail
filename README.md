# proton-agent-mail

A local, AgentMail-style REST API for Proton Mail. An AI agent can read, search, reply to and send mail through it without ever holding the mailbox password.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)
[![Proton Mail Bridge](https://img.shields.io/badge/Proton-Bridge-6D4AFF.svg)](https://proton.me/mail/bridge)
[![Agent skill](https://img.shields.io/badge/agent%20skill-SKILL.md-111111.svg)](skills/proton-agent-mail/SKILL.md)

It is not a Proton product, a hosted inbox service, or a way around Bridge. It is a small service that runs on your machine, in front of the official Proton Mail Bridge.

## Contents

- [Why](#why)
- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Command line](#command-line)
- [HTTP API](#http-api)
- [Giving an agent less access](#giving-an-agent-less-access)
- [Sending safely](#sending-safely)
- [Attachments](#attachments)
- [Events](#events)
- [Configuration](#configuration)
- [Security](#security)
- [Agent skill](#agent-skill)
- [Development](#development)
- [Contributing](#contributing) · [License](#license)

## Why

An agent that reads email can be steered by the email it reads. Handing it IMAP and SMTP credentials means a single hostile message can reach the whole mailbox.

Proton Mail Bridge exposes a Proton account as local IMAP and SMTP, which is all-or-nothing. This service sits between the agent and Bridge and gives the agent something narrower: a small HTTP API behind a bearer token. The Bridge login stays in a file the agent never sees, and the service can be restricted to specific folders, to read-only, and to specific sender addresses.

The API follows the shape of hosted [AgentMail](https://agentmail.to) (`/inboxes/{id}/messages`, threads, send, reply, events), so an agent that already knows that interface needs no new tools.

| | proton-agent-mail | Hosted AgentMail | Raw IMAP/SMTP in the agent |
|---|---|---|---|
| Works with Proton | Yes, through official Bridge | No | Yes |
| Agent sees the mailbox password | No | Not applicable | Usually |
| REST interface agents already know | Yes | Yes | No |
| Mail leaves your machine | Only through Bridge | Stored in a cloud service | Depends |
| Can limit an agent to part of a mailbox | Yes | Not applicable | No |

## Features

- **AgentMail-shaped REST.** List, read, threads, send, reply, label changes, events.
- **Credential isolation.** The agent holds a bearer token. The Bridge login lives in a `0600` file read only by the service.
- **Scoped access.** Pin the folders an agent may touch, make the service read-only, and restrict which addresses it may send from.
- **Safe sending.** One send is one SMTP attempt, with a circuit breaker and refused-recipient memory, so a Bridge refusal cannot turn into a lockout.
- **Quarantined attachments.** Every inbound and outbound attachment is scanned (ClamAV) before it is released.
- **Native client.** Python's own IMAP and SMTP over loopback. No subprocess, no third-party mail client, no dependencies.
- **Loopback only.** Refuses to bind elsewhere unless you explicitly allow it.

## How it works

```
human   ── logs in once ──▶  Proton Mail Bridge
agent   ── Bearer token ──▶  proton-agent-mail    127.0.0.1:18765
                                   │
                             BridgeClient (imaplib + smtplib)
                                   │
                             Bridge  127.0.0.1:1143 / 1025
                                   │
                              Proton Mail
```

## Requirements

- Python 3.11 or newer. There are no Python dependencies.
- [Proton Mail Bridge](https://proton.me/mail/bridge), installed and signed in. Bridge needs a paid Proton plan.
- For attachments: ClamAV (`clamdscan` or `clamscan`) or Docker. With no scanner available, attachments are refused rather than released unscanned.

## Quick start

```bash
git clone https://github.com/PabloTheThinker/proton-agent-mail.git
cd proton-agent-mail
pip install -e .

# 1. Start setup. It launches Bridge if needed and waits for you to sign in.
proton-agent-mail setup

# 2. In another terminal, sign in to Bridge yourself. Never paste these into a chat.
protonmail-bridge -c
#   >>> login

# Setup finishes once Bridge reports IMAP credentials. It writes the Bridge login
# and a bearer token, both mode 0600, and never prints either.

# 3. Serve the API.
export PROTON_AGENT_TOKEN_FILE="$HOME/.config/proton-agent-mail.token"
export PROTON_AGENT_FROM="You <you@your-domain>"
proton-agent-mail serve

# 4. Check it.
proton-agent-mail health
proton-agent-mail list
```

If Bridge is not installed, `setup` exits with status `2` and prints the official download URL. It does not install anything from unofficial sources.

## Command line

| Command | Purpose |
|---|---|
| `setup` | Wait for the Bridge login, store credentials and a token |
| `serve` | Run the API on `127.0.0.1:18765` |
| `health` | Service status, backend, send breaker, scope |
| `token` | Print a new random bearer token |
| `list [--limit N]` | Message envelopes only, no bodies |
| `read ID [--mark-read]` | Read one message (does not mark it read unless asked) |
| `threads [--limit N]` | Thread list |
| `send --to --subject --body` | Send a message |
| `reply ID --body [--to] [--subject]` | Reply in thread |
| `mark ID --add/--remove LABEL` | Labels: `read`, `unread`, `replied`, `starred`, `flagged` |
| `attachments ID [--folder F]` | List a message's attachments |
| `fetch ID [--folder F] [--index N]` | Download into quarantine, scan, release if clean |
| `events [--after ID] [--wait S] [--follow]` | New-mail events |

## HTTP API

Every route except `/health` needs `Authorization: Bearer <token>`. The default inbox id is `default`.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Status (no auth) |
| GET | `/inboxes` | Inbox, plus the agent's folder scope and read-only flag |
| GET | `/inboxes/{id}/messages` | Envelopes. Query: `limit` (max 50), `folder`, `unread`, `q` |
| GET | `/inboxes/{id}/messages/{mid}` | One message. Query: `folder`, `mark_read` |
| PATCH | `/inboxes/{id}/messages/{mid}` | `{"add_labels": [...], "remove_labels": [...]}` |
| GET | `/inboxes/{id}/threads` | Thread list. Query: `limit`, `folder` |
| POST | `/inboxes/{id}/messages/send` | Send |
| POST | `/inboxes/{id}/messages/{mid}/reply` | Reply, threaded |
| GET | `/inboxes/{id}/messages/{mid}/attachments` | List attachments |
| GET | `/inboxes/{id}/messages/{mid}/attachments/{n}` | Download one attachment (scanned) |
| POST | `/inboxes/{id}/messages/{mid}/attachments/fetch` | Fetch into quarantine and scan |
| GET | `/inboxes/{id}/events` | New-mail events (long poll) |
| GET | `/quarantine/status` | Quarantine layout and scanner mode |

List responses return envelope metadata only. A message body is always a second call. Message ids are only meaningful within one folder, so pass `folder` whenever it is not `INBOX`.

**Send**

```bash
curl -s -X POST http://127.0.0.1:18765/inboxes/default/messages/send \
  -H "Authorization: Bearer $(cat $PROTON_AGENT_TOKEN_FILE)" \
  -H "Content-Type: application/json" \
  -d '{"to": "owner@example.com", "subject": "Hello", "text": "Hi there."}'
```

Optional fields: `cc`, `from` (must be an allowed sender), and `attachments`.

**Reply.** The reply goes to `Reply-To` first, then the sender. It is sent from the address the original was written to (when that address is an allowed sender), with `In-Reply-To` and `References` set so the thread stays linked.

```bash
curl -s -X POST http://127.0.0.1:18765/inboxes/default/messages/42/reply \
  -H "Authorization: Bearer $(cat $PROTON_AGENT_TOKEN_FILE)" \
  -H "Content-Type: application/json" \
  -d '{"text": "Thanks, received."}'
```

## Giving an agent less access

Three independent settings narrow what an agent can do. They are service configuration, so the agent cannot widen them.

**Folder scope.** `PROTON_AGENT_FOLDERS=Jobs,Receipts` limits every route to those folders. For example, an agent that tracks job applications can read the `Jobs` folder and nothing else in a personal mailbox.

- Unset means every folder.
- The first entry is the default folder, so a call with no `folder` never falls back to `INBOX`.
- A folder outside the set returns `403 folder_forbidden`, not 404, so the boundary shows in logs.
- Matching is exact. IMAP folder names are case-sensitive; only `INBOX` is case-folded.
- It is enforced on list, read, threads, attachments, reply, label changes and the new-mail watcher.
- `GET /inboxes` reports `folders`, `default_folder` and `read_only`, so an agent can discover its own scope.
- A malformed value stops the service at startup.

**Read-only mode.** `PROTON_AGENT_READONLY=1` makes send, reply, label changes and `mark_read` return `403 read_only`. Reading and attachment fetch still work. Without this switch, an agent that cannot send mail can still alter it through label changes.

**Sender policy.** `PROTON_AGENT_SEND_AS="Name <a@example.com>;Name <b@example.com>"` lists the addresses the service may send from. The first is the default. An explicit `from` outside the list returns `400` and nothing is sent.

A read-only, single-folder deployment:

```bash
PROTON_AGENT_FOLDERS=Jobs PROTON_AGENT_READONLY=1 proton-agent-mail serve
```

## Sending safely

When a send fails repeatedly, Bridge answers `554 Too many failed send attempts` and then refuses every sender for several minutes. Each retry during that window extends it. The service is built so a failure cannot cascade:

- One send is one SMTP attempt. There is no retry loop.
- A lockout opens a shared circuit breaker. Further sends return `503` with `Retry-After` and never reach Bridge.
- A recipient Bridge refuses is remembered for 24 hours and answered with `422` instead of being tried again.
- Headers are RFC 2047 encoded, so a display name or subject with non-ASCII characters is not rejected by Bridge.

Failed sends leave drafts behind in Bridge. A pile of identical drafts means something is retrying.

If you run several processes that send, point them at the same `PROTON_AGENT_BREAKER` file so they share one breaker.

## Attachments

Attachments are untrusted input. The service treats them that way.

- `GET .../attachments` lists `[{index, filename, content_type, size, inline}]`. Filenames are sanitised; the sender's raw name never reaches the filesystem.
- `GET .../attachments/{n}` returns the bytes of one attachment, and only if the quarantine scan reported `clean`. The response is always `application/octet-stream` with `nosniff` and an `attachment` disposition, never the type the sender declared. `X-Attachment-Scan` and `X-Attachment-Sha256` report what was checked.
- A refused file is never served: `422` infected or blocked by policy, `413` over the size limit, `502` scanner failure, `404` unknown index.
- `POST .../attachments/fetch` stages files in the quarantine tree (`incoming` → `clean` or `blocked`) for callers that want paths rather than bytes.
- Outbound attachments, by path or base64, are scanned the same way before SMTP.

A clean scan does not make a document safe to obey. Text inside a PDF can still carry instructions aimed at the model reading it. See [SECURITY.md](SECURITY.md).

## Events

Bridge has no push mechanism, so a watcher polls the default folder and turns new message ids into `message.received` events. It is off unless `PROTON_AGENT_WATCH_SECS` is set.

- **Long poll:** `GET /inboxes/{id}/events?after=<event_id>&wait=<seconds>`
- **Webhook:** set `PROTON_AGENT_WEBHOOK_URL` (http or https). The body is signed with HMAC-SHA256 using `PROTON_AGENT_WEBHOOK_SECRET`, in the `X-Proton-Agent-Signature` header.
- **Local hook:** `PROTON_AGENT_ON_NEW` runs a command with no shell and no mail data passed to it, so a hostile subject cannot inject into it.

Events carry envelope metadata only (id, sender, subject, date, flags), never bodies. Subjects that look like one-time codes are masked.

## Configuration

All settings are environment variables.

**Service**

| Variable | Default | Meaning |
|---|---|---|
| `PROTON_AGENT_TOKEN` | | Bearer token (or use the file) |
| `PROTON_AGENT_TOKEN_FILE` | | Token file; must be mode `0600` or tighter |
| `PROTON_AGENT_BIND` | `127.0.0.1` | Bind address |
| `PROTON_AGENT_ALLOW_LAN` | | `1` to allow a non-loopback bind. Avoid. |
| `PROTON_AGENT_PORT` | `18765` | Port |
| `PROTON_AGENT_INBOX` | `default` | Inbox id in URLs |
| `PROTON_AGENT_STATE` | `~/.local/state/proton-agent-mail` | State: events, refused recipients, breaker |
| `PROTON_AGENT_BREAKER` | | Path of the shared send-breaker file |

**Bridge connection**

| Variable | Default | Meaning |
|---|---|---|
| `PROTON_AGENT_BRIDGE_FILE` | `~/.config/proton-agent-mail/bridge.json` | JSON `{user, password}`, mode `0600` |
| `PROTON_AGENT_BRIDGE_USER` | | Bridge username |
| `PROTON_AGENT_BRIDGE_PASS_FILE` | | File holding the Bridge password (with `..._USER`) |
| `PROTON_AGENT_BRIDGE_PASS` | | Bridge password directly. Prefer a file. |
| `PROTON_BRIDGE_HOST` | `127.0.0.1` | Must be loopback |
| `PROTON_BRIDGE_IMAP_PORT` | `1143` | |
| `PROTON_BRIDGE_SMTP_PORT` | `1025` | |

**Access control**

| Variable | Default | Meaning |
|---|---|---|
| `PROTON_AGENT_FOLDERS` | all | Folders the agent may touch; first is the default |
| `PROTON_AGENT_READONLY` | off | `1` blocks send, reply, label changes, `mark_read` |
| `PROTON_AGENT_FROM` | `agent@localhost` | `From:` when no sender list is set |
| `PROTON_AGENT_SEND_AS` | | Allowed senders, `Name <a@x>;Name <b@x>`; first is default |

**Attachments**

| Variable | Default | Meaning |
|---|---|---|
| `PROTON_AGENT_QUARANTINE` | `~/.local/state/proton-agent-mail/quarantine` | Quarantine root |
| `PROTON_AGENT_SCAN` | `auto` | `auto`, `docker`, `clamdscan` or `clamscan` |
| `PROTON_AGENT_CLAM_IMAGE` | `clamav/clamav:stable` | Image for the Docker scanner |
| `PROTON_AGENT_ATTACH_MAX_BYTES` | 25 MiB | Size limit |
| `PROTON_AGENT_ALLOW_UNKNOWN` | | `1` releases unknown extensions after a clean scan |

**Events**

| Variable | Default | Meaning |
|---|---|---|
| `PROTON_AGENT_WATCH_SECS` | `0` (off) | Polling interval for new mail |
| `PROTON_AGENT_WEBHOOK_URL` | | Webhook target |
| `PROTON_AGENT_WEBHOOK_SECRET` | | HMAC-SHA256 signing secret |
| `PROTON_AGENT_ON_NEW` | | Local command run on new mail |

## Security

The design assumes the agent can be prompt-injected. In short: the agent holds only a bearer token compared in constant time; the Bridge login is a `0600` file; the service binds to loopback and refuses a non-loopback Bridge host; list calls never include bodies; logs redact secrets; folder names and message ids are allow-listed; and attachments are quarantined and scanned.

The full threat model, every guarantee, and an operator checklist are in [SECURITY.md](SECURITY.md). To report a vulnerability, open a private security advisory on GitHub and do not include credentials in public issues.

## Agent skill

[`skills/proton-agent-mail/SKILL.md`](skills/proton-agent-mail/SKILL.md) teaches an agent to set this up with a human and to use the API. It follows the [agentskills.io](https://agentskills.io) layout and walks the human through connecting Bridge without ever asking for a password in chat. A longer guide is in [`references/connect-and-guide.md`](skills/proton-agent-mail/references/connect-and-guide.md).

## Development

```bash
python3 -m unittest discover -s tests
bash scripts/security_audit.sh      # fails if the tree looks like it contains secrets or operator paths
```

The tests include real HTTP requests against the handler with a recording mail client, which prove that a denied request never reaches the mail layer.

## Contributing

Issues and pull requests are welcome. Please keep operator paths, tokens and mailbox contents out of anything you submit, and read [SECURITY.md](SECURITY.md) before filing something that might contain credentials. Run the tests and the audit script before opening a pull request.

## License

[MIT](LICENSE). Copyright (c) 2026 Pablo Navarro and contributors.
