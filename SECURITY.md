# Security

## Threat model

An AI agent process can be prompt-injected. It must not hold the Proton Bridge
password or see IMAP/SMTP secrets.

Proton Mail Bridge is the only hop that talks to Proton. This package talks to
Bridge on **loopback only**.

## Guarantees we aim for

1. Agent authenticates with a random bearer token only.
2. Bridge credentials live in a 0600 file read by the service, never in agent context.
3. Listener is loopback unless the operator opts into LAN.
4. List endpoints do not include message bodies.
5. Logs are redacted for tokens and passwords.
6. One send is one SMTP attempt. A Bridge `554` lockout opens a shared circuit breaker (HTTP 503 + `Retry-After`); refused recipients are remembered, not retried.
7. Serve **refuses** if Bridge IMAP/SMTP is bound off loopback.
8. Serve **refuses** a world-readable Bridge credentials file or token file.
9. The Bridge client **refuses** any non-loopback host.
10. No subprocess handles mail, so the bearer token never reaches a child environment.
11. Folder names and message ids are allowlisted (no shell injection).
12. **Attachments** download into a 0700 quarantine tree (`incoming` → scan → `clean` or `blocked`).
13. ClamAV scan before any attachment is marked usable (`clamdscan` / Docker `clamav/clamav` / `clamscan`).
14. Dangerous extensions (`.exe`, `.bat`, `.js`, …) are blocked by policy even if AV is clean.
15. Outbound attachments are scanned the same way before SMTP.
16. Agent only receives filesystem paths under `clean/` for usable files — never execute them.
17. Mail is sent only from addresses in `PROTON_AGENT_SEND_AS`; an explicit `from` outside it is rejected (HTTP 400) and nothing is sent.
18. Message headers are RFC 2047 encoded, so a display name or subject cannot smuggle raw bytes into a header.
19. `PROTON_AGENT_FOLDERS` limits every route to a set of folders (403 outside it, first entry is the default, exact matching). The agent cannot widen it; it is service configuration.
20. `PROTON_AGENT_READONLY=1` blocks send, reply, label changes and `mark_read`, so a read-only agent cannot delete or alter mail through this API.

## Attachment quarantine

```
$PROTON_AGENT_QUARANTINE/
  incoming/   # raw drop (mode 0700)
  clean/      # usable after clean scan + policy
  blocked/    # infected / policy / scan errors
  meta/       # JSON manifests (sha256, backend, reasons)
```

Env:

| Variable | Meaning |
|----------|---------|
| `PROTON_AGENT_QUARANTINE` | Root directory |
| `PROTON_AGENT_SCAN` | `auto` (default), `docker`, `clamdscan`, `clamscan` |
| `PROTON_AGENT_CLAM_IMAGE` | Docker image (default `clamav/clamav:stable`) |
| `PROTON_AGENT_ATTACH_MAX_BYTES` | Max size (default 25MB) |
| `PROTON_AGENT_ALLOW_UNKNOWN` | `1` to release unknown extensions after clean AV |

Docker scanner runs `--network=none`, read-only root, file mount `:ro`.

## Bridge hop

```
agent --token--> 127.0.0.1:18765 --> BridgeClient --> 127.0.0.1:1143/1025 --> Bridge --> Proton
```

- Set Bridge IMAP/SMTP host to `127.0.0.1` (not `0.0.0.0`).
- The client uses STARTTLS on loopback without certificate verification (Bridge's certificate is self-signed).
  TLS to Proton is inside Bridge. Never point the client at a remote host; it refuses to.
- This tool never prints the Bridge password.

## Operator checklist

- `proton-agent-mail token` — do not commit it.
- `chmod 600` the Bridge credentials file and the token file.
- Do not expose 18765, 1143, or 1025 on a public interface.
- Rotate the token if the agent session is compromised.
- Keep Proton Bridge updated.

## Public repo

No operator hosts, no house paths, no live tokens. The audit script uses
**generic** secret/mesh patterns only — never real home directories or hostnames
(those strings would be the leak). Run:

```bash
bash scripts/security_audit.sh
```

## Reporting

Open a private security advisory. Do not file public issues with credentials.
