"""proton-agent-mail: AgentMail-shaped local API over Proton Bridge.

Security model
--------------
The *agent* authenticates with a bearer token.
The *service* holds the Proton Bridge login (a 0600 file) and talks to Bridge over loopback IMAP/SMTP
with Python's own client (``proton_agent_mail.bridge``); there is no subprocess and no third-party mail client.
The agent never sees the mailbox password.
Bind 127.0.0.1 only unless explicitly overridden.
"""

__version__ = "0.6.0"
__all__ = ["__version__"]
