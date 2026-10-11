# OpenCode MCP bridge

This repository can expose a stateless, Streamable HTTP MCP endpoint at /mcp.
It gives an MCP client controlled access to the OpenCode engine attached to this
WebUI instance.

## Safety and enablement

The endpoint remains unusable until the Prisma Compute project has an
environment variable named WEBUI_MCP_TOKEN with a random secret of at least 32
characters. Send it as Authorization: Bearer <token>. Do not reuse the WebUI
login password. Keep the token private and rotate it immediately if exposed.

The bridge is intentionally narrow: health, session listing/creation, message
history, file listing/reading, and sending a prompt to OpenCode. Sending a
prompt can lead OpenCode to modify files, so only connect trusted MCP clients.

## Supported MCP methods

- initialize
- ping
- tools/list
- tools/call

## ChatGPT plan note

A remote MCP endpoint is not automatically connectable from every ChatGPT plan.
Check custom-app/MCP availability for the account before relying on it as a
ChatGPT tool. The same endpoint can be tested from other MCP clients that
support Streamable HTTP and bearer-token authentication.
