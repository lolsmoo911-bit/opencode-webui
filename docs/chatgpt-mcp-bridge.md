# OpenCode MCP bridge

This repository exposes a stateless Streamable HTTP MCP endpoint at `/mcp`.
It gives an MCP client controlled access to the OpenCode engine attached to this WebUI instance.

## Enable the bridge

1. In Prisma Console, set `WEBUI_MCP_TOKEN` as an encrypted **Preview** environment variable, or as a branch override for `feature/chatgpt-mcp-bridge`.
2. Use a unique random secret with at least 32 characters. Never commit the token, share it in chat, or reuse the WebUI login password.
3. Redeploy the preview branch after changing this variable. Prisma resolves environment variables when a deployment is created; saving a value does not update an already-running deployment.

## Connect an MCP client

- Endpoint: `https://xpw8e5kpd150o4ifttv9gp7r.ewr.prisma.build/mcp` (preview only; use the current preview URL if it changes).
- Transport: Streamable HTTP using JSON-RPC, with `Content-Type: application/json`.
- Authentication: `Authorization: Bearer <WEBUI_MCP_TOKEN>`.

The bridge supports `initialize`, `ping`, `tools/list`, and `tools/call`. Its tools cover engine health, sessions, session messages, file listing/reading, and sending a prompt to OpenCode.

**Safety:** `send_message` can cause OpenCode to modify project files. Connect only trusted MCP clients and review the result before deploying code. Do not disable bearer-token authentication to troubleshoot the bridge.

## Smoke test

After redeployment, configure an MCP client that supports remote Streamable HTTP and bearer-token authentication. Call `tools/list`, then `opencode_health`. ChatGPT's ability to connect depends on whether custom remote MCP apps are available for your account; the endpoint alone does not enable that feature on every plan.
