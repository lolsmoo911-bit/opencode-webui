import assert from "node:assert/strict";
import { guardRequest, resolveAllowedHosts } from "../../server/auth";
import { handleMcpBridge } from "../../server/mcpBridge";

const TEST_TOKEN = "unit-test-token-which-is-at-least-32-characters";
const calls: Array<{ path: string; method: string; body?: string }> = [];

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

const requestEngine = async (path: string, init?: RequestInit): Promise<Response> => {
  const method = init?.method ?? "GET";
  const body = typeof init?.body === "string" ? init.body : undefined;
  calls.push({ path, method, ...(body === undefined ? {} : { body }) });

  if (path === "/api/info" && method === "GET") {
    return json({ version: "2.0.26", pid: 123 });
  }
  if (path === "/api/health" && method === "GET") return new Response("Not found", { status: 404, headers: { "content-type": "text/plain" } });
  if (path === "/global/health" && method === "GET") return new Response("OK", { status: 200, headers: { "content-type": "text/plain" } });
  if (path === "/api/session?limit=1" && method === "GET") return json({ data: [] });
  if (path === "/api/session" && method === "GET") return json({ data: [] });
  if (path === "/api/agent" && method === "GET") return json({ data: [{ name: "build" }] });
  if (path === "/api/model" && method === "GET") return json({ data: [{ id: "test-model" }] });
  if (path === "/api/command" && method === "GET") return json({ data: [{ name: "init" }] });
  if (path === "/api/fs/find?query=README&type=file&limit=50" && method === "GET") {
    return json({ data: [{ path: "README.md", type: "file" }] });
  }
  if (path === "/api/session" && method === "POST") {
    const input = JSON.parse(body ?? "{}") as { title?: string };
    return json({ data: { id: "sess-test", title: input.title ?? "" } });
  }
  if (path === "/api/fs/list?path=." && method === "GET") {
    return json({ data: [{ path: "README.md", type: "file" }] });
  }
  if (path === "/api/fs/list?path=src" && method === "GET") {
    return json({ data: [{ path: "src/index.ts", type: "file" }] });
  }
  if (path === "/api/fs/read/README.md" && method === "GET") {
    return new Response("# fixture file", { status: 200, headers: { "content-type": "text/plain" } });
  }
  if (path === "/api/session/sess-test" && method === "GET") {
    return json({ data: { id: "sess-test", title: "bridge-test", status: "idle" } });
  }
  if (path === "/api/session/sess-test/context" && method === "GET") {
    return json({ data: [{ id: "msg-context", role: "assistant", parts: [{ type: "text", text: "context" }] }] });
  }
  if (path === "/api/session/sess-test/diff" && method === "GET") {
    return json({ data: [{ file: "README.md", additions: 1, deletions: 0 }] });
  }
  if (path === "/api/session/sess-test/message?limit=3" && method === "GET") {
    return json({ data: [{ id: "msg-user", type: "user", text: "hello" }] });
  }
  if (path === "/api/session/sess-test/prompt" && method === "POST") {
    const input = JSON.parse(body ?? "{}") as { id?: unknown; prompt?: { text?: string } };
    assert.equal(input.id, null);
    assert.equal(input.prompt?.text, "say hello");
    return new Response(null, { status: 204 });
  }
  if (path === "/api/experimental/session/sess-test/wait" && method === "POST") {
    return new Response(null, { status: 204 });
  }
  if (path === "/api/session/sess-test/message?limit=10&order=desc" && method === "GET") {
    return json({
      data: [
        { id: "msg-assistant", type: "assistant", content: [{ type: "text", text: "hello from OpenCode" }] },
        { id: "msg-user", type: "user", text: "say hello" },
      ],
    });
  }
  return json({ error: "Unexpected mocked engine request: " + method + " " + path }, 404);
};

async function rpc(method: string, params: unknown, authorized = true): Promise<any> {
  const headers: Record<string, string> = { "content-type": "application/json", "MCP-Protocol-Version": "2025-06-18" };
  if (authorized) headers.authorization = "Bearer " + TEST_TOKEN;
  const response = await handleMcpBridge(new Request("https://bridge.test/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  }), { token: TEST_TOKEN, requestEngine });
  return { status: response.status, body: await response.json() };
}

async function tool(name: string, args: Record<string, unknown> = {}, authorized = true): Promise<any> {
  const rpcResult = await rpc("tools/call", { name, arguments: args }, authorized);
  assert.equal(rpcResult.status, 200, name + " should return an MCP response");
  assert.equal(rpcResult.body.result?.isError, false, name + " should succeed: " + JSON.stringify(rpcResult.body));
  return JSON.parse(rpcResult.body.result.content[0].text);
}

async function main() {
  const previewHost = "preview.test";
  const allowedHosts = resolveAllowedHosts();
  const requestFor = (path: string, origin: string) => new Request(`https://${previewHost}${path}`, {
    method: "POST",
    headers: { host: previewHost, origin, "content-type": "application/x-www-form-urlencoded" },
    body: "test=1",
  });
  const oauthConsentGuard = guardRequest(requestFor("/oauth/authorize", "null"), previewHost, allowedHosts, false);
  assert.equal(oauthConsentGuard, null, "OAuth consent POST should permit an opaque Origin after host validation");
  const mcpGuard = guardRequest(requestFor("/mcp", "null"), previewHost, allowedHosts, false);
  assert.equal(mcpGuard?.status, 403, "Opaque Origin must remain blocked for MCP POSTs");
  const tokenGuard = guardRequest(requestFor("/oauth/token", "null"), previewHost, allowedHosts, false);
  assert.equal(tokenGuard?.status, 403, "Opaque Origin must remain blocked for token exchange");
  const crossOriginGuard = guardRequest(requestFor("/oauth/authorize", "https://attacker.test"), previewHost, allowedHosts, false);
  assert.equal(crossOriginGuard?.status, 403, "A concrete foreign Origin must remain blocked on OAuth consent");

  const sessions = await tool("list_sessions");
  assert.deepEqual(sessions.data, []);

  const created = await tool("create_session", { title: "bridge-test" });
  assert.equal(created.data.id, "sess-test");

  const messages = await tool("get_session_messages", { session_id: "sess-test", limit: 3 });
  assert.equal(messages.data[0].id, "msg-user");

  const sessionStatus = await tool("get_session_status", { session_id: "sess-test" });
  assert.equal(sessionStatus.data.id, "sess-test");

  const sessionContext = await tool("get_session_context", { session_id: "sess-test" });
  assert.equal(sessionContext.data[0].id, "msg-context");

  const sessionDiff = await tool("get_session_diff", { session_id: "sess-test" });
  assert.equal(sessionDiff.data[0].file, "README.md");

  const agents = await tool("list_agents");
  assert.equal(agents.data[0].name, "build");

  const models = await tool("list_models");
  assert.equal(models.data[0].id, "test-model");

  const commands = await tool("list_commands");
  assert.equal(commands.data[0].name, "init");

  const found = await tool("find_files", { query: "README", type: "file" });
  assert.equal(found.data[0].path, "README.md");

  const files = await tool("list_files", { path: "src" });
  assert.equal(files.data[0].path, "src/index.ts");

  const file = await tool("read_file", { path: "README.md" });
  assert.equal(file, "# fixture file");

  const sent = await tool("send_message", { session_id: "sess-test", message: "say hello" });
  assert.equal(sent.assistant_response, "hello from OpenCode");
  assert.equal(calls.some(call => call.path === "/api/session/sess-test/prompt" && call.method === "POST"), true);
  assert.equal(calls.some(call => call.path === "/api/experimental/session/sess-test/wait" && call.method === "POST"), true);

  const previous = process.env.WEBUI_MCP_ALLOW_NO_AUTH;
  process.env.WEBUI_MCP_ALLOW_NO_AUTH = "1";
  try {
    const listed = await rpc("tools/list", {}, false);
    assert.deepEqual(
      listed.body.result.tools.map((entry: { name: string }) => entry.name).sort(),
      ["opencode_api_diagnostics", "opencode_bridge_capabilities", "opencode_health", "opencode_server_info"].sort(),
    );
    const serverInfo = await tool("opencode_server_info", {}, false);
    assert.equal(serverInfo.version, "2.0.26");
    const diagnostics = await tool("opencode_api_diagnostics", {}, false);
    assert.equal(diagnostics.allEndpointsResponded, true);
    const healthCheck = diagnostics.checks.find((entry: { name: string }) => entry.name === "health");
    assert.equal(healthCheck.status, 200);
    assert.equal(healthCheck.json, false);
    assert.equal(healthCheck.readiness, null);
    const health = await tool("opencode_health", {}, false);
    assert.equal(health.healthStatus, 200);
    assert.equal(health.healthConfirmed, false);
    assert.equal(health.readiness, null);
    assert.equal(diagnostics.checks.find((entry: { name: string }) => entry.name === "filesystem").itemCount, 1);
    const catalog = await tool("opencode_bridge_capabilities", {}, false);
    assert.equal(catalog.mode, "restricted-diagnostic");
    assert.equal(catalog.protectedTools.includes("send_message"), true);
    const blocked = await rpc("tools/call", { name: "send_message", arguments: { session_id: "sess-test", message: "no" } }, false);
    assert.equal(blocked.body.result.isError, true);
  } finally {
    if (previous === undefined) delete process.env.WEBUI_MCP_ALLOW_NO_AUTH;
    else process.env.WEBUI_MCP_ALLOW_NO_AUTH = previous;
  }

  console.log("MCP bridge checks passed: diagnostic helpers, protected sessions/files, agents/models/commands/search and prompt/wait/reply.");
}

await main();
