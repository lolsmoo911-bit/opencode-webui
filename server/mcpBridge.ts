import { timingSafeEqual } from "node:crypto";

type EngineRequest = (path: string, init?: RequestInit) => Promise<Response>;
type BridgeOptions = { token?: string; requestEngine: EngineRequest };
type JsonRpcRequest = { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };

const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"] as const;
const TOOLS = [
  {
    name: "opencode_health",
    description: "Check whether the connected OpenCode engine is healthy.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: "list_sessions",
    description: "List sessions in the currently configured OpenCode workspace.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: "create_session",
    description: "Create a new OpenCode session. This does not itself edit files.",
    inputSchema: {
      type: "object",
      properties: { title: { type: "string", description: "Optional short session title." } },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "get_session_messages",
    description: "Read the messages in an OpenCode session.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: { type: "string", description: "OpenCode session ID." },
        limit: { type: "integer", minimum: 1, maximum: 100 },
      },
      required: ["session_id"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "send_message",
    description: "Send a task or prompt to OpenCode. OpenCode may read or modify project files according to its own permissions and configured model.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: { type: "string", description: "OpenCode session ID." },
        message: { type: "string", minLength: 1, description: "Task or prompt for OpenCode." },
      },
      required: ["session_id", "message"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "list_files",
    description: "List files and directories in the active OpenCode project.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Directory path; defaults to the project root." } },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "read_file",
    description: "Read a text file from the active OpenCode project.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", minLength: 1, description: "Project-relative file path." } },
      required: ["path"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
  },
] as const;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "MCP-Protocol-Version": "2025-06-18",
    },
  });
}

function rpcError(id: unknown, code: number, message: string, status = 400): Response {
  return jsonResponse({ jsonrpc: "2.0", id: id ?? null, error: { code, message } }, status);
}

function tokenIsValid(expected: string | undefined, header: string | null): boolean {
  if (!expected || expected.length < 32 || !header?.startsWith("Bearer ")) return false;
  const supplied = header.slice("Bearer ".length).trim();
  const left = Buffer.from(expected, "utf8");
  const right = Buffer.from(supplied, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringArg(args: Record<string, unknown>, name: string): string {
  const value = args[name];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("Missing or invalid required argument: " + name);
  }
  return value.trim();
}

async function engineJson(requestEngine: EngineRequest, path: string, init?: RequestInit): Promise<unknown> {
  const response = await requestEngine(path, init);
  const text = await response.text();
  let value: unknown = null;
  if (text) {
    try {
      value = JSON.parse(text);
    } catch {
      value = text;
    }
  }
  if (!response.ok) {
    const detail = typeof value === "string" ? value : JSON.stringify(value);
    throw new Error("OpenCode API returned HTTP " + response.status + (detail ? ": " + detail.slice(0, 400) : ""));
  }
  return value;
}

function jsonBody(value: unknown): RequestInit {
  return {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  };
}

async function callTool(name: string, rawArgs: unknown, requestEngine: EngineRequest): Promise<unknown> {
  const args = record(rawArgs);
  switch (name) {
    case "opencode_health":
      return engineJson(requestEngine, "/global/health");
    case "list_sessions":
      return engineJson(requestEngine, "/session");
    case "create_session": {
      const title = typeof args.title === "string" ? args.title.trim() : "";
      return engineJson(requestEngine, "/session", jsonBody(title ? { title } : {}));
    }
    case "get_session_messages": {
      const sessionId = encodeURIComponent(stringArg(args, "session_id"));
      const requestedLimit = args.limit;
      const limit = typeof requestedLimit === "number" && Number.isInteger(requestedLimit)
        ? Math.min(100, Math.max(1, requestedLimit))
        : 50;
      return engineJson(requestEngine, "/session/" + sessionId + "/message?limit=" + limit);
    }
    case "send_message": {
      const sessionId = encodeURIComponent(stringArg(args, "session_id"));
      const message = stringArg(args, "message");
      return engineJson(requestEngine, "/session/" + sessionId + "/message", jsonBody({
        parts: [{ type: "text", text: message }],
      }));
    }
    case "list_files": {
      const path = typeof args.path === "string" ? args.path : ".";
      return engineJson(requestEngine, "/file?path=" + encodeURIComponent(path));
    }
    case "read_file": {
      const path = stringArg(args, "path");
      return engineJson(requestEngine, "/file/content?path=" + encodeURIComponent(path));
    }
    default:
      throw new Error("Unknown tool: " + name);
  }
}

/**
 * Stateless Streamable HTTP MCP endpoint.
 * It stays unusable until WEBUI_MCP_TOKEN is configured with a random secret
 * of at least 32 characters. Do not remove this authentication: send_message
 * can cause the connected OpenCode agent to change project files.
 */
export async function handleMcpBridge(req: Request, options: BridgeOptions): Promise<Response> {
  if (!tokenIsValid(options.token ?? process.env.WEBUI_MCP_TOKEN, req.headers.get("authorization"))) {
    return jsonResponse({ error: "MCP bridge is disabled or authentication failed." }, 401);
  }
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { allow: "POST", "cache-control": "no-store" },
    });
  }
  if (!(req.headers.get("content-type") ?? "").toLowerCase().includes("application/json")) {
    return jsonResponse({ error: "Content-Type must be application/json." }, 415);
  }

  let rpc: JsonRpcRequest;
  try {
    rpc = (await req.json()) as JsonRpcRequest;
  } catch {
    return rpcError(null, -32700, "Parse error");
  }
  if (!rpc || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") {
    return rpcError(rpc?.id, -32600, "Invalid Request");
  }

  const hasId = Object.prototype.hasOwnProperty.call(rpc, "id");
  const id = hasId ? rpc.id : null;
  const params = record(rpc.params);
  if (!hasId && rpc.method.startsWith("notifications/")) {
    return new Response(null, { status: 202, headers: { "cache-control": "no-store" } });
  }
  if (!hasId) return rpcError(null, -32600, "Request ID is required");

  try {
    switch (rpc.method) {
      case "initialize": {
        const requested = params.protocolVersion;
        const protocolVersion = typeof requested === "string" &&
          (PROTOCOL_VERSIONS as readonly string[]).includes(requested)
          ? requested
          : "2025-03-26";
        return jsonResponse({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "opencode-webui-bridge", version: "0.1.0" },
            instructions: "Use send_message to delegate a task to OpenCode. Review results before deployment.",
          },
        });
      }
      case "ping":
        return jsonResponse({ jsonrpc: "2.0", id, result: {} });
      case "tools/list":
        return jsonResponse({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
      case "tools/call": {
        const name = typeof params.name === "string" ? params.name : "";
        try {
          const result = await callTool(name, params.arguments, options.requestEngine);
          return jsonResponse({
            jsonrpc: "2.0",
            id,
            result: { content: [{ type: "text", text: JSON.stringify(result) }], isError: false },
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          return jsonResponse({
            jsonrpc: "2.0",
            id,
            result: { content: [{ type: "text", text: message }], isError: true },
          });
        }
      }
      default:
        return rpcError(id, -32601, "Method not found: " + rpc.method, 404);
    }
  } catch {
    return rpcError(id, -32603, "Internal MCP bridge error", 500);
  }
}
