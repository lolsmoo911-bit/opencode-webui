/**
 * Small authenticated MCP Streamable HTTP bridge for OpenCode.
 *
 * This intentionally exposes only status, session listing, and prompt submission.
 * It does not expose shell or arbitrary engine endpoints.
 */
type EngineAccess = { url: string; headers: Record<string, string> };
type BridgeOptions = {
  token: string;
  resolveEngine: () => Promise<EngineAccess>;
};

const PROTOCOL_VERSION = "2025-03-26";
const MAX_BODY_BYTES = 64 * 1024;
const MAX_PROMPT_CHARS = 12_000;

function jsonRpc(id: unknown, result: unknown): Response {
  return Response.json({ jsonrpc: "2.0", id, result }, {
    headers: { "cache-control": "no-store" },
  });
}

function rpcError(id: unknown, code: number, message: string): Response {
  return Response.json({ jsonrpc: "2.0", id, error: { code, message } }, {
    headers: { "cache-control": "no-store" },
  });
}

function constantTimeTokenMatch(supplied: string, expected: string): boolean {
  if (!supplied || !expected) return false;
  // Hash before comparing so the comparison operands are always fixed length.
  const digest = (value: string) => new Bun.CryptoHasher("sha256").update(value).digest("hex");
  const a = digest(supplied);
  const b = digest(expected);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function engineRequest(
  engine: EngineAccess,
  paths: string[],
  init: RequestInit = {},
): Promise<Response> {
  let last: Response | undefined;
  for (const path of paths) {
    const response = await fetch(new URL(path, engine.url.endsWith("/") ? engine.url : engine.url + "/"), {
      ...init,
      headers: {
        ...engine.headers,
        accept: "application/json",
        "accept-encoding": "identity",
        ...(init.headers as Record<string, string> | undefined),
      },
      redirect: "manual",
      signal: AbortSignal.timeout(25_000),
    });
    if (response.status !== 404 && response.status !== 405) return response;
    last = response;
  }
  return last ?? new Response("engine route unavailable", { status: 502 });
}

async function responseJson(response: Response): Promise<any> {
  const text = await response.text();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return { message: text.slice(0, 2000) }; }
}

function toolsResult(tools: unknown[]) {
  return { tools };
}

const TOOLS = [
  {
    name: "opencode_status",
    description: "Check whether the connected OpenCode engine is reachable.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "opencode_list_sessions",
    description: "List recent OpenCode sessions for the engine's default workspace.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "opencode_start_task",
    description: "Create an OpenCode session and submit a coding task to its default workspace. Returns the session ID so the task can be followed in OpenCode.",
    inputSchema: {
      type: "object",
      properties: {
        prompt: { type: "string", minLength: 1, maxLength: MAX_PROMPT_CHARS, description: "The coding task to give OpenCode." },
        title: { type: "string", maxLength: 100, description: "Optional short session title." },
      },
      required: ["prompt"],
      additionalProperties: false,
    },
  },
];

async function callTool(name: string, args: Record<string, unknown>, options: BridgeOptions) {
  const engine = await options.resolveEngine();
  if (name === "opencode_status") {
    const response = await engineRequest(engine, ["/global/health", "/health", "/api/health"]);
    const data = await responseJson(response);
    if (!response.ok) throw new Error(`OpenCode health check failed (${response.status}): ${JSON.stringify(data)}`);
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, status: data }) }], structuredContent: { ok: true, status: data } };
  }

  if (name === "opencode_list_sessions") {
    const response = await engineRequest(engine, ["/session", "/api/session"]);
    const data = await responseJson(response);
    if (!response.ok) throw new Error(`Could not list sessions (${response.status}): ${JSON.stringify(data)}`);
    return { content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: { sessions: data } };
  }

  if (name === "opencode_start_task") {
    const prompt = args.prompt;
    const title = args.title;
    if (typeof prompt !== "string" || prompt.trim().length === 0 || prompt.length > MAX_PROMPT_CHARS) {
      throw new Error(`prompt must be 1-${MAX_PROMPT_CHARS} characters`);
    }
    if (title !== undefined && (typeof title !== "string" || title.length > 100)) {
      throw new Error("title must be a string of at most 100 characters");
    }
    const create = await engineRequest(engine, ["/session", "/api/session"], {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(title ? { title } : {}),
    });
    const created = await responseJson(create);
    if (!create.ok) throw new Error(`Could not create OpenCode session (${create.status}): ${JSON.stringify(created)}`);
    const sessionId = created?.id ?? created?.data?.id ?? created?.sessionID;
    if (typeof sessionId !== "string" || !sessionId) throw new Error("OpenCode created a session but did not return its ID");

    const queued = await engineRequest(engine, [
      `/session/${encodeURIComponent(sessionId)}/prompt_async`,
      `/api/session/${encodeURIComponent(sessionId)}/prompt`,
    ], {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ parts: [{ type: "text", text: prompt.trim() }], prompt: { text: prompt.trim() } }),
    });
    if (!queued.ok) {
      const error = await responseJson(queued);
      throw new Error(`Session ${sessionId} was created, but OpenCode rejected the task (${queued.status}): ${JSON.stringify(error)}`);
    }
    const result = {
      accepted: true,
      sessionID: sessionId,
      title: typeof created?.title === "string" ? created.title : (typeof title === "string" ? title : "OpenCode task"),
      message: "Task submitted to OpenCode's default workspace. Check this session in OpenCode for progress and results.",
    };
    return { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result };
  }

  throw new Error(`Unknown tool: ${name}`);
}

/** Return a response for /mcp, or null when this module does not own the request. */
export async function handleMcpBridgeRequest(req: Request, options: BridgeOptions): Promise<Response | null> {
  const url = new URL(req.url);
  if (url.pathname !== "/mcp") return null;
  if (req.method !== "POST") {
    return new Response("MCP endpoint accepts POST only", {
      status: 405,
      headers: { allow: "POST", "cache-control": "no-store" },
    });
  }

  const authorization = req.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!match || !constantTimeTokenMatch(match[1] ?? "", options.token)) {
    return new Response("Unauthorized", {
      status: 401,
      headers: { "www-authenticate": 'Bearer realm="opencode-mcp"', "cache-control": "no-store" },
    });
  }

  const origin = req.headers.get("origin");
  if (origin) {
    // Cross-origin browser calls are unnecessary for server-side MCP clients.
    // Reject browsers while allowing non-browser clients that omit Origin.
    return new Response("Origin header is not supported by this server-to-server endpoint", { status: 403 });
  }

  let raw: string;
  try {
    raw = await req.text();
    if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
      return new Response("Request too large", { status: 413 });
    }
  } catch {
    return new Response("Invalid request body", { status: 400 });
  }

  let rpc: any;
  try { rpc = JSON.parse(raw); } catch { return new Response("Invalid JSON", { status: 400 }); }
  if (!rpc || typeof rpc !== "object" || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") {
    return rpcError(rpc?.id ?? null, -32600, "Invalid JSON-RPC request");
  }

  // Notifications have no id and must not receive a JSON-RPC response.
  const hasId = Object.prototype.hasOwnProperty.call(rpc, "id");
  if (rpc.method === "notifications/initialized" || rpc.method === "notifications/cancelled") {
    return new Response(null, { status: 202 });
  }
  if (!hasId) return new Response(null, { status: 202 });

  if (rpc.method === "initialize") {
    return jsonRpc(rpc.id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: { name: "opencode-webui-bridge", version: "0.1.0" },
      instructions: "Use opencode_start_task to submit tasks to the OpenCode engine's default workspace.",
    });
  }

  if (rpc.method === "ping") return jsonRpc(rpc.id, {});
  if (rpc.method === "tools/list") return jsonRpc(rpc.id, toolsResult(TOOLS));
  if (rpc.method === "tools/call") {
    const params = rpc.params ?? {};
    if (typeof params.name !== "string" || !params.arguments || typeof params.arguments !== "object" || Array.isArray(params.arguments)) {
      return rpcError(rpc.id, -32602, "tools/call requires a tool name and object arguments");
    }
    try {
      const result = await callTool(params.name, params.arguments, options);
      return jsonRpc(rpc.id, result);
    } catch (error) {
      return jsonRpc(rpc.id, {
        content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        isError: true,
      });
    }
  }

  return rpcError(rpc.id, -32601, `Method not found: ${rpc.method}`);
}
