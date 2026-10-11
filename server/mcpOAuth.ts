import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const AUTH_SERVER_PATH = "/.well-known/oauth-authorization-server";
const RESOURCE_PATHS = new Set(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]);
const AUTH_CODE_TTL_SECONDS = 5 * 60;
const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const MAX_BODY_BYTES = 32 * 1024;
const ALLOWED_SCOPES = new Set(["opencode:read", "opencode:write", "offline_access"]);
const USED_CODES = new Set<string>();

type JsonRecord = Record<string, unknown>;
type RegisteredClient = { client_id: string; redirect_uris: string[]; client_name?: string };
type AuthorizationPayload = {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  resource: string;
  exp: number;
  jti: string;
};
type AccessPayload = { scope: string; resource: string; exp: number; sub: string };

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return Response.json(data, {
    status,
    headers: { "cache-control": "no-store", pragma: "no-cache", ...extraHeaders },
  });
}
function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, status);
}
function b64url(input: string | Uint8Array): string {
  return Buffer.from(input).toString("base64url");
}
function parseB64urlJson<T>(value: string): T | null {
  try { return JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as T; } catch { return null; }
}
function signingKey(secret: string): Buffer {
  return createHmac("sha256", secret).update("opencode-webui/oauth/signing-key/v1").digest();
}
function sign(secret: string, prefix: string, payload: unknown): string {
  const encoded = b64url(JSON.stringify(payload));
  const signature = createHmac("sha256", signingKey(secret)).update(prefix + "." + encoded).digest("base64url");
  return prefix + "." + encoded + "." + signature;
}
function verify(secret: string, token: string, prefix: string): JsonRecord | null {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== prefix) return null;
  const encoded = parts[1]!;
  const signature = parts[2]!;
  const expected = createHmac("sha256", signingKey(secret)).update(prefix + "." + encoded).digest();
  let got: Buffer;
  try { got = Buffer.from(signature, "base64url"); } catch { return null; }
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return null;
  const payload = parseB64urlJson<JsonRecord>(encoded);
  if (!payload || typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}
function escapeHtml(input: string): string {
  return input.replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
}
function validSecret(supplied: string, expected: string): boolean {
  if (!expected || expected.length < 32) return false;
  const left = createHash("sha256").update(supplied).digest();
  const right = createHash("sha256").update(expected).digest();
  return timingSafeEqual(left, right);
}
function validChatGptRedirect(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const uri = new URL(value);
    if (uri.protocol !== "https:" || uri.hostname !== "chatgpt.com" || uri.username || uri.password || uri.hash) return false;
    return uri.pathname === "/connector_platform_oauth_redirect" ||
      /^\/connector\/oauth\/[A-Za-z0-9_-]{1,200}$/.test(uri.pathname);
  } catch {
    return false;
  }
}
function parseClientId(clientId: string, secret: string): RegisteredClient | null {
  const signed = verify(secret, clientId, "client");
  if (signed && typeof signed.client_id === "string" && Array.isArray(signed.redirect_uris) &&
      signed.redirect_uris.length > 0 && signed.redirect_uris.every(validChatGptRedirect)) {
    return { client_id: signed.client_id, redirect_uris: signed.redirect_uris as string[],
      ...(typeof signed.client_name === "string" ? { client_name: signed.client_name } : {}) };
  }
  // ChatGPT can use its documented Client ID Metadata Document (CIMD) client IDs.
  // Redirect URIs are still strictly allow-listed at authorization time.
  if (/^https:\/\/chatgpt\.com\/oauth\/(?:[A-Za-z0-9_-]+\/)?client\.json$/.test(clientId)) {
    return { client_id: clientId, redirect_uris: [
      "https://chatgpt.com/connector_platform_oauth_redirect",
    ] };
  }
  return null;
}
export function publicMcpOrigin(req: Request): string {
  const requestUrl = new URL(req.url);
  const forwardedHost = req.headers.get("x-forwarded-host")?.split(",")[0]?.trim();
  const host = forwardedHost || req.headers.get("host")?.split(",")[0]?.trim() || requestUrl.host;
  const forwardedProto = req.headers.get("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
  const protocol = forwardedProto === "https" || forwardedProto === "http"
    ? forwardedProto
    : requestUrl.protocol.replace(/:$/, "");
  try {
    return new URL(protocol + "://" + host).origin;
  } catch {
    return requestUrl.origin;
  }
}
function expectedResource(origin: string): string {
  return origin.replace(/\/$/, "") + "/mcp";
}
function decodeForm(value: string): URLSearchParams {
  return new URLSearchParams(value);
}
function htmlResponse(html: string): Response {
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}
function issueAccessToken(secret: string, payload: AccessPayload): string {
  return sign(secret, "access", payload);
}

/** Validate a Bearer token for the MCP endpoint; returns OAuth scopes for OAuth-issued tokens. */
export function verifyMcpAccessToken(token: string, secret: string | undefined, resource: string): { scopes: string[] } | null {
  if (!secret || secret.length < 32) return null;
  const payload = verify(secret, token, "access");
  if (!payload || payload.resource !== resource) return null;
  const scope = typeof payload.scope === "string" ? payload.scope : "";
  return { scopes: scope.split(/\s+/).filter(Boolean) };
}

/**
 * OAuth 2.1 authorization-code + PKCE endpoints for ChatGPT's remote MCP client.
 * The existing high-entropy WEBUI_MCP_TOKEN is used only on the HTTPS consent
 * page; OAuth access tokens issued to ChatGPT are short-lived and scoped.
 */
export async function handleMcpOAuthRequest(req: Request, configuredSecret?: string): Promise<Response | null> {
  const url = new URL(req.url);
  const origin = publicMcpOrigin(req);
  const resource = expectedResource(origin);
  const secret = configuredSecret ?? process.env.WEBUI_MCP_TOKEN;

  if (url.pathname === AUTH_SERVER_PATH && req.method === "GET") {
    return json({
      issuer: origin,
      authorization_endpoint: origin + "/oauth/authorize",
      token_endpoint: origin + "/oauth/token",
      registration_endpoint: origin + "/oauth/register",
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: [...ALLOWED_SCOPES],
      authorization_response_iss_parameter_supported: true,
      resource_parameter_supported: true,
    });
  }

  if (RESOURCE_PATHS.has(url.pathname) && req.method === "GET") {
    return json({
      resource,
      authorization_servers: [origin],
      scopes_supported: [...ALLOWED_SCOPES],
      resource_documentation: origin + "/",
    });
  }

  if (!url.pathname.startsWith("/oauth/")) return null;
  if (!secret || secret.length < 32) return oauthError("server_error", "MCP OAuth is not configured with a sufficiently long secret.", 503);

  if (url.pathname === "/oauth/register" && req.method === "POST") {
    let body: JsonRecord;
    try {
      const raw = await req.text();
      if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) return oauthError("invalid_client_metadata", "Request body too large.", 413);
      body = JSON.parse(raw) as JsonRecord;
    } catch {
      return oauthError("invalid_client_metadata", "Expected a JSON client registration request.");
    }
    const redirects = body.redirect_uris;
    if (!Array.isArray(redirects) || redirects.length < 1 || redirects.length > 5 || !redirects.every(validChatGptRedirect)) {
      return oauthError("invalid_redirect_uri", "Only approved HTTPS ChatGPT callback URLs are allowed.");
    }
    const grants = body.grant_types;
    if (grants !== undefined && (!Array.isArray(grants) || !grants.every(x => x === "authorization_code"))) {
      return oauthError("invalid_client_metadata", "Only the authorization_code grant is supported.");
    }
    const responseTypes = body.response_types;
    if (responseTypes !== undefined && (!Array.isArray(responseTypes) || !responseTypes.every(x => x === "code"))) {
      return oauthError("invalid_client_metadata", "Only the code response type is supported.");
    }
    const clientName = typeof body.client_name === "string" ? body.client_name.slice(0, 100) : "ChatGPT MCP client";
    // Registration data is signed into the client ID so server restarts do not lose it.
    const payload = {
      client_id: "chatgpt-" + randomBytes(18).toString("hex"),
      redirect_uris: redirects,
      client_name: clientName,
      exp: Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60,
    };
    const signedClientId = sign(secret, "client", payload);
    return json({
      client_id: signedClientId,
      client_name: clientName,
      redirect_uris: redirects,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, 201);
  }

  if (url.pathname === "/oauth/authorize" && req.method === "GET") {
    const query = url.searchParams;
    const clientId = query.get("client_id") ?? "";
    const client = parseClientId(clientId, secret);
    const redirectUri = query.get("redirect_uri") ?? "";
    const challenge = query.get("code_challenge") ?? "";
    const method = query.get("code_challenge_method") ?? "";
    const scopes = (query.get("scope") ?? "opencode:read opencode:write offline_access").split(/\s+/).filter(Boolean);
    const requestedResource = query.get("resource") ?? resource;
    const responseType = query.get("response_type");
    const state = query.get("state") ?? "";
    if (!client || responseType !== "code" || !client.redirect_uris.includes(redirectUri) ||
        !validChatGptRedirect(redirectUri) || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) ||
        method !== "S256" || requestedResource !== resource ||
        scopes.some(scope => !ALLOWED_SCOPES.has(scope)) || state.length > 1000) {
      return oauthError("invalid_request", "Invalid OAuth authorization request.");
    }
    const hidden = (name: string, value: string) =>
      `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`;
    const page = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Connect OpenCode WebUI</title><style>body{font:16px system-ui;max-width:480px;margin:8vh auto;padding:24px;color:#202124}label,input{display:block;width:100%;box-sizing:border-box}input{padding:12px;margin:8px 0 18px;border:1px solid #aaa;border-radius:8px}button{padding:12px 18px;border:0;border-radius:8px;background:#222;color:white;font-weight:600}small{color:#555}.scope{padding:12px;background:#f4f4f4;border-radius:8px;margin:16px 0}</style></head><body><h1>Connect OpenCode WebUI</h1><p>ChatGPT is requesting permission to connect to your OpenCode instance.</p><div class="scope"><b>Access requested</b><br>${scopes.map(escapeHtml).join(", ")}</div><p>Enter the value you saved as <code>WEBUI_MCP_TOKEN</code> in Prisma. The token is checked on this server and is not sent back to ChatGPT.</p><form method="post" action="/oauth/authorize">${hidden("client_id", clientId)}${hidden("redirect_uri", redirectUri)}${hidden("response_type", "code")}${hidden("code_challenge", challenge)}${hidden("code_challenge_method", method)}${hidden("scope", scopes.join(" "))}${hidden("resource", requestedResource)}${hidden("state", state)}<label for="mcp_token">Prisma MCP token</label><input id="mcp_token" name="mcp_token" type="password" autocomplete="current-password" required minlength="32"><button type="submit">Authorize ChatGPT</button></form><p><small>Only grant access to a client you trust. The write permission allows OpenCode to receive prompts that can modify project files.</small></p></body></html>`;
    return htmlResponse(page);
  }

  if (url.pathname === "/oauth/authorize" && req.method === "POST") {
    let form: URLSearchParams;
    try {
      const raw = await req.text();
      if (raw.length > MAX_BODY_BYTES) return oauthError("invalid_request", "Request body too large.", 413);
      form = decodeForm(raw);
    } catch {
      return oauthError("invalid_request", "Invalid form data.");
    }
    const submitted = form.get("mcp_token") ?? "";
    if (!validSecret(submitted, secret)) {
      return htmlResponse("<!doctype html><html><body><h1>Authorization failed</h1><p>The token was not accepted. Return and try again.</p></body></html>");
    }
    const clientId = form.get("client_id") ?? "";
    const client = parseClientId(clientId, secret);
    const redirectUri = form.get("redirect_uri") ?? "";
    const challenge = form.get("code_challenge") ?? "";
    const method = form.get("code_challenge_method") ?? "";
    const requestedResource = form.get("resource") ?? resource;
    const state = form.get("state") ?? "";
    const scopes = (form.get("scope") ?? "opencode:read opencode:write offline_access").split(/\s+/).filter(Boolean);
    if (!client || !client.redirect_uris.includes(redirectUri) || !validChatGptRedirect(redirectUri) ||
        !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) || method !== "S256" || requestedResource !== resource ||
        scopes.some(scope => !ALLOWED_SCOPES.has(scope))) {
      return oauthError("invalid_request", "The authorization request changed or is invalid.");
    }
    const payload: AuthorizationPayload = {
      client_id: clientId, redirect_uri: redirectUri, code_challenge: challenge,
      scope: scopes.join(" "), resource: requestedResource,
      exp: Math.floor(Date.now() / 1000) + AUTH_CODE_TTL_SECONDS,
      jti: randomBytes(18).toString("base64url"),
    };
    const code = sign(secret, "code", payload);
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", code);
    if (state) callback.searchParams.set("state", state);
    callback.searchParams.set("iss", origin);
    return Response.redirect(callback.toString(), 302);
  }

  if (url.pathname === "/oauth/token" && req.method === "POST") {
    let form: URLSearchParams;
    try {
      const raw = await req.text();
      if (raw.length > MAX_BODY_BYTES) return oauthError("invalid_request", "Request body too large.", 413);
      form = decodeForm(raw);
    } catch {
      return oauthError("invalid_request", "Invalid form data.");
    }
    const grantType = form.get("grant_type") ?? "";
    if (grantType === "refresh_token") {
      const refreshToken = form.get("refresh_token") ?? "";
      const payload = verify(secret, refreshToken, "refresh") as AccessPayload | null;
      const requestedResource = form.get("resource") ?? resource;
      if (!payload || payload.resource !== resource || requestedResource !== resource ||
          !payload.scope.split(/\s+/).includes("offline_access")) {
        return oauthError("invalid_grant", "Refresh token is invalid, expired, or not valid for this resource.");
      }
      const now = Math.floor(Date.now() / 1000);
      const accessScopes = payload.scope.split(/\s+/).filter(scope => scope !== "offline_access");
      const accessToken = issueAccessToken(secret, {
        scope: accessScopes.join(" "), resource, exp: now + ACCESS_TOKEN_TTL_SECONDS,
        sub: payload.sub,
      });
      const rotatedRefreshToken = sign(secret, "refresh", {
        scope: payload.scope, resource, exp: now + REFRESH_TOKEN_TTL_SECONDS,
        sub: payload.sub,
      } satisfies AccessPayload);
      return json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        scope: accessScopes.join(" "),
        refresh_token: rotatedRefreshToken,
      });
    }
    if (grantType !== "authorization_code") {
      return oauthError("unsupported_grant_type", "Only authorization_code and refresh_token are supported.");
    }
    const code = form.get("code") ?? "";
    const payload = verify(secret, code, "code") as AuthorizationPayload | null;
    const clientId = form.get("client_id") ?? "";
    const redirectUri = form.get("redirect_uri") ?? "";
    const verifier = form.get("code_verifier") ?? "";
    const resourceParam = form.get("resource") ?? (payload?.resource ?? "");
    if (!payload || !parseClientId(clientId, secret) || payload.client_id !== clientId ||
        payload.redirect_uri !== redirectUri || resourceParam !== resource ||
        !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
      return oauthError("invalid_grant", "Authorization code or PKCE verifier is invalid.");
    }
    const expectedChallenge = createHash("sha256").update(verifier).digest("base64url");
    if (expectedChallenge !== payload.code_challenge || USED_CODES.has(payload.jti)) {
      return oauthError("invalid_grant", "Authorization code has expired or was already used.");
    }
    USED_CODES.add(payload.jti);
    const now = Math.floor(Date.now() / 1000);
    const subject = b64url(randomBytes(12));
    const accessScopes = payload.scope.split(/\s+/).filter(scope => scope !== "offline_access");
    const accessToken = issueAccessToken(secret, {
      scope: accessScopes.join(" "), resource, exp: now + ACCESS_TOKEN_TTL_SECONDS,
      sub: subject,
    });
    const response: JsonRecord = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      scope: accessScopes.join(" "),
    };
    if (payload.scope.split(/\s+/).includes("offline_access")) {
      response.refresh_token = sign(secret, "refresh", {
        scope: payload.scope, resource, exp: now + REFRESH_TOKEN_TTL_SECONDS,
        sub: subject,
      } satisfies AccessPayload);
    }
    return json(response, 200, { pragma: "no-cache" });
  }

  return new Response("Method Not Allowed", {
    status: 405,
    headers: { allow: url.pathname === "/oauth/register" || url.pathname === "/oauth/token" ? "POST" : "GET, POST", "cache-control": "no-store" },
  });
}
