import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { rateLimit } from "express-rate-limit";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { DoxaOAuthProvider } from "./oauth.js";
import { decryptSecretBundle, readMasterKey } from "./secrets.js";

const ROOT = "/data";
const PORT = Number(process.env.PORT ?? 3000);
let TOKEN = process.env.MCP_TOKEN ?? "";
const PUBLIC_BASE_URL = new URL(process.env.PUBLIC_BASE_URL ?? "http://127.0.0.1:3000");
const MCP_RESOURCE_URL = new URL("/mcp", PUBLIC_BASE_URL).href;
let OAUTH_ADMIN_USERNAME = process.env.OAUTH_ADMIN_USERNAME ?? "";
let OAUTH_ADMIN_PASSWORD = process.env.OAUTH_ADMIN_PASSWORD ?? "";
const OAUTH_MASTER_KEY_FILE = process.env.OAUTH_MASTER_KEY_FILE;
const OAUTH_SECRETS_FILE = process.env.OAUTH_SECRETS_FILE;
const OAUTH_STATE_FILE = process.env.OAUTH_STATE_FILE;
let oauthMasterKey: Buffer | undefined;
if (OAUTH_MASTER_KEY_FILE || OAUTH_SECRETS_FILE) {
  if (!OAUTH_MASTER_KEY_FILE || !OAUTH_SECRETS_FILE) {
    throw new Error("OAUTH_MASTER_KEY_FILE and OAUTH_SECRETS_FILE must be configured together");
  }
  oauthMasterKey = await readMasterKey(OAUTH_MASTER_KEY_FILE);
  const encryptedSecrets = await decryptSecretBundle(OAUTH_SECRETS_FILE, oauthMasterKey);
  TOKEN = encryptedSecrets.legacyMcpToken;
  OAUTH_ADMIN_USERNAME = encryptedSecrets.adminUsername;
  OAUTH_ADMIN_PASSWORD = encryptedSecrets.adminPassword;
}
const MAX_FILE_BYTES = Number(process.env.MCP_MAX_FILE_BYTES ?? 10 * 1024 * 1024);
const ALLOWED = new Set(
  (process.env.MCP_ALLOWED_OPS ?? "read,list,search,write,mkdir,move")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean),
);

if (TOKEN.length < 24) {
  throw new Error("MCP_TOKEN or encrypted legacyMcpToken must be at least 24 characters");
}
if (!OAUTH_ADMIN_USERNAME || OAUTH_ADMIN_PASSWORD.length < 16) {
  throw new Error("OAuth owner credentials are missing or too short");
}
if (OAUTH_STATE_FILE && !oauthMasterKey) {
  throw new Error("OAUTH_STATE_FILE requires encrypted secrets and a master key");
}

function enabled(op: string): boolean {
  return ALLOWED.has(op);
}

function safeRelative(input: string): string {
  if (input.includes("\0")) throw new Error("Invalid path");
  const normalized = path.posix.normalize("/" + input.replaceAll("\\", "/")).slice(1);
  if (normalized === ".." || normalized.startsWith("../")) throw new Error("Path escapes vault");
  return normalized;
}

async function safePath(input: string, allowMissing = false): Promise<string> {
  const rel = safeRelative(input);
  const candidate = path.resolve(ROOT, rel);
  const root = path.resolve(ROOT);
  if (candidate !== root && !candidate.startsWith(root + path.sep)) throw new Error("Path escapes vault");

  // Block symlink traversal for existing ancestors.
  let current = root;
  for (const part of rel.split("/").filter(Boolean)) {
    current = path.join(current, part);
    try {
      const st = await fs.lstat(current);
      if (st.isSymbolicLink()) throw new Error("Symlinks are not allowed");
    } catch (err: any) {
      if (err?.code === "ENOENT" && allowMissing) break;
      throw err;
    }
  }
  return candidate;
}

function text(value: unknown) {
  return { content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] };
}

function securityMeta(scope: "doxa:read" | "doxa:write") {
  return {
    securitySchemes: [{ type: "oauth2", scopes: [scope, "offline_access"] }],
  };
}

function authorizationChallenge(authInfo: AuthInfo | undefined, scope: "doxa:read" | "doxa:write") {
  if (authInfo?.scopes.includes(scope)) return undefined;
  const error = authInfo ? "insufficient_scope" : "invalid_token";
  const description = authInfo ? `The ${scope} scope is required` : "Authentication is required";
  const metadata = new URL("/.well-known/oauth-protected-resource/mcp", PUBLIC_BASE_URL).href;
  return {
    content: [{ type: "text" as const, text: description }],
    isError: true,
    _meta: {
      "mcp/www_authenticate": [
        `Bearer error="${error}", error_description="${description}", resource_metadata="${metadata}", scope="${scope} offline_access"`,
      ],
    },
  };
}

function requireOp(op: string) {
  if (!enabled(op)) throw new Error(`Operation disabled: ${op}`);
}

function buildServer(): McpServer {
  const server = new McpServer({ name: "doxa-files", version: "0.1.0" });

  server.registerTool("list", {
    description: "List files and directories inside the shared vault.",
    inputSchema: { path: z.string().default(".") },
    annotations: { readOnlyHint: true },
    _meta: securityMeta("doxa:read"),
  }, async ({ path: target }, extra) => {
    const challenge = authorizationChallenge(extra.authInfo, "doxa:read");
    if (challenge) return challenge;
    requireOp("list");
    const full = await safePath(target);
    const entries = await fs.readdir(full, { withFileTypes: true });
    return text(entries.map((e) => ({ name: e.name, type: e.isDirectory() ? "directory" : "file" })));
  });

  server.registerTool("read", {
    description: "Read a UTF-8 text file from the shared vault.",
    inputSchema: { path: z.string() },
    annotations: { readOnlyHint: true },
    _meta: securityMeta("doxa:read"),
  }, async ({ path: target }, extra) => {
    const challenge = authorizationChallenge(extra.authInfo, "doxa:read");
    if (challenge) return challenge;
    requireOp("read");
    const full = await safePath(target);
    const st = await fs.stat(full);
    if (!st.isFile()) throw new Error("Not a file");
    if (st.size > MAX_FILE_BYTES) throw new Error(`File exceeds ${MAX_FILE_BYTES} bytes`);
    return text(await fs.readFile(full, "utf8"));
  });

  server.registerTool("search", {
    description: "Search UTF-8 text files by filename or text. Binary and oversized files are skipped.",
    inputSchema: {
      query: z.string().min(1),
      path: z.string().default("."),
      maxResults: z.number().int().min(1).max(100).default(20),
    },
    annotations: { readOnlyHint: true },
    _meta: securityMeta("doxa:read"),
  }, async ({ query, path: target, maxResults }, extra) => {
    const challenge = authorizationChallenge(extra.authInfo, "doxa:read");
    if (challenge) return challenge;
    requireOp("search");
    const start = await safePath(target);
    const q = query.toLowerCase();
    const results: Array<{ path: string; match: "name" | "content" }> = [];

    async function walk(dir: string): Promise<void> {
      if (results.length >= maxResults) return;
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (results.length >= maxResults) return;
        const full = path.join(dir, entry.name);
        const rel = path.relative(ROOT, full).split(path.sep).join("/");
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          await walk(full);
          continue;
        }
        if (!entry.isFile()) continue;
        if (entry.name.toLowerCase().includes(q)) {
          results.push({ path: rel, match: "name" });
          continue;
        }
        try {
          const st = await fs.stat(full);
          if (st.size > MAX_FILE_BYTES) continue;
          const buffer = await fs.readFile(full);
          if (buffer.includes(0)) continue;
          if (buffer.toString("utf8").toLowerCase().includes(q)) results.push({ path: rel, match: "content" });
        } catch {
          // Skip unreadable files.
        }
      }
    }

    await walk(start);
    return text(results);
  });

  server.registerTool("write", {
    description: "Create or replace a UTF-8 text file in the shared vault.",
    inputSchema: { path: z.string(), content: z.string() },
    annotations: { readOnlyHint: false, destructiveHint: true },
    _meta: securityMeta("doxa:write"),
  }, async ({ path: target, content }, extra) => {
    const challenge = authorizationChallenge(extra.authInfo, "doxa:write");
    if (challenge) return challenge;
    requireOp("write");
    if (Buffer.byteLength(content, "utf8") > MAX_FILE_BYTES) throw new Error(`Content exceeds ${MAX_FILE_BYTES} bytes`);
    const full = await safePath(target, true);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content, { encoding: "utf8", mode: 0o664 });
    return text({ ok: true, path: safeRelative(target) });
  });

  server.registerTool("mkdir", {
    description: "Create a directory inside the shared vault.",
    inputSchema: { path: z.string() },
    annotations: { readOnlyHint: false },
    _meta: securityMeta("doxa:write"),
  }, async ({ path: target }, extra) => {
    const challenge = authorizationChallenge(extra.authInfo, "doxa:write");
    if (challenge) return challenge;
    requireOp("mkdir");
    const full = await safePath(target, true);
    await fs.mkdir(full, { recursive: true });
    return text({ ok: true, path: safeRelative(target) });
  });

  server.registerTool("move", {
    description: "Move or rename a file/directory inside the shared vault.",
    inputSchema: { from: z.string(), to: z.string() },
    annotations: { readOnlyHint: false, destructiveHint: true },
    _meta: securityMeta("doxa:write"),
  }, async ({ from, to }, extra) => {
    const challenge = authorizationChallenge(extra.authInfo, "doxa:write");
    if (challenge) return challenge;
    requireOp("move");
    const src = await safePath(from);
    const dst = await safePath(to, true);
    await fs.mkdir(path.dirname(dst), { recursive: true });
    await fs.rename(src, dst);
    return text({ ok: true, from: safeRelative(from), to: safeRelative(to) });
  });

  return server;
}

function ownerAuthenticate(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization") ?? "";
  const encoded = header.startsWith("Basic ") ? header.slice(6) : "";
  let username = "";
  let password = "";
  try {
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator >= 0) {
      username = decoded.slice(0, separator);
      password = decoded.slice(separator + 1);
    }
  } catch {}
  const supplied = Buffer.from(`${username}\0${password}`);
  const expected = Buffer.from(`${OAUTH_ADMIN_USERNAME}\0${OAUTH_ADMIN_PASSWORD}`);
  if (!OAUTH_ADMIN_USERNAME || !OAUTH_ADMIN_PASSWORD || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Doxa OAuth", charset="UTF-8"');
    res.status(401).send("Owner authentication required");
    return;
  }
  next();
}

async function resolveAuth(req: Request): Promise<AuthInfo | undefined> {
  const header = req.header("authorization") ?? "";
  const provided = header.startsWith("Bearer ") ? header.slice(7) : "";
  const staticToken = Buffer.from(TOKEN);
  const candidate = Buffer.from(provided);
  if (TOKEN && candidate.length === staticToken.length && crypto.timingSafeEqual(candidate, staticToken)) {
    return {
      token: provided,
      clientId: "legacy-static-token",
      scopes: ["doxa:read", "doxa:write", "offline_access"],
      resource: new URL(MCP_RESOURCE_URL),
    };
  }
  if (!provided) return undefined;
  try {
    return await oauthProvider.verifyAccessToken(provided);
  } catch {
    return undefined;
  }
}

const oauthProvider = new DoxaOAuthProvider(new URL(MCP_RESOURCE_URL), {
  stateFile: OAUTH_STATE_FILE,
  stateKey: oauthMasterKey,
});
await oauthProvider.load();
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use("/authorize", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many authorization attempts; try again later.",
}), ownerAuthenticate);
app.post("/approve",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: "Too many authorization confirmations; try again later.",
  }),
  ownerAuthenticate,
  express.urlencoded({ extended: false, limit: "16kb" }),
  async (req, res) => {
    const consentId = typeof req.body?.consent_id === "string" ? req.body.consent_id : "";
    const csrfToken = typeof req.body?.csrf_token === "string" ? req.body.csrf_token : "";
    const decision = typeof req.body?.decision === "string" ? req.body.decision : "";
    const cookieHeader = req.header("cookie") ?? "";
    const sessionToken = cookieHeader
      .split(";")
      .map((entry) => entry.trim())
      .find((entry) => entry.startsWith("doxa_oauth_session="))
      ?.slice("doxa_oauth_session=".length) ?? "";
    if (consentId.length > 256 || csrfToken.length > 256 || sessionToken.length > 256) {
      res.status(400).send("Invalid authorization confirmation");
      return;
    }
    await oauthProvider.approveConsent(consentId, csrfToken, sessionToken, decision, res);
  },
);
app.use(mcpAuthRouter({
  provider: oauthProvider,
  issuerUrl: PUBLIC_BASE_URL,
  resourceServerUrl: new URL(MCP_RESOURCE_URL),
  scopesSupported: ["doxa:read", "doxa:write", "offline_access"],
  resourceName: "Doxa",
  clientRegistrationOptions: { clientSecretExpirySeconds: 0 },
}));

app.get("/health", (_req, res) => res.json({ ok: true }));
app.all("/mcp", async (req, res) => {
  const authInfo = await resolveAuth(req);
  if (authInfo) (req as Request & { auth?: AuthInfo }).auth = authInfo;
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error(error);
    if (!res.headersSent) res.status(500).json({ error: "internal_error" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP listening on :${PORT}/mcp; root=${ROOT}; ops=${[...ALLOWED].join(",")}`);
});
