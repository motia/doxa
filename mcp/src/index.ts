import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const ROOT = "/data";
const PORT = Number(process.env.PORT ?? 3000);
const TOKEN = process.env.MCP_TOKEN ?? "";
const MAX_FILE_BYTES = Number(process.env.MCP_MAX_FILE_BYTES ?? 10 * 1024 * 1024);
const ALLOWED = new Set(
  (process.env.MCP_ALLOWED_OPS ?? "read,list,search,write,mkdir,move")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean),
);

if (TOKEN.length < 24) {
  throw new Error("MCP_TOKEN must be at least 24 characters");
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

function requireOp(op: string) {
  if (!enabled(op)) throw new Error(`Operation disabled: ${op}`);
}

function buildServer(): McpServer {
  const server = new McpServer({ name: "koinon-files", version: "0.1.0" });

  server.registerTool("list", {
    description: "List files and directories inside the shared vault.",
    inputSchema: { path: z.string().default(".") },
    annotations: { readOnlyHint: true },
  }, async ({ path: target }) => {
    requireOp("list");
    const full = await safePath(target);
    const entries = await fs.readdir(full, { withFileTypes: true });
    return text(entries.map((e) => ({ name: e.name, type: e.isDirectory() ? "directory" : "file" })));
  });

  server.registerTool("read", {
    description: "Read a UTF-8 text file from the shared vault.",
    inputSchema: { path: z.string() },
    annotations: { readOnlyHint: true },
  }, async ({ path: target }) => {
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
  }, async ({ query, path: target, maxResults }) => {
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
  }, async ({ path: target, content }) => {
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
  }, async ({ path: target }) => {
    requireOp("mkdir");
    const full = await safePath(target, true);
    await fs.mkdir(full, { recursive: true });
    return text({ ok: true, path: safeRelative(target) });
  });

  server.registerTool("move", {
    description: "Move or rename a file/directory inside the shared vault.",
    inputSchema: { from: z.string(), to: z.string() },
    annotations: { readOnlyHint: false, destructiveHint: true },
  }, async ({ from, to }) => {
    requireOp("move");
    const src = await safePath(from);
    const dst = await safePath(to, true);
    await fs.mkdir(path.dirname(dst), { recursive: true });
    await fs.rename(src, dst);
    return text({ ok: true, from: safeRelative(from), to: safeRelative(to) });
  });

  return server;
}

function authenticate(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization") ?? "";
  const provided = header.startsWith("Bearer ") ? header.slice(7) : "";
  const expected = TOKEN;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_req, res) => res.json({ ok: true }));
app.all("/mcp", authenticate, async (req, res) => {
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
