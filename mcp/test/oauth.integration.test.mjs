import assert from "node:assert/strict";
import crypto from "node:crypto";
import { once } from "node:events";
import net from "node:net";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

async function freePort() {
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.equal(typeof address, "object");
  const port = address.port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function startServer(extraEnv = {}) {
  const port = await freePort();
  const child = spawn(process.execPath, ["dist/index.js"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      PORT: String(port),
      MCP_TOKEN: "test-static-token-at-least-24-characters",
      PUBLIC_BASE_URL: "https://doxa.example.test",
      OAUTH_ADMIN_USERNAME: "owner",
      OAUTH_ADMIN_PASSWORD: "correct horse battery staple",
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`server exited: ${stderr}`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return { child, port };
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  child.kill("SIGTERM");
  throw new Error(`server did not become ready: ${stderr}`);
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await once(child, "exit");
}

async function submitConsent(authorizeUrl, username, password, overrides = {}) {
  const authorization = `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
  const consent = await fetch(authorizeUrl, {
    redirect: "manual",
    headers: { authorization },
  });
  assert.equal(consent.status, 200);
  const html = await consent.text();
  assert.match(html, /Authorize Doxa access/);
  assert.match(html, /Requested scopes/);
  assert.match(html, /Redirect URI/);
  const consentId = html.match(/name="consent_id" value="([^"]+)"/)?.[1];
  const csrfToken = html.match(/name="csrf_token" value="([^"]+)"/)?.[1];
  assert.ok(consentId);
  assert.ok(csrfToken);
  const cookie = consent.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(cookie);
  const body = new URLSearchParams({ consent_id: consentId, csrf_token: csrfToken, decision: "approve", ...overrides });
  return fetch(new URL("/approve", authorizeUrl), {
    method: "POST",
    redirect: "manual",
    headers: {
      authorization,
      cookie,
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
}

test("allows unauthenticated discovery and returns a tool-level OAuth challenge", async () => {
  const { child, port } = await startServer();
  const endpoint = `http://127.0.0.1:${port}/mcp`;
  const request = (body) => fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify(body),
  });
  try {
    const initialize = await request({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "ChatGPT", version: "1" } },
    });
    assert.equal(initialize.status, 200);

    const toolsResponse = await request({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    assert.equal(toolsResponse.status, 200);
    const tools = (await toolsResponse.json()).result.tools;
    assert.ok(tools.length >= 6);
    for (const tool of tools) {
      const scope = ["list", "read", "search"].includes(tool.name) ? "doxa:read" : "doxa:write";
      assert.deepEqual(tool._meta.securitySchemes, [{
        type: "oauth2",
        scopes: [scope, "offline_access"],
      }]);
    }

    const callResponse = await request({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "list", arguments: { path: "" } },
    });
    assert.equal(callResponse.status, 200);
    const challenged = (await callResponse.json()).result;
    assert.equal(challenged.isError, true);
    assert.match(challenged._meta["mcp/www_authenticate"][0], /resource_metadata="https:\/\/doxa\.example\.test\/\.well-known\/oauth-protected-resource\/mcp"/);
  } finally {
    await stopServer(child);
  }
});

test("loads encrypted secrets and preserves OAuth clients in encrypted state across restarts", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "doxa-state-"));
  const { encryptSecretBundle } = await import("../dist/secrets.js");
  const key = crypto.randomBytes(32);
  const keyFile = path.join(directory, "oauth-master.key");
  const secretsFile = path.join(directory, "oauth-secrets.enc");
  const stateFile = path.join(directory, "oauth-state.enc");
  await writeFile(keyFile, `${key.toString("base64")}\n`, { mode: 0o600 });
  await encryptSecretBundle(secretsFile, key, {
    version: 1,
    adminUsername: "encrypted-owner",
    adminPassword: "encrypted-owner-password",
    legacyMcpToken: "encrypted-legacy-token-123456",
  });
  const env = {
    MCP_TOKEN: "",
    OAUTH_ADMIN_USERNAME: "",
    OAUTH_ADMIN_PASSWORD: "",
    OAUTH_MASTER_KEY_FILE: keyFile,
    OAUTH_SECRETS_FILE: secretsFile,
    OAUTH_STATE_FILE: stateFile,
  };
  let first;
  try {
    first = await startServer(env);
    const registration = await fetch(`http://127.0.0.1:${first.port}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "ChatGPT Persistent",
        redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    });
    assert.equal(registration.status, 201);
    const client = await registration.json();
    await stopServer(first.child);
    first = undefined;
    const ciphertext = await readFile(stateFile);
    assert.equal(ciphertext.includes(Buffer.from("ChatGPT Persistent")), false);
    assert.equal(ciphertext.includes(Buffer.from("chatgpt.com")), false);

    const second = await startServer(env);
    try {
      const verifier = crypto.randomBytes(32).toString("base64url");
      const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
      const authorize = new URL(`http://127.0.0.1:${second.port}/authorize`);
      authorize.search = new URLSearchParams({
        response_type: "code",
        client_id: client.client_id,
        redirect_uri: client.redirect_uris[0],
        code_challenge: challenge,
        code_challenge_method: "S256",
        scope: "doxa:read offline_access",
        state: "restart-state",
        resource: "https://doxa.example.test/mcp",
      }).toString();
      const response = await submitConsent(authorize, "encrypted-owner", "encrypted-owner-password");
      assert.equal(response.status, 302);
    } finally {
      await stopServer(second.child);
    }
  } finally {
    if (first) await stopServer(first.child);
    await rm(directory, { recursive: true, force: true });
  }
});

test("purges expired and malformed encrypted OAuth records during load", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "doxa-oauth-state-validation-"));
  try {
    const stateFile = path.join(dir, "oauth-state.enc");
    const key = crypto.randomBytes(32);
    const { encryptJsonFile, decryptJsonFile } = await import("../dist/secrets.js");
    const { DoxaOAuthProvider } = await import("../dist/oauth.js");
    const client = {
      client_id: "chatgpt-valid-client",
      client_name: "ChatGPT",
      redirect_uris: ["https://chatgpt.com/connector/oauth/valid-callback-id"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    };
    const now = Date.now();
    await encryptJsonFile(stateFile, key, {
      version: 1,
      clients: [[client.client_id, client]],
      codes: [
        ["expired-code", { clientId: client.client_id, expiresAt: now - 1, params: { redirectUri: client.redirect_uris[0], codeChallenge: "A".repeat(43), scopes: ["doxa:read"], resource: "https://doxa.example.test/mcp" } }],
        ["malformed-code", { clientId: client.client_id, expiresAt: now + 60_000, params: { redirectUri: "https://chatgpt.com/connector/oauth/other", codeChallenge: "bad", scopes: ["doxa:admin"], resource: "https://other.example/mcp" } }],
      ],
      accessTokens: [
        ["access-key", { token: "different-token", clientId: client.client_id, scopes: ["doxa:read"], resource: "https://doxa.example.test/mcp", expiresAt: now + 60_000 }],
      ],
      refreshTokens: [
        ["refresh-key", { token: "refresh-key", clientId: client.client_id, scopes: ["doxa:admin"], resource: "https://doxa.example.test/mcp", expiresAt: now + 60_000 }],
      ],
    }, "doxa-oauth-state:v1");

    const provider = new DoxaOAuthProvider(new URL("https://doxa.example.test/mcp"), { stateFile, stateKey: key });
    await provider.load();
    assert.equal(provider.clientsStore.clients.size, 1);
    assert.equal(provider.codes.size, 0);
    assert.equal(provider.accessTokens.size, 0);
    assert.equal(provider.refreshTokens.size, 0);

    const cleaned = await decryptJsonFile(stateFile, key, "doxa-oauth-state:v1");
    assert.deepEqual(cleaned.codes, []);
    assert.deepEqual(cleaned.accessTokens, []);
    assert.deepEqual(cleaned.refreshTokens, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("encrypts OAuth secrets at rest and rejects the wrong master key", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "doxa-secrets-"));
  try {
    const { encryptSecretBundle, decryptSecretBundle } = await import("../dist/secrets.js");
    const file = path.join(directory, "oauth-secrets.enc");
    const key = crypto.randomBytes(32);
    const secrets = {
      version: 1,
      adminUsername: "owner",
      adminPassword: "correct horse battery staple",
      legacyMcpToken: "legacy-token-value-123456789",
    };
    await encryptSecretBundle(file, key, secrets);
    const ciphertext = await readFile(file);
    assert.equal(ciphertext.includes(Buffer.from(secrets.adminPassword)), false);
    assert.equal(ciphertext.includes(Buffer.from(secrets.legacyMcpToken)), false);
    assert.deepEqual(await decryptSecretBundle(file, key), secrets);
    await assert.rejects(() => decryptSecretBundle(file, crypto.randomBytes(32)), /decrypt|authentic/i);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("requires explicit consent with a valid same-session CSRF token", async () => {
  const { child, port } = await startServer();
  try {
    const registration = await fetch(`http://127.0.0.1:${port}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "ChatGPT CSRF test",
        redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    });
    const client = await registration.json();
    const verifier = crypto.randomBytes(32).toString("base64url");
    const authorize = new URL(`http://127.0.0.1:${port}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      scope: "doxa:read offline_access",
      state: "csrf-state",
      resource: "https://doxa.example.test/mcp",
    }).toString();
    const rejected = await submitConsent(authorize, "owner", "correct horse battery staple", { csrf_token: "wrong-csrf-token" });
    assert.equal(rejected.status, 403);
  } finally {
    await stopServer(child);
  }
});

test("completes PKCE authorization, refresh, and authenticated MCP access", async () => {
  const { child, port } = await startServer();
  try {
    const registration = await fetch(`http://127.0.0.1:${port}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "ChatGPT",
        redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    });
    const client = await registration.json();
    const verifier = crypto.randomBytes(32).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    const authorize = new URL(`http://127.0.0.1:${port}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: "doxa:read offline_access",
      state: "chatgpt-state",
      resource: "https://doxa.example.test/mcp",
    }).toString();
    const approval = await submitConsent(authorize, "owner", "correct horse battery staple");
    assert.equal(approval.status, 302);
    const callback = new URL(approval.headers.get("location"));
    assert.equal(callback.origin + callback.pathname, client.redirect_uris[0]);
    assert.equal(callback.searchParams.get("state"), "chatgpt-state");
    const code = callback.searchParams.get("code");
    assert.ok(code);

    const invalidPkceResponse = await fetch(`http://127.0.0.1:${port}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: client.client_id,
        code,
        code_verifier: crypto.randomBytes(32).toString("base64url"),
        redirect_uri: client.redirect_uris[0],
        resource: "https://doxa.example.test/mcp",
      }),
    });
    assert.equal(invalidPkceResponse.status, 400);
    assert.equal((await invalidPkceResponse.json()).error, "invalid_grant");

    const tokenResponse = await fetch(`http://127.0.0.1:${port}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: client.client_id,
        code,
        code_verifier: verifier,
        redirect_uri: client.redirect_uris[0],
        resource: "https://doxa.example.test/mcp",
      }),
    });
    assert.equal(tokenResponse.status, 200);
    const tokens = await tokenResponse.json();
    assert.match(tokens.access_token, /^[A-Za-z0-9_-]{40,}$/);
    assert.match(tokens.refresh_token, /^[A-Za-z0-9_-]{40,}$/);
    assert.equal(tokens.token_type, "Bearer");

    const initialize = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${tokens.access_token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "ChatGPT", version: "1" } },
      }),
    });
    assert.equal(initialize.status, 200);
    assert.equal((await initialize.json()).result.serverInfo.name, "doxa-files");

    const deniedWrite = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${tokens.access_token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "write", arguments: { path: "scope-test.md", content: "must not be written" } },
      }),
    });
    assert.equal(deniedWrite.status, 200);
    const deniedBody = await deniedWrite.json();
    assert.equal(deniedBody.result.isError, true);
    assert.match(deniedBody.result._meta["mcp/www_authenticate"][0], /insufficient_scope/);

    const refreshResponse = await fetch(`http://127.0.0.1:${port}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: client.client_id,
        refresh_token: tokens.refresh_token,
        resource: "https://doxa.example.test/mcp",
      }),
    });
    assert.equal(refreshResponse.status, 200);
    const refreshed = await refreshResponse.json();
    assert.notEqual(refreshed.access_token, tokens.access_token);
    assert.notEqual(refreshed.refresh_token, tokens.refresh_token);

    const replayResponse = await fetch(`http://127.0.0.1:${port}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: client.client_id,
        refresh_token: tokens.refresh_token,
        resource: "https://doxa.example.test/mcp",
      }),
    });
    assert.equal(replayResponse.status, 400);
    assert.equal((await replayResponse.json()).error, "invalid_grant");
  } finally {
    await stopServer(child);
  }
});

test("does not count successful owner authorization pages toward the failure limit", async () => {
  const { child, port } = await startServer();
  try {
    const registration = await fetch(`http://127.0.0.1:${port}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "ChatGPT retry test",
        redirect_uris: ["https://chatgpt.com/connector/oauth/retry-callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    });
    const client = await registration.json();
    const verifier = crypto.randomBytes(32).toString("base64url");
    const authorize = new URL(`http://127.0.0.1:${port}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      scope: "doxa:read offline_access",
      state: "retry-state",
      resource: "https://doxa.example.test/mcp",
    }).toString();
    const authorization = `Basic ${Buffer.from("owner:correct horse battery staple").toString("base64")}`;
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const response = await fetch(authorize, { headers: { authorization } });
      assert.equal(response.status, 200);
    }
  } finally {
    await stopServer(child);
  }
});

test("rate limits failed owner authentication attempts", async () => {
  const { child, port } = await startServer();
  try {
    let response;
    for (let attempt = 0; attempt < 6; attempt += 1) {
      response = await fetch(`http://127.0.0.1:${port}/authorize`, {
        headers: { authorization: `Basic ${Buffer.from("owner:wrong-password-value").toString("base64")}` },
      });
    }
    assert.equal(response.status, 429);
  } finally {
    await stopServer(child);
  }
});

test("requires owner authentication at the authorization endpoint", async () => {
  const { child, port } = await startServer();
  try {
    const response = await fetch(`http://127.0.0.1:${port}/authorize`);
    assert.equal(response.status, 401);
    assert.match(response.headers.get("www-authenticate") ?? "", /^Basic /);
  } finally {
    await stopServer(child);
  }
});

test("rejects dynamically registered clients with non-ChatGPT redirect URIs", async () => {
  const { child, port } = await startServer();
  try {
    const response = await fetch(`http://127.0.0.1:${port}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Attacker",
        redirect_uris: ["https://attacker.example/oauth/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "invalid_client_metadata");
  } finally {
    await stopServer(child);
  }
});

test("dynamically registers a public OAuth client", async () => {
  const { child, port } = await startServer();
  try {
    const response = await fetch(`http://127.0.0.1:${port}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "ChatGPT",
        redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    });
    assert.equal(response.status, 201);
    const client = await response.json();
    assert.match(client.client_id, /^[0-9a-f-]{36}$/);
    assert.equal(client.client_secret, undefined);
    assert.deepEqual(client.redirect_uris, ["https://chatgpt.com/connector/oauth/callback"]);
  } finally {
    await stopServer(child);
  }
});

test("publishes OAuth protected-resource and authorization-server metadata", async () => {
  const { child, port } = await startServer();
  try {
    const resource = await fetch(`http://127.0.0.1:${port}/.well-known/oauth-protected-resource/mcp`);
    assert.equal(resource.status, 200);
    assert.deepEqual(await resource.json(), {
      resource: "https://doxa.example.test/mcp",
      authorization_servers: ["https://doxa.example.test/"],
      scopes_supported: ["doxa:read", "doxa:write", "offline_access"],
      resource_name: "Doxa",
    });

    const authorization = await fetch(`http://127.0.0.1:${port}/.well-known/oauth-authorization-server`);
    assert.equal(authorization.status, 200);
    const metadata = await authorization.json();
    assert.equal(metadata.issuer, "https://doxa.example.test/");
    assert.equal(metadata.authorization_endpoint, "https://doxa.example.test/authorize");
    assert.equal(metadata.token_endpoint, "https://doxa.example.test/token");
    assert.equal(metadata.registration_endpoint, "https://doxa.example.test/register");
    assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
    assert.ok(metadata.grant_types_supported.includes("refresh_token"));
  } finally {
    await stopServer(child);
  }
});
