import crypto from "node:crypto";
import type { Response } from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { decryptJsonFile, encryptJsonFile } from "./secrets.js";

const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

function opaqueToken(): string {
  return crypto.randomBytes(48).toString("base64url");
}

type CodeRecord = {
  clientId: string;
  params: AuthorizationParams;
  expiresAt: number;
};

type TokenRecord = {
  token: string;
  clientId: string;
  scopes: string[];
  resource: URL;
  expiresAt: number;
};

type PendingConsent = {
  clientId: string;
  params: AuthorizationParams;
  csrfHash: string;
  sessionHash: string;
  expiresAt: number;
};

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function isAllowedChatGptRedirect(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && url.origin === "https://chatgpt.com"
      && !url.username
      && !url.password
      && !url.search
      && !url.hash
      && ((url.pathname.startsWith("/connector/oauth/") && url.pathname.length > "/connector/oauth/".length)
        || url.pathname === "/connector_platform_oauth_redirect");
  } catch {
    return false;
  }
}

class MemoryClientsStore implements OAuthRegisteredClientsStore {
  readonly clients = new Map<string, OAuthClientInformationFull>();

  constructor(private readonly onChange: () => Promise<void>) {}

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  async registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> {
    if (!client.redirect_uris.length || !client.redirect_uris.every(isAllowedChatGptRedirect)) {
      throw new InvalidClientMetadataError("All redirect_uris must match a documented ChatGPT connector callback pattern");
    }
    this.clients.set(client.client_id, client);
    await this.onChange();
    return client;
  }
}

type ProviderOptions = {
  stateFile?: string;
  stateKey?: Buffer;
};

type StoredTokenRecord = Omit<TokenRecord, "resource"> & { resource: string };
type StoredCodeRecord = Omit<CodeRecord, "params"> & {
  params: Omit<AuthorizationParams, "resource"> & { resource?: string };
};
type StoredState = {
  version: 1;
  clients: Array<[string, OAuthClientInformationFull]>;
  codes: Array<[string, StoredCodeRecord]>;
  accessTokens: Array<[string, StoredTokenRecord]>;
  refreshTokens: Array<[string, StoredTokenRecord]>;
};

const ALLOWED_SCOPES = new Set(["doxa:read", "doxa:write", "offline_access"]);

function hasValidScopes(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((scope) => typeof scope === "string" && ALLOWED_SCOPES.has(scope));
}

function hasValidExpiry(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > Date.now();
}

function isValidStoredClient(key: unknown, value: unknown): value is OAuthClientInformationFull {
  if (!value || typeof value !== "object") return false;
  const client = value as Partial<OAuthClientInformationFull>;
  return typeof key === "string"
    && typeof client.client_id === "string"
    && key === client.client_id
    && Array.isArray(client.redirect_uris)
    && client.redirect_uris.length > 0
    && client.redirect_uris.every((uri) => typeof uri === "string" && isAllowedChatGptRedirect(uri))
    && client.token_endpoint_auth_method === "none";
}

function isValidStoredCode(
  key: unknown,
  value: unknown,
  clients: Map<string, OAuthClientInformationFull>,
  resourceUrl: URL,
): value is StoredCodeRecord {
  if (typeof key !== "string" || key.length < 40 || !value || typeof value !== "object") return false;
  const record = value as Partial<StoredCodeRecord>;
  const params = record.params as Record<string, unknown> | undefined;
  const client = typeof record.clientId === "string" ? clients.get(record.clientId) : undefined;
  return !!client
    && hasValidExpiry(record.expiresAt)
    && !!params
    && typeof params.redirectUri === "string"
    && client.redirect_uris.includes(params.redirectUri)
    && typeof params.codeChallenge === "string"
    && /^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)
    && hasValidScopes(params.scopes)
    && params.resource === resourceUrl.href;
}

function isValidStoredToken(
  key: unknown,
  value: unknown,
  clients: Map<string, OAuthClientInformationFull>,
  resourceUrl: URL,
): value is StoredTokenRecord {
  if (typeof key !== "string" || key.length < 40 || !value || typeof value !== "object") return false;
  const record = value as Partial<StoredTokenRecord>;
  return record.token === key
    && typeof record.clientId === "string"
    && clients.has(record.clientId)
    && hasValidScopes(record.scopes)
    && record.resource === resourceUrl.href
    && hasValidExpiry(record.expiresAt);
}

export class DoxaOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: MemoryClientsStore;
  readonly codes = new Map<string, CodeRecord>();
  readonly accessTokens = new Map<string, TokenRecord>();
  readonly refreshTokens = new Map<string, TokenRecord>();
  readonly pendingConsents = new Map<string, PendingConsent>();
  private saveQueue = Promise.resolve();

  constructor(private readonly resourceUrl: URL, private readonly options: ProviderOptions = {}) {
    this.clientsStore = new MemoryClientsStore(() => this.persist());
    if ((options.stateFile && !options.stateKey) || (!options.stateFile && options.stateKey)) {
      throw new Error("OAuth stateFile and stateKey must be configured together");
    }
  }

  async load(): Promise<void> {
    if (!this.options.stateFile || !this.options.stateKey) return;
    try {
      const state = await decryptJsonFile<StoredState>(
        this.options.stateFile,
        this.options.stateKey,
        "doxa-oauth-state:v1",
      );
      if (state.version !== 1
        || !Array.isArray(state.clients)
        || !Array.isArray(state.codes)
        || !Array.isArray(state.accessTokens)
        || !Array.isArray(state.refreshTokens)) {
        throw new Error("Unsupported or malformed OAuth state structure");
      }
      this.clientsStore.clients.clear();
      let dirty = false;
      for (const entry of state.clients) {
        if (Array.isArray(entry) && entry.length === 2 && isValidStoredClient(entry[0], entry[1])) {
          this.clientsStore.clients.set(entry[0], entry[1]);
        } else {
          dirty = true;
        }
      }
      this.codes.clear();
      for (const entry of state.codes) {
        if (Array.isArray(entry) && entry.length === 2
          && isValidStoredCode(entry[0], entry[1], this.clientsStore.clients, this.resourceUrl)) {
          const [key, value] = entry;
          this.codes.set(key, {
            ...value,
            params: {
              ...value.params,
              resource: new URL(value.params.resource!),
            },
          });
        } else {
          dirty = true;
        }
      }
      this.accessTokens.clear();
      for (const entry of state.accessTokens) {
        if (Array.isArray(entry) && entry.length === 2
          && isValidStoredToken(entry[0], entry[1], this.clientsStore.clients, this.resourceUrl)) {
          const [key, value] = entry;
          this.accessTokens.set(key, { ...value, resource: new URL(value.resource) });
        } else {
          dirty = true;
        }
      }
      this.refreshTokens.clear();
      for (const entry of state.refreshTokens) {
        if (Array.isArray(entry) && entry.length === 2
          && isValidStoredToken(entry[0], entry[1], this.clientsStore.clients, this.resourceUrl)) {
          const [key, value] = entry;
          this.refreshTokens.set(key, { ...value, resource: new URL(value.resource) });
        } else {
          dirty = true;
        }
      }
      if (dirty) await this.persist();
    } catch (error: any) {
      if (error?.cause?.code === "ENOENT" || error?.code === "ENOENT") return;
      throw error;
    }
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (!client.redirect_uris.includes(params.redirectUri)) {
      throw new InvalidRequestError("Unregistered redirect_uri");
    }
    this.assertResource(params.resource);
    this.assertScopes(params.scopes ?? []);
    this.prunePendingConsents();
    const consentId = opaqueToken();
    const csrfToken = opaqueToken();
    const sessionToken = opaqueToken();
    this.pendingConsents.set(consentId, {
      clientId: client.client_id,
      params,
      csrfHash: sha256(csrfToken),
      sessionHash: sha256(sessionToken),
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
    res.setHeader("Set-Cookie", `doxa_oauth_session=${sessionToken}; Path=/approve; HttpOnly; Secure; SameSite=Strict; Max-Age=300`);
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    res.setHeader("X-Frame-Options", "DENY");
    res.status(200).type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize Doxa access</title>
<style>body{font:16px system-ui;max-width:44rem;margin:4rem auto;padding:0 1rem;color:#162033}dl{background:#f4f6fa;padding:1rem;border-radius:.5rem}dt{font-weight:700;margin-top:.7rem}dd{margin:.2rem 0;overflow-wrap:anywhere}.actions{display:flex;gap:.75rem;margin-top:1.5rem}button{padding:.7rem 1rem;border:0;border-radius:.4rem;background:#174ea6;color:white;font-weight:700}button[value=deny]{background:#59636e}</style></head>
<body><h1>Authorize Doxa access</h1><p>Review this request before granting access to your shared vault.</p>
<dl><dt>Client</dt><dd>${escapeHtml(client.client_name ?? client.client_id)}</dd><dt>Redirect URI</dt><dd>${escapeHtml(params.redirectUri)}</dd><dt>Requested scopes</dt><dd>${escapeHtml((params.scopes ?? []).join(" "))}</dd></dl>
<form method="post" action="/approve"><input type="hidden" name="consent_id" value="${consentId}"><input type="hidden" name="csrf_token" value="${csrfToken}"><div class="actions"><button type="submit" name="decision" value="approve">Authorize</button><button type="submit" name="decision" value="deny">Deny</button></div></form></body></html>`);
  }

  async approveConsent(consentId: string, csrfToken: string, sessionToken: string, decision: string, res: Response): Promise<void> {
    this.prunePendingConsents();
    const pending = this.pendingConsents.get(consentId);
    if (!pending
      || !safeEqual(pending.csrfHash, sha256(csrfToken))
      || !safeEqual(pending.sessionHash, sha256(sessionToken))) {
      res.status(403).send("Invalid or expired authorization confirmation");
      return;
    }
    this.pendingConsents.delete(consentId);
    const client = this.clientsStore.getClient(pending.clientId);
    if (!client || !client.redirect_uris.includes(pending.params.redirectUri)) {
      res.status(400).send("Invalid OAuth client");
      return;
    }
    const callback = new URL(pending.params.redirectUri);
    if (pending.params.state) callback.searchParams.set("state", pending.params.state);
    if (decision !== "approve") {
      callback.searchParams.set("error", "access_denied");
      res.redirect(302, callback.href);
      return;
    }
    const code = opaqueToken();
    this.codes.set(code, {
      clientId: client.client_id,
      params: pending.params,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
    await this.persist();
    callback.searchParams.set("code", code);
    res.redirect(302, callback.href);
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const record = this.validCode(client, authorizationCode);
    return record.params.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const record = this.validCode(client, authorizationCode);
    if (redirectUri && redirectUri !== record.params.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request");
    }
    this.assertResource(resource ?? record.params.resource);
    this.codes.delete(authorizationCode);
    return this.issueTokens(client.client_id, record.params.scopes ?? [], resource ?? record.params.resource);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const record = this.refreshTokens.get(refreshToken);
    if (!record || record.clientId !== client.client_id || record.expiresAt <= Date.now()) {
      throw new InvalidGrantError("Invalid or expired refresh token");
    }
    const requestedScopes = scopes ?? record.scopes;
    if (!requestedScopes.every((scope) => record.scopes.includes(scope))) {
      throw new InvalidScopeError("Refresh scope exceeds the originally granted scope");
    }
    this.assertResource(resource ?? record.resource);
    this.refreshTokens.delete(refreshToken);
    return this.issueTokens(client.client_id, requestedScopes, resource ?? record.resource);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = this.accessTokens.get(token);
    if (!record || record.expiresAt <= Date.now()) {
      throw new InvalidTokenError("Invalid or expired access token");
    }
    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: Math.floor(record.expiresAt / 1000),
      resource: record.resource,
    };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const access = this.accessTokens.get(request.token);
    if (access?.clientId === client.client_id) this.accessTokens.delete(request.token);
    const refresh = this.refreshTokens.get(request.token);
    if (refresh?.clientId === client.client_id) this.refreshTokens.delete(request.token);
    await this.persist();
  }

  private validCode(client: OAuthClientInformationFull, code: string): CodeRecord {
    const record = this.codes.get(code);
    if (!record || record.clientId !== client.client_id || record.expiresAt <= Date.now()) {
      throw new InvalidGrantError("Invalid or expired authorization code");
    }
    return record;
  }

  private assertResource(resource?: URL): asserts resource is URL {
    if (!resource || resource.href !== this.resourceUrl.href) {
      throw new InvalidRequestError(`Invalid resource; expected ${this.resourceUrl.href}`);
    }
  }

  private assertScopes(scopes: string[]): void {
    if (!hasValidScopes(scopes)) {
      throw new InvalidScopeError("Unsupported scope requested");
    }
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, value] of this.codes) if (value.expiresAt <= now) this.codes.delete(key);
    for (const [key, value] of this.accessTokens) if (value.expiresAt <= now) this.accessTokens.delete(key);
    for (const [key, value] of this.refreshTokens) if (value.expiresAt <= now) this.refreshTokens.delete(key);
  }

  private prunePendingConsents(): void {
    const now = Date.now();
    for (const [key, value] of this.pendingConsents) {
      if (value.expiresAt <= now) this.pendingConsents.delete(key);
    }
  }

  private snapshot(): StoredState {
    this.pruneExpired();
    return {
      version: 1,
      clients: [...this.clientsStore.clients.entries()],
      codes: [...this.codes.entries()].map(([key, value]) => [key, {
        ...value,
        params: {
          ...value.params,
          resource: value.params.resource?.href,
        },
      }]),
      accessTokens: [...this.accessTokens.entries()].map(([key, value]) => [key, {
        ...value,
        resource: value.resource.href,
      }]),
      refreshTokens: [...this.refreshTokens.entries()].map(([key, value]) => [key, {
        ...value,
        resource: value.resource.href,
      }]),
    };
  }

  private async persist(): Promise<void> {
    if (!this.options.stateFile || !this.options.stateKey) return;
    this.saveQueue = this.saveQueue
      .catch(() => undefined)
      .then(() => encryptJsonFile(
        this.options.stateFile!,
        this.options.stateKey!,
        this.snapshot(),
        "doxa-oauth-state:v1",
      ));
    await this.saveQueue;
  }

  private async issueTokens(clientId: string, scopes: string[], resource?: URL): Promise<OAuthTokens> {
    this.assertResource(resource);
    const now = Date.now();
    const accessToken = opaqueToken();
    const refreshToken = opaqueToken();
    this.accessTokens.set(accessToken, {
      token: accessToken,
      clientId,
      scopes,
      resource,
      expiresAt: now + ACCESS_TOKEN_TTL_SECONDS * 1000,
    });
    this.refreshTokens.set(refreshToken, {
      token: refreshToken,
      clientId,
      scopes,
      resource,
      expiresAt: now + REFRESH_TOKEN_TTL_SECONDS * 1000,
    });
    await this.persist();
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      scope: scopes.join(" "),
    };
  }
}
