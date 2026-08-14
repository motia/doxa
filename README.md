# Doxa

A tiny self-hosted vault hub for Obsidian (or any folder-based Markdown client):

- **Syncthing** synchronizes one vault across desktop/mobile/VPS.
- **Private/** stays user-only.
- **Shared/** is the only directory mounted into the MCP container.
- A small **Streamable HTTP MCP server** exposes an explicit allowlist of file operations.
- Both web UIs/API ports bind to loopback by default. Use an existing Cloudflare Tunnel if remote MCP access is needed.

```text
Obsidian desktop/mobile
        ↕
     Syncthing
        ↕
  VPS vault root
   ├── Shared/  ──> MCP ──> ChatGPT / remote agents
   └── Private/      (not mounted into MCP)
```

The privacy boundary is a Docker bind mount, not merely an application rule: the MCP container receives `${VAULT_PATH}/Shared` as `/data` and cannot see `Private/`.

## Requirements

- Docker Engine + Docker Compose
- An Obsidian client (optional; any folder-based client works)
- For remote MCP access: a trusted HTTPS ingress such as Cloudflare Tunnel

## Quick start

```bash
git clone git@github.com:motia/doxa.git
cd doxa
cp .env.example .env
```

Create the vault areas, build the secret-management utility, and initialize the encrypted OAuth bundle:

```bash
mkdir -p data/vault/{Shared,Private} data/oauth/state
cd mcp
npm ci
npm run build
MCP_TOKEN="$(openssl rand -hex 32)" \
  npm run secrets -- init \
  ../data/oauth/oauth-master.key \
  ../data/oauth/oauth-secrets.enc \
  motia
cd ..
chmod 700 data/oauth data/oauth/state
chmod 600 data/oauth/oauth-master.key data/oauth/oauth-secrets.enc
docker compose up -d --build
```

The generated OAuth owner password is stored only inside the encrypted bundle. Retrieve it later from a private terminal using the `show` command documented below.

Check status:

```bash
docker compose ps
curl http://127.0.0.1:3010/health
```

## Syncthing setup

The Syncthing admin UI is deliberately bound to loopback:

```text
127.0.0.1:8384
```

From your laptop, tunnel it over SSH when configuring the VPS device:

```bash
ssh -L 8384:127.0.0.1:8384 user@your-vps
```

Then open `http://127.0.0.1:8384` locally.

Configure a Syncthing folder pointing to `/vault` inside the container. On each client, sync that folder to your Obsidian vault.

The synced vault should look like:

```text
Vault/
├── Shared/
│   ├── Projects/
│   ├── Plans/
│   └── Notes/
└── Private/
    ├── Personal/
    └── Journal/
```

Moving a note between `Private/` and `Shared/` in Obsidian changes whether AI tools can see it after Syncthing propagates the move.

## MCP tools

Default tool set:

- `list` — list a directory
- `read` — read a UTF-8 text file
- `search` — filename/content search
- `write` — create or replace a UTF-8 text file
- `mkdir` — create directories
- `move` — move/rename files and directories

There is intentionally **no delete tool** and no shell/process execution.

Change the exposed tool set with:

```dotenv
MCP_ALLOWED_OPS=read,list,search,write,mkdir,move
```

For a read-only deployment:

```dotenv
MCP_ALLOWED_OPS=read,list,search
```

## MCP authentication and ChatGPT

Doxa includes an OAuth 2.1 authorization server compatible with remote MCP clients. It provides:

- OAuth authorization-server metadata
- MCP protected-resource metadata
- Dynamic Client Registration restricted to exact ChatGPT HTTPS connector callback URLs
- explicit owner consent with the client name, exact redirect URI, requested scopes, and same-session CSRF protection
- authorization-code flow with PKCE `S256`
- one-hour access tokens
- rotating 30-day refresh tokens
- token revocation
- encrypted persistent registration/token state

Public endpoint:

```text
https://doxa-managed.motiavated.com/mcp
```

Discovery endpoints:

```text
https://doxa-managed.motiavated.com/.well-known/oauth-protected-resource/mcp
https://doxa-managed.motiavated.com/.well-known/oauth-authorization-server
```

ChatGPT can call MCP `initialize` and `tools/list` without credentials so it can discover the app. Every file tool declares its required OAuth scope (`doxa:read` or `doxa:write`) and returns an MCP `mcp/www_authenticate` challenge when authorization is missing. No vault data is returned anonymously.

The `/authorize` endpoint first uses a single-owner HTTPS Basic challenge, then displays an explicit consent screen showing the client, exact redirect URI, and requested scopes. Approval requires a short-lived same-session CSRF token. Retrieve the owner login only in a private server terminal:

```bash
cd mcp
npm run build
npm run secrets -- show \
  ../data/oauth/oauth-master.key \
  ../data/oauth/oauth-secrets.enc
```

Never post that output in chat, logs, tickets, or source control.

To connect ChatGPT on the web:

1. Enable **Developer mode** under ChatGPT **Settings → Security and login**.
2. Open **Apps/Plugins**, select **Create app**, and name it `Doxa`.
3. Set the MCP server URL to `https://doxa-managed.motiavated.com/mcp`.
4. Select **OAuth** authentication. Dynamic registration supplies the client details.
5. When the browser opens Doxa authorization, enter the owner username/password from the private `show` command.
6. Approve the app and confirm ChatGPT discovers `list`, `read`, `search`, `write`, `mkdir`, and `move`.

Doxa retains the former static bearer token as a legacy credential for trusted clients, but that token now lives only in the encrypted bundle. ChatGPT uses OAuth instead.

### Encrypted files

```text
data/oauth/oauth-secrets.enc   AES-256-GCM encrypted owner login and legacy token
data/oauth/state/oauth-state.enc  AES-256-GCM encrypted clients, codes, and tokens
data/oauth/oauth-master.key    Separate 256-bit decryption key, mode 0600
```

The key and encrypted files are runtime data under ignored `data/`; none are committed. Keeping the decryption key beside the ciphertext protects against accidental plaintext disclosure and repository leakage, but not a root-level compromise of the host. For a stronger threat model, mount the key from a secret manager or hardware-backed store.

## Cloudflare Tunnel

Do not expose port 3010 directly. Route a hostname through your existing Cloudflare Tunnel to the loopback service, for example:

```yaml
ingress:
  - hostname: vault-mcp.example.com
    service: http://127.0.0.1:3010
```

On the Motiavated managed controller, the MCP service joins the external Docker `web` network and is registered through the existing `managed-dev` stack:

```bash
COMPOSE_PROJECT_NAME=doxa-managed \
  docker compose -f docker-compose.yml -f docker-compose.managed.yml up -d --build
chmod +x scripts/register-managed-dev.py
scripts/register-managed-dev.py
```

This publishes the managed service at:

```text
https://doxa-managed.motiavated.com/mcp
```

The `-managed` suffix is the convention for persistent managed services. The registration points Traefik directly at `http://doxa-managed-mcp:3000`; it does not expose the loopback port. To remove only the external route while preserving Doxa data and containers, run `managed-dev remove-route doxa-managed`.

The MCP endpoint then becomes:

```text
https://vault-mcp.example.com/mcp
```

Keep application-level MCP authentication enabled even when using Cloudflare Tunnel. Cloudflare Access can be added where your MCP client supports the chosen authentication flow.

## Filesystem isolation

Syncthing gets the whole vault:

```yaml
- ${VAULT_PATH}:/vault
```

MCP gets only the shared area:

```yaml
- ${VAULT_PATH}/Shared:/data
```

Even if the MCP server has a bug, `/Private` is not mounted into its container.

The MCP server additionally rejects path traversal and symlink traversal.

## File ownership

The official Syncthing image defaults to UID/GID 1000 and supports `PUID`/`PGID`. Set these in `.env` to the owner that should manage the vault files on the VPS.

If Hermes runs directly on the VPS, give its service user access to `Shared/` only when possible. Do not grant it access to `Private/` just for convenience.

## Backups

Syncthing is synchronization, not backup. Back up the VPS vault independently and consider Syncthing file versioning for accidental edits/deletions.

## Security model

- MCP container physically sees only `Shared/`.
- MCP has no delete or shell tool.
- Tool exposure is allowlisted with `MCP_ALLOWED_OPS`.
- MCP and Syncthing GUI bind to localhost.
- MCP requires OAuth 2.1 with PKCE, with a retained encrypted legacy token for trusted clients.
- OAuth credentials and persistent client/token state are encrypted at rest with AES-256-GCM.
- MCP rejects `..` traversal and symlinks.
- MCP container runs as an unprivileged Node user with a read-only root filesystem and `no-new-privileges`.
- Syncthing discovery/sync ports remain available so devices can synchronize.

For multi-user/hosted commercialization, replace the single-owner authorization gate with a hardened external identity provider, add tenant-specific vault isolation, audit logging, quotas, managed key storage, and stronger lifecycle/backup controls before treating this as a production multi-tenant service.

## Why not run Obsidian on the VPS?

Obsidian remains the human-facing desktop/mobile client. The VPS hosts only the synchronized filesystem and AI access layer. This keeps the stored data as normal files and allows other clients to use the same vault format later.

## License

MIT
