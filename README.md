# Koinon

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
git clone git@github.com:motia/koinon.git
cd koinon
cp .env.example .env
```

Generate a long token and place it in `.env`:

```bash
openssl rand -hex 32
```

Create the vault areas and start the services:

```bash
mkdir -p data/vault/{Shared,Private}
docker compose up -d --build
```

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

## MCP authentication

The MCP endpoint uses a static bearer token:

```http
Authorization: Bearer <MCP_TOKEN>
```

The endpoint is:

```text
http://127.0.0.1:3010/mcp
```

The token is a simple service credential, suitable for a private/single-user deployment. For a multi-user commercial deployment, replace it with proper OAuth/OIDC and per-user authorization.

## Cloudflare Tunnel

Do not expose port 3010 directly. Route a hostname through your existing Cloudflare Tunnel to the loopback service, for example:

```yaml
ingress:
  - hostname: vault-mcp.example.com
    service: http://127.0.0.1:3010
```

On the Motiavated managed controller, the MCP service joins the external Docker `web` network and is registered through the existing `managed-dev` stack:

```bash
COMPOSE_PROJECT_NAME=koinon-managed \
  docker compose -f docker-compose.yml -f docker-compose.managed.yml up -d --build
chmod +x scripts/register-managed-dev.py
scripts/register-managed-dev.py
```

This publishes the managed service at:

```text
https://koinon-managed.motiavated.com/mcp
```

The `-managed` suffix is the convention for persistent managed services. The registration points Traefik directly at `http://koinon-managed-mcp:3000`; it does not expose the loopback port. To remove only the external route while preserving Koinon data and containers, run `managed-dev remove-route koinon-managed`.

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
- MCP requires a bearer token.
- MCP rejects `..` traversal and symlinks.
- MCP container runs as an unprivileged Node user with a read-only root filesystem and `no-new-privileges`.
- Syncthing discovery/sync ports remain available so devices can synchronize.

For multi-user/hosted commercialization, add OAuth/OIDC, tenant-specific vault isolation, audit logging, quotas, encrypted secret management, and stronger lifecycle/backup controls before treating this as a production multi-tenant service.

## Why not run Obsidian on the VPS?

Obsidian remains the human-facing desktop/mobile client. The VPS hosts only the synchronized filesystem and AI access layer. This keeps the stored data as normal files and allows other clients to use the same vault format later.

## License

MIT
