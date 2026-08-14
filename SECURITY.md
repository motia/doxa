# Security

This project is intended first for a private/single-user deployment.

## Important boundaries

- Never mount the full vault into the MCP container. Mount only `Shared/`.
- Never expose the MCP or Syncthing GUI ports directly to the public Internet.
- Keep the OAuth owner login, legacy token, master key, and encrypted runtime files out of source control; preserve mode `0600` on credential files.
- Use HTTPS for the public OAuth/MCP endpoint; HTTP Basic protects only the owner consent step and depends on TLS.
- Keep Dynamic Client Registration restricted to exact ChatGPT connector callback URLs. Authorization must always require the explicit, CSRF-protected consent screen; never turn authenticated `/authorize` requests directly into codes.
- Treat Syncthing as synchronization, not backup.

## Commercial/multi-user deployments

The included OAuth server is designed for a private single-owner deployment and is not a complete multi-tenant identity system. Before commercial hosting, use a hardened identity provider and add tenant isolation, per-user permissions, audit logs, stronger rate-limit controls, managed keys, and tested backups/restores.
