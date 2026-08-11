# Security

This project is intended first for a private/single-user deployment.

## Important boundaries

- Never mount the full vault into the MCP container. Mount only `Shared/`.
- Never expose the MCP or Syncthing GUI ports directly to the public Internet.
- Use a long random `MCP_TOKEN` and keep `.env` out of source control.
- Treat Syncthing as synchronization, not backup.

## Commercial/multi-user deployments

The included bearer-token authentication is deliberately small and is not a complete multi-tenant identity system. Before commercial hosting, add OAuth/OIDC, tenant isolation, per-user permissions, audit logs, rate limits, secret management, and tested backups/restores.
