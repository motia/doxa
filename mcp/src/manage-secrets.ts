import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { decryptSecretBundle, encryptSecretBundle, readMasterKey } from "./secrets.js";

function usage(): never {
  throw new Error("Usage: manage-secrets <init|show> <master-key-file> <encrypted-secrets-file> [username]");
}

const [, , command, masterKeyFile, secretsFile, usernameArg] = process.argv;
if (!command || !masterKeyFile || !secretsFile) usage();

if (command === "init") {
  const legacyMcpToken = process.env.MCP_TOKEN ?? "";
  if (legacyMcpToken.length < 24) throw new Error("Set MCP_TOKEN to the existing 24+ character service token");
  const adminUsername = usernameArg ?? process.env.OAUTH_ADMIN_USERNAME ?? "motia";
  const adminPassword = process.env.OAUTH_ADMIN_PASSWORD ?? crypto.randomBytes(24).toString("base64url");
  if (adminPassword.length < 16) throw new Error("OAUTH_ADMIN_PASSWORD must be at least 16 characters");
  const key = crypto.randomBytes(32);
  await fs.mkdir(path.dirname(masterKeyFile), { recursive: true, mode: 0o700 });
  await fs.mkdir(path.dirname(secretsFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(masterKeyFile, `${key.toString("base64")}\n`, { mode: 0o600, flag: "wx" });
  await encryptSecretBundle(secretsFile, key, {
    version: 1,
    adminUsername,
    adminPassword,
    legacyMcpToken,
    tokenPepper: crypto.randomBytes(32).toString("base64url"),
  });
  console.log(`Encrypted OAuth secrets created at ${secretsFile}`);
  console.log(`Master key created at ${masterKeyFile}`);
  console.log("Run the show command in a private terminal when you need the OAuth owner login.");
} else if (command === "show") {
  const key = await readMasterKey(masterKeyFile);
  const secrets = await decryptSecretBundle(secretsFile, key);
  console.log(`OAuth owner username: ${secrets.adminUsername}`);
  console.log(`OAuth owner password: ${secrets.adminPassword}`);
  console.log(`Legacy MCP token: ${secrets.legacyMcpToken}`);
} else {
  usage();
}
