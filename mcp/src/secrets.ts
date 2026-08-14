import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const SECRET_PURPOSE = "doxa-oauth-secrets:v1";

export type SecretBundle = {
  version: 1;
  adminUsername: string;
  adminPassword: string;
  legacyMcpToken: string;
  tokenPepper: string;
};

type Envelope = {
  version: 1;
  algorithm: "aes-256-gcm";
  purpose: string;
  iv: string;
  tag: string;
  ciphertext: string;
};

function assertKey(key: Buffer): void {
  if (key.length !== 32) throw new Error("OAuth master key must be exactly 32 bytes");
}

function isSecretBundle(value: unknown): value is SecretBundle {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return candidate.version === 1
    && typeof candidate.adminUsername === "string"
    && candidate.adminUsername.length > 0
    && typeof candidate.adminPassword === "string"
    && candidate.adminPassword.length >= 16
    && typeof candidate.legacyMcpToken === "string"
    && typeof candidate.tokenPepper === "string"
    && candidate.tokenPepper.length >= 32;
}

export async function encryptJsonFile(file: string, key: Buffer, value: unknown, purpose: string): Promise<void> {
  assertKey(key);
  const aad = Buffer.from(purpose, "utf8");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
  ]);
  const envelope: Envelope = {
    version: 1,
    algorithm: "aes-256-gcm",
    purpose,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
  await fs.rename(temporary, file);
  await fs.chmod(file, 0o600);
}

export async function decryptJsonFile<T>(file: string, key: Buffer, purpose: string): Promise<T> {
  assertKey(key);
  const envelope = JSON.parse(await fs.readFile(file, "utf8")) as Envelope;
  if (envelope.version !== 1 || envelope.algorithm !== "aes-256-gcm" || envelope.purpose !== purpose) {
    throw new Error("Unsupported encrypted file format or purpose");
  }
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
  decipher.setAAD(Buffer.from(purpose, "utf8"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]);
  const value = JSON.parse(plaintext.toString("utf8")) as T;
  plaintext.fill(0);
  return value;
}

export async function encryptSecretBundle(file: string, key: Buffer, secrets: SecretBundle): Promise<void> {
  if (!isSecretBundle(secrets)) throw new Error("Invalid OAuth secret bundle");
  await encryptJsonFile(file, key, secrets, SECRET_PURPOSE);
}

export async function decryptSecretBundle(file: string, key: Buffer): Promise<SecretBundle> {
  try {
    const secrets = await decryptJsonFile<unknown>(file, key, SECRET_PURPOSE);
    if (!isSecretBundle(secrets)) throw new Error("Invalid decrypted secret bundle");
    return secrets;
  } catch (error) {
    throw new Error("Could not decrypt or authenticate OAuth secret bundle", { cause: error });
  }
}

export async function readMasterKey(file: string): Promise<Buffer> {
  const encoded = (await fs.readFile(file, "utf8")).trim();
  const key = Buffer.from(encoded, "base64");
  assertKey(key);
  return key;
}
