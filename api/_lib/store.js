import crypto from "node:crypto";
import { get, put } from "@vercel/blob";

function getBlobPath() {
  const prefix = (process.env.BLOB_SECRET_PREFIX || "").trim();
  if (!prefix) throw new Error("BLOB_SECRET_PREFIX is not configured");
  return `private/${prefix}/codes.json`;
}

function getSessionSecret() {
  const secret = (process.env.SESSION_SECRET || "").trim();
  if (!secret) throw new Error("SESSION_SECRET is not configured");
  return secret;
}

export function normalizeCode(raw) {
  return String(raw || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "-");
}

export function generateRandomCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(6);
  let part = "";
  for (let i = 0; i < 6; i++) {
    part += alphabet[bytes[i] % alphabet.length];
  }
  return `FH-${part}`;
}

export function verifyPin(inputPin) {
  const expected = (process.env.ADMIN_PIN || "").trim();
  if (!expected) return false;
  const a = crypto.createHash("sha256").update(String(inputPin || "").trim()).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

export function signAdminToken() {
  const now = Date.now();
  const exp = now + 30 * 24 * 60 * 60 * 1000; // 30 days
  const payload = { role: "owner", iat: now, exp };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = crypto
    .createHmac("sha256", getSessionSecret())
    .update(body)
    .digest("base64url");
  return { token: `${body}.${sig}`, expiresAt: new Date(exp).toISOString() };
}

export function verifyAdminToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.trim().split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  if (!body || !sig) return null;
  try {
    const expectedSig = crypto
      .createHmac("sha256", getSessionSecret())
      .update(body)
      .digest("base64url");
    const a = Buffer.from(sig, "utf8");
    const b = Buffer.from(expectedSig, "utf8");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload || payload.role !== "owner") return null;
    if (typeof payload.exp !== "number" || Date.now() > payload.exp) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

export async function loadCodes() {
  const pathname = getBlobPath();
  try {
    const result = await get(pathname, {
      access: "public",
      useCache: false
    });
    if (!result || !result.stream) {
      return { version: 1, codes: {} };
    }
    const text = await new Response(result.stream).text();
    if (!text.trim()) return { version: 1, codes: {} };
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || typeof parsed.codes !== "object") {
      return { version: 1, codes: {} };
    }
    return parsed;
  } catch (err) {
    const msg = String(err?.message || err || "");
    if (msg.includes("404") || msg.toLowerCase().includes("not found") || err?.name === "BlobNotFoundError") {
      return { version: 1, codes: {} };
    }
    throw err;
  }
}

export async function saveCodes(db) {
  const pathname = getBlobPath();
  const payload = JSON.stringify({ version: 1, updatedAt: new Date().toISOString(), codes: db.codes || {} }, null, 2);
  await put(pathname, payload, {
    access: "public",
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: "application/json",
    cacheControlMaxAge: 60
  });
}

export async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string" && req.body.trim()) {
    try { return JSON.parse(req.body); } catch (_) { return {}; }
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  try { return JSON.parse(raw); } catch (_) { return {}; }
}

export function setNoCacheHeaders(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
}

export function computeStatus(entry) {
  if (entry.revoked) return "revoked";
  if (entry.expiresAt && Date.now() > Date.parse(entry.expiresAt)) return "expired";
  if (entry.maxUses != null && (entry.uses || 0) >= entry.maxUses) return "exhausted";
  return "active";
}

export function formatAdminEntry(entry) {
  return {
    code: entry.code,
    tier: entry.tier,
    label: entry.label || "",
    maxUses: entry.maxUses ?? null,
    uses: entry.uses || 0,
    expiresAt: entry.expiresAt || null,
    revoked: !!entry.revoked,
    createdAt: entry.createdAt,
    lastUsedAt: entry.lastUsedAt || null,
    status: computeStatus(entry),
    shareUrl: `https://frumhost.com/?code=${encodeURIComponent(entry.code)}`
  };
}
