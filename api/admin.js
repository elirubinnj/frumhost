import {
  loadCodes,
  saveCodes,
  normalizeCode,
  generateRandomCode,
  verifyPin,
  signAdminToken,
  verifyAdminToken,
  readBody,
  setNoCacheHeaders,
  formatAdminEntry
} from "./_lib/store.js";

function requireAdmin(req, res) {
  const authHeader = String(req.headers.authorization || "");
  const token = authHeader.toLowerCase().startsWith("bearer ") ? authHeader.slice(7).trim() : "";
  const verified = verifyAdminToken(token);
  if (!verified) {
    res.status(401).json({ ok: false, error: "Unauthorized — please sign in with your Admin PIN." });
    return null;
  }
  return verified;
}

export default async function handler(req, res) {
  setNoCacheHeaders(res);
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "GET" && req.method !== "POST") {
    res.status(405).json({ ok: false, error: "Method not allowed" });
    return;
  }

  try {
    const body = req.method === "POST" ? await readBody(req) : {};
    const action = req.method === "GET" ? (req.query?.action || "list") : (body.action || "");

    if (action === "login") {
      if (!verifyPin(body.pin)) {
        res.status(401).json({ ok: false, error: "Incorrect Admin PIN." });
        return;
      }
      const { token, expiresAt } = signAdminToken();
      res.status(200).json({ ok: true, adminToken: token, expiresAt });
      return;
    }

    if (!requireAdmin(req, res)) return;

    if (action === "list") {
      const db = await loadCodes();
      const list = Object.values(db.codes || {})
        .map(formatAdminEntry)
        .sort((a, b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0));
      res.status(200).json({ ok: true, codes: list });
      return;
    }

    if (action === "create") {
      const tier = body.tier === "family" ? "family" : "pro";
      const label = String(body.label || "").trim().slice(0, 120);

      let maxUses = null;
      if (body.maxUses !== null && body.maxUses !== undefined && body.maxUses !== "") {
        const parsed = parseInt(String(body.maxUses), 10);
        if (!Number.isFinite(parsed) || parsed < 1) {
          res.status(400).json({ ok: false, error: "Max uses must be a positive whole number or blank for unlimited." });
          return;
        }
        maxUses = parsed;
      }

      let expiresAt = null;
      if (body.expiresAt) {
        const ts = Date.parse(String(body.expiresAt));
        if (!Number.isFinite(ts)) {
          res.status(400).json({ ok: false, error: "Invalid expiration date." });
          return;
        }
        expiresAt = new Date(ts).toISOString();
      } else if (body.expiresInHours !== null && body.expiresInHours !== undefined && body.expiresInHours !== "") {
        const hrs = Number(body.expiresInHours);
        if (!Number.isFinite(hrs) || hrs <= 0) {
          res.status(400).json({ ok: false, error: "Expiration hours must be positive." });
          return;
        }
        expiresAt = new Date(Date.now() + hrs * 3600 * 1000).toISOString();
      }

      const db = await loadCodes();
      let code = normalizeCode(body.code || "");
      if (code) {
        if (!/^[A-Z0-9_-]{3,32}$/.test(code)) {
          res.status(400).json({ ok: false, error: "Code must be 3–32 characters using letters, numbers, hyphens, or underscores." });
          return;
        }
        if (db.codes[code]) {
          res.status(409).json({ ok: false, error: `Code "${code}" already exists.` });
          return;
        }
      } else {
        for (let i = 0; i < 10; i++) {
          const candidate = generateRandomCode();
          if (!db.codes[candidate]) { code = candidate; break; }
        }
      }

      const entry = {
        code,
        tier,
        label,
        maxUses,
        uses: 0,
        devices: [],
        expiresAt,
        revoked: false,
        createdAt: new Date().toISOString(),
        lastUsedAt: null
      };
      db.codes[code] = entry;
      await saveCodes(db);

      res.status(201).json({ ok: true, entry: formatAdminEntry(entry) });
      return;
    }

    if (action === "revoke") {
      const code = normalizeCode(body.code || "");
      if (!code) {
        res.status(400).json({ ok: false, error: "Code is required." });
        return;
      }
      const db = await loadCodes();
      const entry = db.codes[code];
      if (!entry) {
        res.status(404).json({ ok: false, error: `Code "${code}" not found.` });
        return;
      }
      entry.revoked = body.revoked !== undefined ? Boolean(body.revoked) : !entry.revoked;
      db.codes[code] = entry;
      await saveCodes(db);
      res.status(200).json({ ok: true, entry: formatAdminEntry(entry) });
      return;
    }

    if (action === "delete") {
      const code = normalizeCode(body.code || "");
      if (!code) {
        res.status(400).json({ ok: false, error: "Code is required." });
        return;
      }
      const db = await loadCodes();
      if (!db.codes[code]) {
        res.status(404).json({ ok: false, error: `Code "${code}" not found.` });
        return;
      }
      delete db.codes[code];
      await saveCodes(db);
      res.status(200).json({ ok: true, deleted: code });
      return;
    }

    res.status(400).json({ ok: false, error: `Unknown action: ${action}` });
  } catch (err) {
    console.error("admin error:", err);
    res.status(500).json({ ok: false, error: "Server error processing admin request." });
  }
}
