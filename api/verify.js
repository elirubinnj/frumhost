import {
  loadCodes,
  saveCodes,
  normalizeCode,
  verifyAdminToken,
  readBody,
  setNoCacheHeaders
} from "./_lib/store.js";

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
    const q = req.query || {};

    // Check ownerToken first (Bearer header, body.ownerToken, or query.ownerToken)
    const authHeader = String(req.headers.authorization || "");
    const bearer = authHeader.toLowerCase().startsWith("bearer ") ? authHeader.slice(7).trim() : "";
    const ownerToken = body.ownerToken || q.ownerToken || bearer || "";
    if (ownerToken && !body.code && !q.code) {
      const verified = verifyAdminToken(ownerToken);
      if (!verified) {
        res.status(200).json({ ok: false, reason: "invalid_owner_token", error: "Owner session expired." });
        return;
      }
      res.status(200).json({
        ok: true,
        owner: true,
        tier: "pro",
        label: "Owner Mode",
        expiresAt: new Date(verified.exp).toISOString(),
        remainingUses: null
      });
      return;
    }

    const rawCode = body.code ?? q.code ?? "";
    const code = normalizeCode(rawCode);
    if (!code) {
      res.status(400).json({ ok: false, reason: "missing_code", error: "Please enter an access code." });
      return;
    }

    const checkOnlyParam = body.checkOnly === true || q.checkOnly === "1" || q.checkOnly === "true";
    const redeem = body.redeem === false || checkOnlyParam ? false : (req.method === "POST" || q.redeem === "1" || q.redeem === "true");
    const deviceId = String(body.deviceId || q.deviceId || "").trim().slice(0, 80);

    const db = await loadCodes();
    const entry = db.codes[code];
    if (!entry) {
      res.status(200).json({ ok: false, reason: "not_found", error: "Access code not found. Double-check the spelling and try again." });
      return;
    }

    if (entry.revoked) {
      res.status(200).json({ ok: false, reason: "revoked", error: "This access code has been revoked." });
      return;
    }

    if (entry.expiresAt && Date.now() > Date.parse(entry.expiresAt)) {
      res.status(200).json({ ok: false, reason: "expired", error: "This access code has expired." });
      return;
    }

    const devices = Array.isArray(entry.devices) ? entry.devices : [];
    const alreadyRedeemedByDevice = Boolean(deviceId && devices.includes(deviceId));
    const currentUses = entry.uses || 0;

    if (redeem) {
      if (!alreadyRedeemedByDevice) {
        if (entry.maxUses != null && currentUses >= entry.maxUses) {
          res.status(200).json({
            ok: false,
            reason: "max_uses_reached",
            error: "This access code has reached its maximum number of uses."
          });
          return;
        }
        entry.uses = currentUses + 1;
        entry.lastUsedAt = new Date().toISOString();
        if (deviceId) {
          if (!Array.isArray(entry.devices)) entry.devices = [];
          entry.devices.push(deviceId);
          if (entry.devices.length > 500) entry.devices = entry.devices.slice(-500);
        }
        db.codes[code] = entry;
        await saveCodes(db);
      }
    } else {
      // checkOnly mode: allow if device already redeemed, or if uses remain, or if no deviceId supplied
      if (deviceId && !alreadyRedeemedByDevice && entry.maxUses != null && currentUses >= entry.maxUses) {
        res.status(200).json({
          ok: false,
          reason: "max_uses_reached",
          error: "This access code has reached its maximum number of uses."
        });
        return;
      }
    }

    const finalUses = entry.uses || 0;
    const remainingUses = entry.maxUses == null ? null : Math.max(0, entry.maxUses - finalUses);

    res.status(200).json({
      ok: true,
      code: entry.code,
      tier: entry.tier === "family" ? "family" : "pro",
      label: entry.label || "",
      expiresAt: entry.expiresAt || null,
      maxUses: entry.maxUses ?? null,
      uses: finalUses,
      remainingUses
    });
  } catch (err) {
    console.error("verify error:", err);
    res.status(500).json({ ok: false, reason: "server_error", error: "Could not verify access code right now." });
  }
}
