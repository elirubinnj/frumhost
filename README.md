# FrumHost.com

Luxury Jewish Hospitality & Shabbos Guest Sign Studio with live Zmanim, tier-gated features, and a mobile-friendly `/admin` Access Code Manager.

## Stack
- **Hosting & Serverless API:** Vercel (`public/` static assets + `api/verify.js` + `api/admin.js`)
- **Storage:** Vercel Blob (`@vercel/blob`)
- **Custom Domain:** `https://frumhost.com` (`www.frumhost.com` → 308 redirect)
- **Zmanim:** Live Hebcal API (by ZIP & date)

## Structure
- `public/index.html` — FrumHost Sign Studio (Free, Family, Pro Host & Owner Mode)
- `public/admin.html` — Mobile-first `/admin` Access Code Manager
- `public/*.jpg` — Watercolor hospitality artwork (`candles.jpg`, `kiddush.jpg`, `welcome_key.jpg`, `jerusalem.jpg`)
- `api/verify.js` — Access code redemption, `checkOnly` live revocation check & Owner Mode token verification
- `api/admin.js` — PIN login (`ADMIN_PIN`), list/create/revoke/delete access codes
- `api/_lib/store.js` — Vercel Blob persistence (`useCache: false`) & HMAC token helpers
- `vercel.json` — Clean URLs, `/admin` rewrite & `no-store` API headers
