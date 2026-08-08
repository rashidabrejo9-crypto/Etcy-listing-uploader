
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3003;
const PUBLIC_DIR = process.cwd();
const upload = multer({ dest: path.join(process.cwd(), "tmp") });

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

const sessions = new Map();

function requireEnv(name) {
  if (!process.env[name]) throw new Error(`Missing ${name} in .env`);
  return process.env[name];
}

function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function newPkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function getSession(req) {
  const sid = req.headers["x-session-id"];
  return sid ? sessions.get(sid) : null;
}

function apiHeaders(session) {
  return {
    "x-api-key": `${requireEnv("ETSY_KEYSTRING")}:${requireEnv("ETSY_SHARED_SECRET")}`,
    "Authorization": `Bearer ${session.accessToken}`
  };
}

async function etsyFetch(url, options = {}, session) {
  const headers = { ...(options.headers || {}), ...apiHeaders(session) };
  return fetch(url, { ...options, headers });
}

app.get("/api/config", (req, res) => {
  res.json({
    configured: Boolean(process.env.ETSY_KEYSTRING && process.env.ETSY_SHARED_SECRET),
    redirectUri: process.env.ETSY_REDIRECT_URI || `http://localhost:${PORT}/oauth/callback`
  });
});

app.get("/api/auth/start", (req, res) => {
  try {
    const clientId = requireEnv("ETSY_KEYSTRING");
    const redirectUri = process.env.ETSY_REDIRECT_URI || `http://localhost:${PORT}/oauth/callback`;
    const sid = crypto.randomUUID();
    const state = base64url(crypto.randomBytes(24));
    const { verifier, challenge } = newPkce();

    sessions.set(sid, { state, verifier, redirectUri, createdAt: Date.now() });

    const scopes = [
      "shops_r",
      "listings_r",
      "listings_w"
    ].join(" ");

    const params = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    res.json({
      sessionId: sid,
      authorizeUrl: `https://www.etsy.com/oauth/connect?${params.toString()}`
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;
  const sid = [...sessions.entries()].find(([, s]) => s.state === state)?.[0];

  if (!sid) return res.status(400).send("Invalid or expired OAuth state.");
  const session = sessions.get(sid);

  if (error) return res.status(400).send(`Etsy authorization failed: ${error_description || error}`);

  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: requireEnv("ETSY_KEYSTRING"),
      redirect_uri: session.redirectUri,
      code,
      code_verifier: session.verifier
    });

    const tokenResp = await fetch("https://api.etsy.com/v3/public/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    const token = await tokenResp.json();
    if (!tokenResp.ok) throw new Error(token.error_description || token.error || "Token exchange failed");

    session.accessToken = token.access_token;
    session.refreshToken = token.refresh_token;
    session.expiresAt = Date.now() + (token.expires_in * 1000);
    session.userId = token.access_token.split(".")[0];

    res.redirect(`/?connected=1&session=${encodeURIComponent(sid)}`);
  } catch (e) {
    res.status(500).send(`OAuth callback error: ${e.message}`);
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ connected: false });

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/users/${session.userId}`,
      {},
      session
    );
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json({ connected: true, user: data, expiresAt: session.expiresAt });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/shops", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/users/${session.userId}/shops`,
      {},
      session
    );
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/listings", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });
    const shopId = req.query.shop_id;
    if (!shopId) return res.status(400).json({ error: "shop_id is required" });

    const state = req.query.state || "active";
    const limit = Math.min(Number(req.query.limit || 100), 100);
    const offset = Number(req.query.offset || 0);

    const url = new URL(`https://api.etsy.com/v3/application/shops/${shopId}/listings`);
    url.searchParams.set("state", state);
    url.searchParams.set("limit", String(limit));
    url.searchParams.set("offset", String(offset));

    const r = await etsyFetch(url, {}, session);
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function cleanTags(tags) {
  return (tags || [])
    .map(t => String(t).trim())
    .filter(Boolean)
    .slice(0, 13);
}

app.post("/api/listings/draft", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });

    const {
      shop_id, title, description, price, quantity, taxonomy_id,
      who_made = "i_did", when_made = "made_to_order",
      tags = [], type = "download", is_supply = false,
      is_taxable = false, should_auto_renew = false
    } = req.body;

    if (!shop_id || !title || !description || !price || !quantity || !taxonomy_id) {
      return res.status(400).json({
        error: "shop_id, title, description, price, quantity and taxonomy_id are required."
      });
    }

    const form = new URLSearchParams();
    form.set("quantity", String(quantity));
    form.set("title", String(title));
    form.set("description", String(description));
    form.set("price", String(price));
    form.set("who_made", who_made);
    form.set("when_made", when_made);
    form.set("taxonomy_id", String(taxonomy_id));
    form.set("tags", cleanTags(tags).join(","));
    form.set("type", type);
    form.set("is_supply", String(Boolean(is_supply)));
    form.set("is_taxable", String(Boolean(is_taxable)));
    form.set("should_auto_renew", String(Boolean(should_auto_renew)));

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${shop_id}/listings`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
        body: form
      },
      session
    );
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);

    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/listings/:listingId/image", upload.single("image"), async (req, res) => {
  const session = getSession(req);
  if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });
  if (!req.file) return res.status(400).json({ error: "Image file required" });

  try {
    const form = new FormData();
    form.append("image", new Blob([fs.readFileSync(req.file.path)], { type: req.file.mimetype }), req.file.originalname);
    form.append("rank", String(req.body.rank || 1));
    if (req.body.alt_text) form.append("alt_text", req.body.alt_text);

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${req.body.shop_id}/listings/${req.params.listingId}/images`,
      { method: "POST", body: form },
      session
    );
    const data = await r.json();
    fs.unlink(req.file.path, () => {});
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/listings/:listingId/file", upload.single("file"), async (req, res) => {
  const session = getSession(req);
  if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });
  if (!req.file) return res.status(400).json({ error: "Digital file required" });

  try {
    const form = new FormData();
    form.append("file", new Blob([fs.readFileSync(req.file.path)], { type: req.file.mimetype }), req.file.originalname);
    form.append("name", req.file.originalname);
    form.append("rank", "1");

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${req.body.shop_id}/listings/${req.params.listingId}/files`,
      { method: "POST", body: form },
      session
    );
    const data = await r.json();
    fs.unlink(req.file.path, () => {});
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/listings/:listingId/video", upload.single("video"), async (req, res) => {
  const session = getSession(req);
  if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });
  if (!req.file) return res.status(400).json({ error: "Video file required" });

  try {
    const form = new FormData();
    form.append("video", new Blob([fs.readFileSync(req.file.path)], { type: req.file.mimetype }), req.file.originalname);
    form.append("name", req.file.originalname);

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${req.body.shop_id}/listings/${req.params.listingId}/videos`,
      { method: "POST", body: form },
      session
    );
    const data = await r.json();
    fs.unlink(req.file.path, () => {});
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/listings/:listingId", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });
    const { shop_id, ...updates } = req.body;
    const form = new URLSearchParams();

    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) form.set(key, value.join(","));
      else form.set(key, String(value));
    }

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${shop_id}/listings/${req.params.listingId}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
        body: form
      },
      session
    );
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

    if (process.env.VERCEL !== "1") {
  app.listen(PORT, () => {
    console.log(`Etsy Listing Uploader running at http://localhost:${PORT}`);
  });
}

export default app;
