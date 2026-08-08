import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();
const PUBLIC_DIR = process.cwd();
const upload = multer({ dest: "/tmp" });

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

const COOKIE = "etsy_session";

function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s) throw new Error("Missing SESSION_SECRET");
  return s;
}

function b64(buf) {
  return Buffer.from(buf).toString("base64url");
}

function sign(payload) {
  const data = b64(Buffer.from(JSON.stringify(payload)));
  const sig = crypto.createHmac("sha256", secret()).update(data).digest("base64url");
  return `${data}.${sig}`;
}

function verify(value) {
  try {
    const [data, sig] = String(value || "").split(".");
    if (!data || !sig) return null;
    const expected = crypto.createHmac("sha256", secret()).update(data).digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(data, "base64url").toString());
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function setSession(res, payload) {
  const value = sign({ ...payload, exp: Date.now() + 60 * 60 * 1000 });
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`
  );
}

function getSession(req) {
  const raw = req.headers.cookie || "";
  const item = raw.split(";").map(x => x.trim()).find(x => x.startsWith(`${COOKIE}=`));
  return item ? verify(item.slice(COOKIE.length + 1)) : null;
}

function requireEnv(name) {
  if (!process.env[name]) throw new Error(`Missing ${name}`);
  return process.env[name];
}

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function pkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function apiHeaders(session) {
  return {
    "x-api-key": `${requireEnv("ETSY_KEYSTRING")}:${requireEnv("ETSY_SHARED_SECRET")}`,
    Authorization: `Bearer ${session.accessToken}`
  };
}

async function etsyFetch(url, options = {}, session) {
  return fetch(url, {
    ...options,
    headers: { ...(options.headers || {}), ...apiHeaders(session) }
  });
}

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/api/config", (req, res) => {
  res.json({
    configured: Boolean(process.env.ETSY_KEYSTRING && process.env.ETSY_SHARED_SECRET),
    redirectUri: process.env.ETSY_REDIRECT_URI || ""
  });
});

app.get("/api/auth/start", (req, res) => {
  try {
    const redirectUri = requireEnv("ETSY_REDIRECT_URI");
    const { verifier, challenge } = pkce();
    const state = crypto.randomBytes(24).toString("hex");

    setSession(res, { state, verifier, redirectUri });

    const params = new URLSearchParams({
      response_type: "code",
      client_id: requireEnv("ETSY_KEYSTRING"),
      redirect_uri: redirectUri,
      scope: "shops_r listings_r listings_w",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    res.json({
      authorizeUrl: `https://www.etsy.com/oauth/connect?${params.toString()}`
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/oauth/callback", async (req, res) => {
  const session = getSession(req);
  const { code, state, error, error_description } = req.query;

  if (error) return res.status(400).send(`Etsy authorization failed: ${error_description || error}`);
  if (!session || session.state !== state) return res.status(400).send("Invalid or expired OAuth state.");
  if (!code) return res.status(400).send("Missing authorization code.");

  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: requireEnv("ETSY_KEYSTRING"),
      redirect_uri: session.redirectUri,
      code: String(code),
      code_verifier: session.verifier
    });

    const tokenResp = await fetch("https://api.etsy.com/v3/public/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    const token = await tokenResp.json();
    if (!tokenResp.ok) throw new Error(token.error_description || token.error || "Token exchange failed");

    const userId = String(token.user_id || "").trim();
    const newSession = {
      accessToken: token.access_token,
      refreshToken: token.refresh_token,
      userId,
      redirectUri: session.redirectUri
    };

    setSession(res, newSession);
    res.redirect("/?connected=1");
  } catch (e) {
    res.status(500).send(`OAuth callback error: ${e.message}`);
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken || !session?.userId) return res.status(401).json({ connected: false });
    res.json({ connected: true, userId: session.userId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/shops", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken || !session?.userId) return res.status(401).json({ error: "Not connected" });

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

    const url = new URL(`https://api.etsy.com/v3/application/shops/${shopId}/listings`);
    url.searchParams.set("state", req.query.state || "active");
    url.searchParams.set("limit", String(Math.min(Number(req.query.limit || 100), 100)));
    url.searchParams.set("offset", String(Number(req.query.offset || 0)));

    const r = await etsyFetch(url, {}, session);
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function cleanTags(tags) {
  return (tags || []).map(x => String(x).trim()).filter(Boolean).slice(0, 13);
}

app.post("/api/listings/draft", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });

    const { shop_id, title, description, price, quantity, taxonomy_id,
      who_made = "i_did", when_made = "made_to_order", tags = [],
      type = "download", is_supply = false, is_taxable = false,
      should_auto_renew = false } = req.body;

    if (!shop_id || !title || !description || !price || !quantity || !taxonomy_id)
      return res.status(400).json({ error: "shop_id, title, description, price, quantity and taxonomy_id are required." });

    const form = new URLSearchParams();
    for (const [k, v] of Object.entries({
      quantity, title, description, price, who_made, when_made, taxonomy_id,
      type, is_supply: Boolean(is_supply), is_taxable: Boolean(is_taxable),
      should_auto_renew: Boolean(should_auto_renew)
    })) form.set(k, String(v));
    form.set("tags", cleanTags(tags).join(","));

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${shop_id}/listings`,
      { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" }, body: form },
      session
    );
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function uploadToEtsy(req, res, kind) {
  const session = getSession(req);
  if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });
  if (!req.file) return res.status(400).json({ error: `${kind} file required` });

  try {
    const form = new FormData();
    form.append(kind, new Blob([fs.readFileSync(req.file.path)], { type: req.file.mimetype }), req.file.originalname);
    if (kind === "image") form.append("rank", String(req.body.rank || 1));
    if (kind === "file") { form.append("name", req.file.originalname); form.append("rank", "1"); }

    const endpoint = kind === "image" ? "images" : kind === "file" ? "files" : "videos";
    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${req.body.shop_id}/listings/${req.params.listingId}/${endpoint}`,
      { method: "POST", body: form },
      session
    );
    const data = await r.json();
    fs.unlink(req.file.path, () => {});
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    fs.unlink(req.file.path, () => {});
    res.status(500).json({ error: e.message });
  }
}

app.post("/api/listings/:listingId/image", upload.single("image"), (req, res) => uploadToEtsy(req, res, "image"));
app.post("/api/listings/:listingId/file", upload.single("file"), (req, res) => uploadToEtsy(req, res, "file"));
app.post("/api/listings/:listingId/video", upload.single("video"), (req, res) => uploadToEtsy(req, res, "video"));

app.patch("/api/listings/:listingId", async (req, res) => {
  try {
    const session = getSession(req);
    if (!session?.accessToken) return res.status(401).json({ error: "Not connected" });
    const { shop_id, ...updates } = req.body;
    if (!shop_id) return res.status(400).json({ error: "shop_id is required" });

    const form = new URLSearchParams();
    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined || value === null || value === "") continue;
      form.set(key, Array.isArray(value) ? value.join(",") : String(value));
    }

    const r = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${shop_id}/listings/${req.params.listingId}`,
      { method: "PATCH", headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" }, body: form },
      session
    );
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default app;
