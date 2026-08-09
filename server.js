import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";

dotenv.config();

const app = express();
const upload = multer({ dest: "/tmp/etsy-listing-uploader" });

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(process.cwd()));

const SESSION_COOKIE = "etsy_session";
const OAUTH_COOKIE = "etsy_oauth";
const CALLBACK_DEFAULT = "https://etsy-listing-uploader.vercel.app/oauth/callback";
const SESSION_TTL = 60 * 60 * 1000;
const OAUTH_TTL = 10 * 60 * 1000;

function env(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name} environment variable`);
  return value;
}

function redirectUri() {
  return process.env.ETSY_REDIRECT_URI || CALLBACK_DEFAULT;
}

function b64(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function unb64(value) {
  const s = String(value);
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

function cryptoKey() {
  return crypto.createHash("sha256").update(env("SESSION_SECRET")).digest();
}

function seal(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", cryptoKey(), iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(payload), "utf8"),
    cipher.final()
  ]);
  return `${b64(iv)}.${b64(cipher.getAuthTag())}.${b64(encrypted)}`;
}

function unseal(value) {
  try {
    if (!value) return null;
    const [ivText, tagText, dataText] = String(value).split(".");
    if (!ivText || !tagText || !dataText) return null;

    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      cryptoKey(),
      unb64(ivText)
    );
    decipher.setAuthTag(unb64(tagText));

    const plain = Buffer.concat([
      decipher.update(unb64(dataText)),
      decipher.final()
    ]).toString("utf8");

    return JSON.parse(plain);
  } catch {
    return null;
  }
}

function cookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function setCookie(res, name, value, maxAge) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    `Max-Age=${Math.floor(maxAge / 1000)}`,
    "HttpOnly",
    "SameSite=Lax"
  ];
  if (process.env.NODE_ENV === "production" || process.env.VERCEL === "1") {
    parts.push("Secure");
  }
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  const parts = [
    `${name}=`,
    "Path=/",
    "Max-Age=0",
    "HttpOnly",
    "SameSite=Lax"
  ];
  if (process.env.NODE_ENV === "production" || process.env.VERCEL === "1") {
    parts.push("Secure");
  }
  res.setHeader("Set-Cookie", parts.join("; "));
}

function getSession(req) {
  const session = unseal(cookies(req)[SESSION_COOKIE]);
  if (!session?.accessToken || !session?.userId) return null;
  if (session.expiresAt && Date.now() >= session.expiresAt) return null;
  return session;
}

function apiHeaders(session) {
  return {
    "x-api-key": `${env("ETSY_KEYSTRING")}:${env("ETSY_SHARED_SECRET")}`,
    Authorization: `Bearer ${session.accessToken}`
  };
}

async function etsyFetch(url, options = {}, session) {
  return fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...apiHeaders(session)
    }
  });
}

async function refreshAccessToken(session) {
  if (!session.refreshToken) return null;

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: env("ETSY_KEYSTRING"),
    refresh_token: session.refreshToken
  });

  const response = await fetch(
    "https://api.etsy.com/v3/public/oauth/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    }
  );

  const token = await response.json();
  if (!response.ok) return null;

  const accessToken = String(token.access_token || "");
  if (!accessToken) return null;

  const userId = accessToken.includes(".")
    ? accessToken.split(".")[0]
    : String(session.userId || "");

  return {
    accessToken,
    refreshToken: token.refresh_token || session.refreshToken,
    userId,
    expiresAt: Date.now() + Number(token.expires_in || 3600) * 1000
  };
}

async function getUsableSession(req, res) {
  let session = getSession(req);
  if (!session) return null;

  if (session.expiresAt && Date.now() >= session.expiresAt - 30_000) {
    const refreshed = await refreshAccessToken(session);
    if (!refreshed) {
      clearCookie(res, SESSION_COOKIE);
      return null;
    }
    session = refreshed;
    setCookie(res, SESSION_COOKIE, seal(session), SESSION_TTL);
  }

  return session;
}

function userIdFromAccessToken(accessToken) {
  const token = String(accessToken || "");
  return token.includes(".") ? token.split(".")[0] : "";
}

app.get("/api/config", (req, res) => {
  res.json({
    configured: Boolean(
      process.env.ETSY_KEYSTRING &&
      process.env.ETSY_SHARED_SECRET &&
      process.env.SESSION_SECRET &&
      redirectUri()
    ),
    redirectUri: redirectUri()
  });
});

app.get("/api/auth/start", (req, res) => {
  try {
    const verifier = b64(crypto.randomBytes(32));
    const challenge = b64(
      crypto.createHash("sha256").update(verifier).digest()
    );
    const state = b64(crypto.randomBytes(32));
    const callback = redirectUri();

    setCookie(
      res,
      OAUTH_COOKIE,
      seal({
        state,
        verifier,
        redirectUri: callback,
        createdAt: Date.now()
      }),
      OAUTH_TTL
    );

    const params = new URLSearchParams({
      response_type: "code",
      client_id: env("ETSY_KEYSTRING"),
      redirect_uri: callback,
      scope: "shops_r listings_r listings_w",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    res.json({
      authorizeUrl: `https://www.etsy.com/oauth/connect?${params.toString()}`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/oauth/callback", async (req, res) => {
  const stored = unseal(cookies(req)[OAUTH_COOKIE]);
  const { code, state, error, error_description } = req.query;

  clearCookie(res, OAUTH_COOKIE);

  if (
    !stored ||
    !state ||
    stored.state !== String(state) ||
    Date.now() - Number(stored.createdAt || 0) > OAUTH_TTL
  ) {
    return res.status(400).send(
      "Invalid or expired OAuth state. Start a new Etsy connection from the app."
    );
  }

  if (error) {
    return res.status(400).send(
      `Etsy authorization failed: ${error_description || error}`
    );
  }

  if (!code) {
    return res.status(400).send("Missing Etsy authorization code.");
  }

  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: env("ETSY_KEYSTRING"),
      redirect_uri: stored.redirectUri,
      code: String(code),
      code_verifier: stored.verifier
    });

    const response = await fetch(
      "https://api.etsy.com/v3/public/oauth/token",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      }
    );

    const token = await response.json();

    if (!response.ok) {
      throw new Error(
        token.error_description ||
        token.error ||
        "Etsy token exchange failed"
      );
    }

    const accessToken = String(token.access_token || "");
    const userId = userIdFromAccessToken(accessToken);

    if (!accessToken || !userId) {
      throw new Error("Etsy returned an invalid access token.");
    }

    const session = {
      accessToken,
      refreshToken: String(token.refresh_token || ""),
      userId,
      expiresAt: Date.now() + Number(token.expires_in || 3600) * 1000
    };

    setCookie(res, SESSION_COOKIE, seal(session), SESSION_TTL);
    return res.redirect("/?connected=1");
  } catch (error) {
    return res.status(500).send(`OAuth callback error: ${error.message}`);
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const session = await getUsableSession(req, res);
    if (!session) return res.status(401).json({ connected: false });

    res.json({
      connected: true,
      userId: session.userId,
      expiresAt: session.expiresAt
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/logout", (req, res) => {
  clearCookie(res, SESSION_COOKIE);
  res.json({ ok: true });
});

app.get("/api/shops", async (req, res) => {
  try {
    const session = await getUsableSession(req, res);
    if (!session) return res.status(401).json({ error: "Not connected" });

    const response = await etsyFetch(
      `https://api.etsy.com/v3/application/users/${session.userId}/shops`,
      {},
      session
    );
    const data = await response.json();

    if (!response.ok) {
      if (response.status === 401) clearCookie(res, SESSION_COOKIE);
      return res.status(response.status).json(data);
    }

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/listings", async (req, res) => {
  try {
    const session = await getUsableSession(req, res);
    if (!session) return res.status(401).json({ error: "Not connected" });

    const shopId = String(req.query.shop_id || "");
    if (!shopId) return res.status(400).json({ error: "shop_id is required" });

    const url = new URL(
      `https://api.etsy.com/v3/application/shops/${shopId}/listings`
    );
    url.searchParams.set("state", String(req.query.state || "active"));
    url.searchParams.set(
      "limit",
      String(Math.min(Math.max(Number(req.query.limit || 100), 1), 100))
    );
    url.searchParams.set(
      "offset",
      String(Math.max(Number(req.query.offset || 0), 0))
    );

    const response = await etsyFetch(url, {}, session);
    const data = await response.json();

    if (!response.ok) return res.status(response.status).json(data);
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function cleanTags(tags) {
  return (Array.isArray(tags) ? tags : [])
    .map(tag => String(tag).trim())
    .filter(Boolean)
    .slice(0, 13);
}

app.post("/api/listings/draft", async (req, res) => {
  try {
    const session = await getUsableSession(req, res);
    if (!session) return res.status(401).json({ error: "Not connected" });

    const {
      shop_id,
      title,
      description,
      price,
      quantity,
      taxonomy_id,
      who_made = "i_did",
      when_made = "made_to_order",
      tags = [],
      type = "download",
      is_supply = false,
      is_taxable = false,
      should_auto_renew = false
    } = req.body;

    if (!shop_id || !title || !description || price === undefined ||
        quantity === undefined || !taxonomy_id) {
      return res.status(400).json({
        error: "shop_id, title, description, price, quantity and taxonomy_id are required."
      });
    }

    const form = new URLSearchParams();
    form.set("quantity", String(quantity));
    form.set("title", String(title));
    form.set("description", String(description));
    form.set("price", String(price));
    form.set("who_made", String(who_made));
    form.set("when_made", String(when_made));
    form.set("taxonomy_id", String(taxonomy_id));
    form.set("tags", cleanTags(tags).join(","));
    form.set("type", String(type));
    form.set("is_supply", String(Boolean(is_supply)));
    form.set("is_taxable", String(Boolean(is_taxable)));
    form.set("should_auto_renew", String(Boolean(should_auto_renew)));

    const response = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${shop_id}/listings`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
        },
        body: form
      },
      session
    );

    const data = await response.json();
    if (!response.ok) return res.status(response.status).json(data);

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

async function uploadToEtsy(req, res, kind) {
  const session = await getUsableSession(req, res);
  if (!session) return res.status(401).json({ error: "Not connected" });
  if (!req.file) return res.status(400).json({ error: `${kind} file required` });

  try {
    const form = new FormData();
    const bytes = fs.readFileSync(req.file.path);

    form.append(
      kind,
      new Blob([bytes], { type: req.file.mimetype }),
      req.file.originalname
    );

    if (kind === "image") {
      form.append("rank", String(req.body.rank || 1));
    }

    if (kind === "file") {
      form.append("name", req.file.originalname);
      form.append("rank", "1");
    }

    const endpoint = kind === "image" ? "images" :
      kind === "file" ? "files" : "videos";

    const response = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${req.body.shop_id}/listings/${req.params.listingId}/${endpoint}`,
      { method: "POST", body: form },
      session
    );

    const data = await response.json();
    fs.unlink(req.file.path, () => {});

    if (!response.ok) return res.status(response.status).json(data);
    res.json(data);
  } catch (error) {
    fs.unlink(req.file.path, () => {});
    res.status(500).json({ error: error.message });
  }
}

app.post(
  "/api/listings/:listingId/image",
  upload.single("image"),
  (req, res) => uploadToEtsy(req, res, "image")
);

app.post(
  "/api/listings/:listingId/file",
  upload.single("file"),
  (req, res) => uploadToEtsy(req, res, "file")
);

app.post(
  "/api/listings/:listingId/video",
  upload.single("video"),
  (req, res) => uploadToEtsy(req, res, "video")
);

app.patch("/api/listings/:listingId", async (req, res) => {
  try {
    const session = await getUsableSession(req, res);
    if (!session) return res.status(401).json({ error: "Not connected" });

    const { shop_id, ...updates } = req.body;
    if (!shop_id) return res.status(400).json({ error: "shop_id is required" });

    const form = new URLSearchParams();

    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined || value === null || value === "") continue;
      form.set(key, Array.isArray(value) ? value.join(",") : String(value));
    }

    const response = await etsyFetch(
      `https://api.etsy.com/v3/application/shops/${shop_id}/listings/${req.params.listingId}`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
        },
        body: form
      },
      session
    );

    const data = await response.json();
    if (!response.ok) return res.status(response.status).json(data);

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

if (process.env.VERCEL !== "1") {
  const port = process.env.PORT || 3003;
  app.listen(port, () => {
    console.log(`Etsy Listing Uploader running on port ${port}`);
  });
}

export default app;
