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

const upload = multer({
  dest: "/tmp"
});

const SESSION_COOKIE = "etsy_session";

/*
 * IMPORTANT:
 * Keep this exactly the same as your Vercel Production domain.
 */
const REDIRECT_URI =
  process.env.ETSY_REDIRECT_URI ||
  "https://etcy-listing-uploader.vercel.app/oauth/callback";

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

/* ---------------------------------------------------------
   BASIC HELPERS
--------------------------------------------------------- */

function requireEnv(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing ${name} in environment variables`);
  }

  return value;
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function randomString(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

/* ---------------------------------------------------------
   SIGNED STATE
--------------------------------------------------------- */

function getSessionSecret() {
  return requireEnv("SESSION_SECRET");
}

function signValue(payload) {
  const encoded = base64url(
    JSON.stringify(payload)
  );

  const signature = crypto
    .createHmac(
      "sha256",
      getSessionSecret()
    )
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifyValue(value) {
  try {
    const parts = String(value || "").split(".");

    if (parts.length !== 2) {
      return null;
    }

    const [encoded, signature] = parts;

    const expected = crypto
      .createHmac(
        "sha256",
        getSessionSecret()
      )
      .update(encoded)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(
        encoded,
        "base64url"
      ).toString("utf8")
    );

    if (
      payload.exp &&
      Number(payload.exp) < Date.now()
    ) {
      return null;
    }

    return payload;

  } catch {
    return null;
  }
}

/* ---------------------------------------------------------
   SESSION COOKIE
--------------------------------------------------------- */

function setSessionCookie(res, payload) {
  const value = signValue({
    ...payload,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  });

  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
  );
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";

  const cookies = cookieHeader
    .split(";")
    .map(x => x.trim());

  const item = cookies.find(
    x => x.startsWith(`${name}=`)
  );

  if (!item) {
    return null;
  }

  return item.slice(name.length + 1);
}

function getSession(req) {
  const raw = getCookie(
    req,
    SESSION_COOKIE
  );

  return raw ? verifyValue(raw) : null;
}

/* ---------------------------------------------------------
   PKCE
--------------------------------------------------------- */

function createPkce() {
  const verifier = randomString(32);

  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  return {
    verifier,
    challenge
  };
}

/* ---------------------------------------------------------
   ETSY API
--------------------------------------------------------- */

function etsyHeaders(session) {
  return {
    "x-api-key":
      `${requireEnv("ETSY_KEYSTRING")}:${requireEnv("ETSY_SHARED_SECRET")}`,

    Authorization:
      `Bearer ${session.accessToken}`
  };
}

async function etsyFetch(
  url,
  options = {},
  session
) {
  return fetch(url, {
    ...options,

    headers: {
      ...(options.headers || {}),
      ...etsyHeaders(session)
    }
  });
}

/* ---------------------------------------------------------
   HOME
--------------------------------------------------------- */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      PUBLIC_DIR,
      "index.html"
    )
  );
});

/* ---------------------------------------------------------
   CONFIG
--------------------------------------------------------- */

app.get("/api/config", (req, res) => {
  res.json({
    configured: Boolean(
      process.env.ETSY_KEYSTRING &&
      process.env.ETSY_SHARED_SECRET &&
      process.env.SESSION_SECRET
    ),

    redirectUri: REDIRECT_URI
  });
});

/* ---------------------------------------------------------
   START ETSY OAUTH
--------------------------------------------------------- */

app.get("/api/auth/start", (req, res) => {
  try {
    const clientId =
      requireEnv("ETSY_KEYSTRING");

    const {
      verifier,
      challenge
    } = createPkce();

    /*
     * IMPORTANT:
     * The verifier is stored INSIDE the signed state.
     *
     * This removes the old dependency on a cookie
     * existing before the Etsy callback.
     */
    const statePayload = {
      verifier,
      redirectUri: REDIRECT_URI,
      exp: Date.now() + 10 * 60 * 1000
    };

    const state =
      signValue(statePayload);

    const params =
      new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: REDIRECT_URI,

        scope:
          "shops_r listings_r listings_w",

        state,

        code_challenge: challenge,
        code_challenge_method: "S256"
      });

    res.json({
      authorizeUrl:
        `https://www.etsy.com/oauth/connect?${params.toString()}`
    });

  } catch (error) {
    console.error(
      "OAuth start error:",
      error
    );

    res.status(500).json({
      error: error.message
    });
  }
});

/* ---------------------------------------------------------
   ETSY OAUTH CALLBACK
--------------------------------------------------------- */

app.get(
  "/oauth/callback",
  async (req, res) => {

    const {
      code,
      state,
      error,
      error_description
    } = req.query;

    if (error) {
      return res.status(400).send(
        `Etsy authorization failed: ${
          error_description || error
        }`
      );
    }

    if (!state) {
      return res.status(400).send(
        "Missing OAuth state."
      );
    }

    if (!code) {
      return res.status(400).send(
        "Missing authorization code."
      );
    }

    /*
     * Verify signed state.
     * No pre-existing cookie is required anymore.
     */
    const stateData =
      verifyValue(state);

    if (!stateData) {
      return res.status(400).send(
        "Invalid or expired OAuth state. Please start Connect Etsy again."
      );
    }

    if (
      stateData.redirectUri !==
      REDIRECT_URI
    ) {
      return res.status(400).send(
        "OAuth redirect URI mismatch."
      );
    }

    try {
      const body =
        new URLSearchParams({
          grant_type:
            "authorization_code",

          client_id:
            requireEnv("ETSY_KEYSTRING"),

          redirect_uri:
            REDIRECT_URI,

          code:
            String(code),

          code_verifier:
            stateData.verifier
        });

      const tokenResponse =
        await fetch(
          "https://api.etsy.com/v3/public/oauth/token",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded"
            },

            body
          }
        );

      const token =
        await tokenResponse.json();

      if (!tokenResponse.ok) {
        console.error(
          "Etsy token error:",
          token
        );

        throw new Error(
          token.error_description ||
          token.error ||
          "Token exchange failed"
        );
      }

      const userId =
        token.user_id
          ? String(token.user_id)
          : "";

      /*
       * Save the Etsy login in a signed,
       * HttpOnly cookie.
       */
      setSessionCookie(
        res,
        {
          accessToken:
            token.access_token,

          refreshToken:
            token.refresh_token || "",

          userId,

          redirectUri:
            REDIRECT_URI
        }
      );

      res.redirect(
        "/?connected=1"
      );

    } catch (error) {

      console.error(
        "OAuth callback error:",
        error
      );

      res.status(500).send(
        `OAuth callback error: ${error.message}`
      );
    }
  }
);

/* ---------------------------------------------------------
   CURRENT USER
--------------------------------------------------------- */

app.get("/api/me", async (req, res) => {
  try {

    const session =
      getSession(req);

    if (
      !session?.accessToken
    ) {
      return res.status(401).json({
        connected: false
      });
    }

    res.json({
      connected: true,
      userId:
        session.userId || null
    });

  } catch (error) {

    res.status(500).json({
      error: error.message
    });
  }
});

/* ---------------------------------------------------------
   SHOPS
--------------------------------------------------------- */

app.get("/api/shops", async (req, res) => {
  try {

    const session =
      getSession(req);

    if (
      !session?.accessToken ||
      !session?.userId
    ) {
      return res.status(401).json({
        error: "Not connected"
      });
    }

    const response =
      await etsyFetch(
        `https://api.etsy.com/v3/application/users/${session.userId}/shops`,
        {},
        session
      );

    const data =
      await response.json();

    if (!response.ok) {
      return res
        .status(response.status)
        .json(data);
    }

    res.json(data);

  } catch (error) {

    res.status(500).json({
      error: error.message
    });
  }
});

/* ---------------------------------------------------------
   LISTINGS
--------------------------------------------------------- */

app.get(
  "/api/listings",
  async (req, res) => {

    try {

      const session =
        getSession(req);

      if (!session?.accessToken) {
        return res.status(401).json({
          error: "Not connected"
        });
      }

      const shopId =
        req.query.shop_id;

      if (!shopId) {
        return res.status(400).json({
          error:
            "shop_id is required"
        });
      }

      const state =
        req.query.state ||
        "active";

      const limit =
        Math.min(
          Number(
            req.query.limit || 100
          ),
          100
        );

      const offset =
        Number(
          req.query.offset || 0
        );

      const url =
        new URL(
          `https://api.etsy.com/v3/application/shops/${shopId}/listings`
        );

      url.searchParams.set(
        "state",
        state
      );

      url.searchParams.set(
        "limit",
        String(limit)
      );

      url.searchParams.set(
        "offset",
        String(offset)
      );

      const response =
        await etsyFetch(
          url,
          {},
          session
        );

      const data =
        await response.json();

      if (!response.ok) {
        return res
          .status(response.status)
          .json(data);
      }

      res.json(data);

    } catch (error) {

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ---------------------------------------------------------
   TAGS
--------------------------------------------------------- */

function cleanTags(tags) {
  return (tags || [])
    .map(tag =>
      String(tag).trim()
    )
    .filter(Boolean)
    .slice(0, 13);
}

/* ---------------------------------------------------------
   CREATE DRAFT LISTING
--------------------------------------------------------- */

app.post(
  "/api/listings/draft",
  async (req, res) => {

    try {

      const session =
        getSession(req);

      if (!session?.accessToken) {
        return res.status(401).json({
          error: "Not connected"
        });
      }

      const {
        shop_id,
        title,
        description,
        price,
        quantity,
        taxonomy_id,

        who_made =
          "i_did",

        when_made =
          "made_to_order",

        tags = [],

        type =
          "download",

        is_supply =
          false,

        is_taxable =
          false,

        should_auto_renew =
          false
      } = req.body;

      if (
        !shop_id ||
        !title ||
        !description ||
        !price ||
        !quantity ||
        !taxonomy_id
      ) {
        return res.status(400).json({
          error:
            "shop_id, title, description, price, quantity and taxonomy_id are required."
        });
      }

      const form =
        new URLSearchParams();

      form.set(
        "quantity",
        String(quantity)
      );

      form.set(
        "title",
        String(title)
      );

      form.set(
        "description",
        String(description)
      );

      form.set(
        "price",
        String(price)
      );

      form.set(
        "who_made",
        String(who_made)
      );

      form.set(
        "when_made",
        String(when_made)
      );

      form.set(
        "taxonomy_id",
        String(taxonomy_id)
      );

      form.set(
        "tags",
        cleanTags(tags).join(",")
      );

      form.set(
        "type",
        String(type)
      );

      form.set(
        "is_supply",
        String(Boolean(is_supply))
      );

      form.set(
        "is_taxable",
        String(Boolean(is_taxable))
      );

      form.set(
        "should_auto_renew",
        String(Boolean(should_auto_renew))
      );

      const response =
        await etsyFetch(
          `https://api.etsy.com/v3/application/shops/${shop_id}/listings`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded; charset=utf-8"
            },

            body: form
          },
          session
        );

      const data =
        await response.json();

      if (!response.ok) {
        return res
          .status(response.status)
          .json(data);
      }

      res.json(data);

    } catch (error) {

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ---------------------------------------------------------
   FILE UPLOAD HELPER
--------------------------------------------------------- */

async function uploadToEtsy(
  req,
  res,
  kind
) {

  const session =
    getSession(req);

  if (!session?.accessToken) {
    return res.status(401).json({
      error: "Not connected"
    });
  }

  if (!req.file) {
    return res.status(400).json({
      error:
        `${kind} file required`
    });
  }

  try {

    const form =
      new FormData();

    const buffer =
      fs.readFileSync(
        req.file.path
      );

    const blob =
      new Blob(
        [buffer],
        {
          type:
            req.file.mimetype
        }
      );

    form.append(
      kind,
      blob,
      req.file.originalname
    );

    if (kind === "image") {
      form.append(
        "rank",
        String(
          req.body.rank || 1
        )
      );

      if (req.body.alt_text) {
        form.append(
          "alt_text",
          String(
            req.body.alt_text
          )
        );
      }
    }

    if (kind === "file") {
      form.append(
        "name",
        req.file.originalname
      );

      form.append(
        "rank",
        "1"
      );
    }

    if (kind === "video") {
      form.append(
        "name",
        req.file.originalname
      );
    }

    const endpoint =
      kind === "image"
        ? "images"
        : kind === "file"
          ? "files"
          : "videos";

    const shopId =
      req.body.shop_id;

    if (!shopId) {
      fs.unlink(
        req.file.path,
        () => {}
      );

      return res.status(400).json({
        error:
          "shop_id is required"
      });
    }

    const response =
      await etsyFetch(
        `https://api.etsy.com/v3/application/shops/${shopId}/listings/${req.params.listingId}/${endpoint}`,
        {
          method: "POST",
          body: form
        },
        session
      );

    const data =
      await response.json();

    fs.unlink(
      req.file.path,
      () => {}
    );

    if (!response.ok) {
      return res
        .status(response.status)
        .json(data);
    }

    res.json(data);

  } catch (error) {

    fs.unlink(
      req.file.path,
      () => {}
    );

    res.status(500).json({
      error: error.message
    });
  }
}

/* ---------------------------------------------------------
   IMAGE
--------------------------------------------------------- */

app.post(
  "/api/listings/:listingId/image",
  upload.single("image"),
  (req, res) =>
    uploadToEtsy(
      req,
      res,
      "image"
    )
);

/* ---------------------------------------------------------
   DIGITAL FILE
--------------------------------------------------------- */

app.post(
  "/api/listings/:listingId/file",
  upload.single("file"),
  (req, res) =>
    uploadToEtsy(
      req,
      res,
      "file"
    )
);

/* ---------------------------------------------------------
   VIDEO
--------------------------------------------------------- */

app.post(
  "/api/listings/:listingId/video",
  upload.single("video"),
  (req, res) =>
    uploadToEtsy(
      req,
      res,
      "video"
    )
);

/* ---------------------------------------------------------
   UPDATE LISTING
--------------------------------------------------------- */

app.patch(
  "/api/listings/:listingId",
  async (req, res) => {

    try {

      const session =
        getSession(req);

      if (!session?.accessToken) {
        return res.status(401).json({
          error: "Not connected"
        });
      }

      const {
        shop_id,
        ...updates
      } = req.body;

      if (!shop_id) {
        return res.status(400).json({
          error:
            "shop_id is required"
        });
      }

      const form =
        new URLSearchParams();

      for (
        const [key, value]
        of Object.entries(updates)
      ) {

        if (
          value === undefined ||
          value === null ||
          value === ""
        ) {
          continue;
        }

        form.set(
          key,
          Array.isArray(value)
            ? value.join(",")
            : String(value)
        );
      }

      const response =
        await etsyFetch(
          `https://api.etsy.com/v3/application/shops/${shop_id}/listings/${req.params.listingId}`,
          {
            method: "PATCH",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded; charset=utf-8"
            },

            body: form
          },
          session
        );

      const data =
        await response.json();

      if (!response.ok) {
        return res
          .status(response.status)
          .json(data);
      }

      res.json(data);

    } catch (error) {

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ---------------------------------------------------------
   LOCAL SERVER
--------------------------------------------------------- */

if (
  process.env.VERCEL !== "1"
) {
  app.listen(
    PORT,
    () => {
      console.log(
        `Etsy Listing Uploader running at http://localhost:${PORT}`
      );
    }
  );
}

export default app;
