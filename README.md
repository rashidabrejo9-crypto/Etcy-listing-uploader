# Etsy Listing Uploader — Professional Vercel Build

## Required Vercel environment variables

Set these in **Production**:

- `ETSY_KEYSTRING` = your Etsy keystring
- `ETSY_SHARED_SECRET` = your Etsy shared secret
- `ETSY_REDIRECT_URI` = `https://etsy-listing-uploader.vercel.app/oauth/callback`
- `SESSION_SECRET` = a long random secret (different from the Etsy shared secret)

After changing environment variables, create a **new deployment**.

## Etsy Developer App

The Redirect URI must be exactly:

https://etsy-listing-uploader.vercel.app/oauth/callback

Do not add a trailing slash.

## Important

Do not put Etsy credentials in frontend JavaScript.

This build uses encrypted HttpOnly cookies instead of an in-memory Map, so OAuth state/session survives Vercel serverless instance changes.

The access token user ID is extracted from the access token prefix and the refresh token is used when the access token is close to expiry.

## Deployment

Upload/replace these files in the GitHub repository:

- `server.js`
- `api/index.js`
- `index.html`
- `vercel.json`
- `package.json`

Then deploy the new commit on Vercel.

## Verification

Open:

`https://etsy-listing-uploader.vercel.app/api/config`

It should report the configured redirect URI.

Then open the home page and use **Connect Etsy Shop**.

Do not test by manually pasting an old Etsy callback URL. Every connection attempt must start from the app so the OAuth state cookie is created first.
