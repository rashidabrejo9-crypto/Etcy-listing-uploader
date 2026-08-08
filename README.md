# Etsy Listing Uploader Dashboard

A working starter dashboard based on the uploaded prototype, upgraded for Etsy Open API v3.

## Included

- Etsy OAuth 2.0 Authorization Code flow with PKCE
- Server-side API key/shared-secret handling
- Shop discovery
- Active/draft listing loading
- Listing creation as a real Etsy draft
- Up to 13 tags in the UI
- Etsy listing images upload
- Digital file upload
- Listing video upload
- Draft -> active publishing through Etsy API
- Local browser draft management
- Search, filters, bulk workflow UI
- Validation for required Etsy fields
- No Etsy secrets in browser JavaScript

## Important Etsy setup

1. Create/configure an Etsy Open API app.
2. Add your exact HTTPS callback URL in Etsy Developer Portal.
3. Copy the app keystring and shared secret into `.env`.
4. Use the same redirect URI in `.env`.
5. Run `npm install` then `npm start`.
6. Open the dashboard and click Connect Etsy Shop.

For local development, use the callback URL supported by your Etsy app configuration. Etsy requires registered redirect URIs to match exactly; production OAuth should use HTTPS.

## Notes

- Etsy write endpoints require OAuth and appropriate scopes. This project requests `shops_r listings_r listings_w`.
- The dashboard intentionally keeps the Etsy shared secret on the server.
- OAuth sessions are in memory for this starter. For production, use a database/session store and encrypted token storage.
- The SKU field in the original prototype is kept as a local planning field. Etsy inventory/SKU management is a separate API workflow and is not silently faked.
- Taxonomy ID is required for reliable listing creation; enter the correct Etsy seller taxonomy ID for the product.
- Publishing an Etsy draft to active requires the listing image requirement to be satisfied.
