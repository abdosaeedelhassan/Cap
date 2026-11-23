# Local Google Drive Integration

Cap's built-in Google Drive support is server-backed — it requires a Cap account and
Cap's cloud service to hold the OAuth tokens and issue upload URLs. This build adds
a **local** Google Drive integration that talks to Google directly from the app.
No Cap account, subscription, or server is needed.

## How it works

1. Click **Connect** in Settings → Integrations → Local Google Drive.
2. Cap opens Google's consent screen in your browser and receives the result on a
   temporary loopback listener (`127.0.0.1:<random-port>`).
3. The refresh token is stored in Cap's local app-data store. PKCE is used for the
   authorization code exchange.
4. Sharing a recording or screenshot uploads the file directly to your Drive via
   the resumable Drive API and sets "anyone with the link" permission, so you get
   a shareable `drive.google.com` link.

No Google Cloud Console setup is required — an OAuth client is embedded in the app.

## Connect in Cap

1. Open **Settings → Integrations → Local Google Drive**.
2. Click **Connect**. Your browser opens Google's consent screen.
3. Sign in to your Google account and approve access to your Drive.
4. Cap stores the token and shows "Connected as <your email>".
5. Click **Use Drive for shares** to make all new shares go to your Drive.

Use **Test** to verify the token still works, and **Disconnect** to revoke the
local connection. You can also revoke Cap's access at any time from
<https://myaccount.google.com/permissions>.

## Limitations

- **Instant Mode** still uses Cap's server for its during-recording segment uploads;
  the local Drive integration covers exporting/sharing recordings and screenshots.
- Re-sharing a recording that was previously uploaded to local Drive creates a new
  Drive file. If you switch back to Cap's server, old Drive-based share IDs are not
  valid Cap video IDs.
- Drive files are created in "My Drive" root. A configurable folder is not yet exposed.
- The embedded OAuth client is rclone's shared public client. If Google retires it,
  sharing will stop working until a replacement client is embedded. Advanced users
  can override it by setting `clientId` and `clientSecret` in the `localDrive`
  section of Cap's app-data store.

## Files

- `apps/desktop-gpui/src/local_drive.rs` — OAuth loopback, token management,
  resumable Drive uploader, sharing.
- `apps/desktop-gpui/src/settings_pages.rs` — Integrations UI page.
- `apps/desktop-gpui/src/upload.rs` — routes shares to local Drive when enabled.
- `apps/desktop-gpui/src/recordings_overlay.rs`, `editor_export.rs` — share gates.
