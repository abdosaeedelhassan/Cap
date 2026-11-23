# Local Google Drive Integration

Cap's built-in Google Drive support is server-backed — it requires a Cap account and
Cap's cloud service to hold the OAuth tokens and issue upload URLs. This build adds
a **local** Google Drive integration that talks to Google directly from the app.
No Cap account, subscription, or server is needed.

## How it works

1. You create your own Google Cloud OAuth client (see below).
2. Cap opens Google's consent screen in your browser and receives the result on a
   temporary loopback listener (`127.0.0.1:<random-port>`).
3. The refresh token is stored in Cap's local app-data store. PKCE is used for the
   authorization code exchange.
4. Sharing a recording or screenshot uploads the file directly to your Drive via
   the resumable Drive API and sets "anyone with the link" permission, so you get
   a shareable `drive.google.com` link.

## One-time Google Cloud setup

1. Go to <https://console.cloud.google.com/> and create/select a project.
2. Enable the **Google Drive API** (APIs & Services → Library → "Google Drive API").
3. Configure the OAuth consent screen:
   - User Type: **External** (or Internal if you use Google Workspace).
   - Add your own email as a **Test user** (required while the app is in Testing).
   - Scopes: add `.../auth/drive.file` and `.../auth/userinfo.email` (or just
     `openid`/`email` — the app requests them itself; adding them to the consent
     screen avoids "unverified app" warnings).
4. Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
5. Application type: **Desktop app**.
6. Copy the **Client ID** and **Client secret**.

Note: Google automatically allows loopback redirect URIs (`http://127.0.0.1:<port>`)
for Desktop app clients. You do not need to register a redirect URI manually.

## Connect in Cap

1. Open **Settings → Integrations → Local Google Drive → Configure**.
2. Paste the Client ID and Client secret.
3. Click **Connect**. Your browser opens Google's consent screen.
4. Approve access to your Drive (you may see an "unverified app" warning because
   the OAuth app is in Testing — click "Advanced → Go to ... (unsafe)" since it
   is your own project).
5. Cap stores the token and shows "Connected as <your email>".
6. Click **Use Drive for shares** to make all new shares go to your Drive.

Use **Test** to verify the token still works, and **Disconnect** to revoke the
local connection. You can revoke Cap's access at any time from
<https://myaccount.google.com/permissions>.

## Limitations

- **Instant Mode** still uses Cap's server for its during-recording segment uploads;
  the local Drive integration covers exporting/sharing recordings and screenshots.
- Re-sharing a recording that was previously uploaded to local Drive creates a new
  Drive file. If you switch back to Cap's server, old Drive-based share IDs are not
  valid Cap video IDs.
- Drive files are created in "My Drive" root. A configurable folder is not yet exposed.
- The OAuth client secret is stored in Cap's local app-data store (plain JSON). Keep
  your app-data directory private, as with any desktop OAuth client.

## Files

- `apps/desktop-gpui/src/local_drive.rs` — OAuth loopback, token management,
  resumable Drive uploader, sharing.
- `apps/desktop-gpui/src/settings_pages.rs` — Integrations UI page.
- `apps/desktop-gpui/src/upload.rs` — routes shares to local Drive when enabled.
- `apps/desktop-gpui/src/recordings_overlay.rs`, `editor_export.rs` — share gates.
