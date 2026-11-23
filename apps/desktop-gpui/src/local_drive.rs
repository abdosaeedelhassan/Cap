//! Direct Google Drive integration.
//!
//! Cap's shipping Google Drive support is server-backed: the desktop app asks
//! `cap.so` for a Drive resumable upload URL and `cap.so` holds the OAuth
//! tokens. This module is the local counterpart -- a complete OAuth2
//! loopback flow and resumable uploader that talks to Google directly, with
//! the refresh token stored in the app's own store file. Nothing here needs a
//! Cap account or a Cap server.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::upload::{ScreenshotShareOutcome, UploadResult, UploadedItem};

const SECTION: &str = "localDrive";

const EMBEDDED_CLIENT_ID: &str = "202264815644.apps.googleusercontent.com";
const EMBEDDED_CLIENT_SECRET: &str = "X4Z3ca8xfWDb1Voo-F9a7ZxJ";

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DRIVE_FILES: &str = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3/files";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";
const SCOPE: &str =
    "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email";

/// Drive resumable chunks must be a multiple of 256 KiB, except the last one.
const CHUNK_SIZE: u64 = 16 * 1024 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_secs(300);

/// The persisted `localDrive` store section.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    pub access_token: String,
    pub expires_at: u64,
    pub email: Option<String>,
    pub enabled: bool,
}

impl Config {
    pub fn load() -> Self {
        let section = crate::store::store_section(SECTION);
        let string = |key: &str| {
            section
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Self {
            client_id: {
                let stored = string("clientId");
                if stored.is_empty() {
                    EMBEDDED_CLIENT_ID.to_string()
                } else {
                    stored
                }
            },
            client_secret: {
                let stored = string("clientSecret");
                if stored.is_empty() {
                    EMBEDDED_CLIENT_SECRET.to_string()
                } else {
                    stored
                }
            },
            refresh_token: string("refreshToken"),
            access_token: string("accessToken"),
            expires_at: section
                .get("expiresAt")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            email: section
                .get("email")
                .and_then(Value::as_str)
                .filter(|email| !email.is_empty())
                .map(str::to_string),
            enabled: section
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    }

    pub fn save(&self) {
        crate::store::set_store_value(
            SECTION,
            json!({
                "clientId": self.client_id,
                "clientSecret": self.client_secret,
                "refreshToken": self.refresh_token,
                "accessToken": self.access_token,
                "expiresAt": self.expires_at,
                "email": self.email,
                "enabled": self.enabled,
            }),
        );
    }

    pub fn has_credentials(&self) -> bool {
        !self.client_id.trim().is_empty() && !self.client_secret.trim().is_empty()
    }

    pub fn is_connected(&self) -> bool {
        self.has_credentials() && !self.refresh_token.is_empty()
    }
}

/// Whether share/upload actions should go to the local Drive instead of Cap's
/// server. Requires a completed OAuth connection *and* the user's opt-in, so
/// pasting credentials alone never changes where uploads land.
pub fn is_enabled() -> bool {
    let config = Config::load();
    config.enabled && config.is_connected()
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(600))
            .user_agent(concat!("Cap/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default()
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    let mut filled = false;
    #[cfg(unix)]
    {
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            filled = file.read_exact(&mut bytes).is_ok();
        }
    }
    if !filled {
        let seed = now_secs() ^ u64::from(std::process::id());
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = ((seed >> (index % 8 * 8)) & 0xff) as u8 ^ (index as u8).wrapping_mul(37);
        }
    }
    bytes
}

fn random_state() -> String {
    random_bytes::<16>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn base64url(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// PKCE verifier: 32 random bytes, base64url encoded (43 characters).
fn pkce_verifier() -> String {
    base64url(&random_bytes::<32>())
}

/// PKCE challenge: base64url(SHA256(ASCII(verifier))).
fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    base64url(&Sha256::digest(verifier.as_bytes()))
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_query(key), decode_query(value))
        })
        .collect()
}

fn decode_query(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// One OAuth attempt: the URL to open, plus a listener that resolves the
/// authorization code Google redirects back with.
pub struct AuthSession {
    pub url: String,
    redirect_uri: String,
    code_verifier: String,
    rx: flume::Receiver<Result<String, String>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for AuthSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn begin_auth(client_id: &str, client_secret: &str) -> Result<AuthSession, String> {
    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        return Err("Google OAuth client ID and client secret are both required".into());
    }
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("Could not open the local OAuth callback port: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("Could not read the OAuth callback port: {error}"))?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("Could not configure the OAuth callback port: {error}"))?;

    let redirect_uri = format!("http://127.0.0.1:{port}");
    let state = random_state();
    let code_verifier = pkce_verifier();
    let code_challenge = pkce_challenge(&code_verifier);
    let url = format!(
        "{AUTH_URL}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&state={}&code_challenge={}&code_challenge_method=S256",
        urlencode(client_id.trim()),
        urlencode(&redirect_uri),
        urlencode(SCOPE),
        urlencode(&state),
        urlencode(&code_challenge),
    );

    let (tx, rx) = flume::bounded(1);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let expected_state = state.clone();
    let thread = std::thread::spawn(move || {
        let deadline = Instant::now() + AUTH_TIMEOUT;
        while !thread_stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(40));
                    continue;
                }
                Err(_) => break,
            };
            let mut buffer = [0u8; 8192];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let target = request.split_whitespace().nth(1).unwrap_or("/");
            let query = target.split_once('?').map(|(_, query)| query).unwrap_or("");
            let params = parse_query(query);

            let find = |key: &str| {
                params
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.clone())
            };

            if let Some(error) = find("error") {
                respond(
                    &mut stream,
                    "Google Drive authorization failed. You can close this window.",
                );
                let _ = tx.send(Err(format!("Google returned: {error}")));
                break;
            }
            if let Some(code) = find("code") {
                match find("state") {
                    Some(returned) if returned == expected_state => {
                        respond(
                            &mut stream,
                            "Cap is connected to your Google Drive. You can close this window.",
                        );
                        let _ = tx.send(Ok(code));
                        break;
                    }
                    _ => {
                        respond(
                            &mut stream,
                            "Unexpected authorization response. You can close this window.",
                        );
                        let _ = tx.send(Err("Google OAuth state mismatch".into()));
                        break;
                    }
                }
            }
            respond(&mut stream, "Waiting for Google authorization...");
        }
    });

    Ok(AuthSession {
        url,
        redirect_uri,
        code_verifier,
        rx,
        stop,
        thread: Some(thread),
    })
}

fn respond(stream: &mut std::net::TcpStream, message: &str) {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Cap</title>\
         <body style=\"font-family:system-ui;background:#111;color:#eee;display:grid;place-items:center;height:100vh;margin:0\">\
         <p style=\"font-size:16px\">{message}</p></body>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Wait for the browser round-trip, exchange the code for tokens, and store
/// the resulting connection. Consumes the session.
pub async fn finish_auth(session: AuthSession, mut config: Config) -> Result<Config, String> {
    let redirect_uri = session.redirect_uri.clone();
    let code_verifier = session.code_verifier.clone();
    let code = match tokio::time::timeout(AUTH_TIMEOUT, session.rx.recv_async()).await {
        Ok(Ok(Ok(code))) => code,
        Ok(Ok(Err(error))) => return Err(error),
        Ok(Err(_)) => return Err("Google authorization was cancelled".into()),
        Err(_) => return Err("Timed out waiting for Google authorization".into()),
    };
    drop(session);

    exchange_code(&mut config, &code, &redirect_uri, &code_verifier).await?;
    if let Ok(email) = fetch_email(&mut config).await {
        config.email = Some(email);
    }
    config.save();
    Ok(config)
}

async fn exchange_code(
    config: &mut Config,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<(), String> {
    let body = token_request(&[
        ("code", code),
        ("client_id", config.client_id.trim()),
        ("client_secret", config.client_secret.trim()),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
        ("code_verifier", code_verifier),
    ])
    .await?;

    let access_token = body
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "Google did not return an access token".to_string())?;
    let expires_in = body
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(3600);
    config.access_token = access_token.to_string();
    config.expires_at = now_secs() + expires_in;
    match body.get("refresh_token").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => config.refresh_token = token.to_string(),
        _ => {
            if config.refresh_token.is_empty() {
                return Err(
                    "Google did not return a refresh token. Revoke this app's access at \
                     https://myaccount.google.com/permissions and connect again."
                        .into(),
                );
            }
        }
    }
    Ok(())
}

async fn token_request(params: &[(&str, &str)]) -> Result<Value, String> {
    let response = client()
        .post(TOKEN_URL)
        .form(params)
        .send()
        .await
        .map_err(|error| format!("Could not reach Google: {error}"))?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("Could not read Google's token response: {error}"))?;
    if !status.is_success() {
        let message = body
            .get("error_description")
            .and_then(Value::as_str)
            .or_else(|| body.get("error").and_then(Value::as_str))
            .unwrap_or("unknown error");
        return Err(format!("Google sign-in failed: {message}"));
    }
    Ok(body)
}

pub async fn access_token(config: &mut Config) -> Result<String, String> {
    let now = now_secs();
    if !config.access_token.is_empty() && config.expires_at > now + 60 {
        return Ok(config.access_token.clone());
    }
    if config.refresh_token.is_empty() {
        return Err("Not connected to Google Drive".into());
    }
    let body = token_request(&[
        ("client_id", config.client_id.trim()),
        ("client_secret", config.client_secret.trim()),
        ("refresh_token", &config.refresh_token),
        ("grant_type", "refresh_token"),
    ])
    .await?;
    let token = body
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "Google did not refresh the access token".to_string())?;
    config.access_token = token.to_string();
    config.expires_at = now_secs()
        + body
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(3600);
    config.save();
    Ok(config.access_token.clone())
}

async fn fetch_email(config: &mut Config) -> Result<String, String> {
    let token = access_token(config).await?;
    let response = client()
        .get(USERINFO_URL)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| format!("Could not reach Google: {error}"))?;
    if !response.status().is_success() {
        return Err("Google did not return the connected account".into());
    }
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("Could not read the Google account: {error}"))?;
    body.get("email")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Google did not return the connected email".into())
}

pub async fn test_connection(config: &mut Config) -> Result<String, String> {
    let token = access_token(config).await?;
    let response = client()
        .get(format!("{DRIVE_FILES}?pageSize=1&fields=files(id)"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| format!("Could not reach Google Drive: {error}"))?;
    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Google Drive rejected the token: {}", body.trim()));
    }
    let email = fetch_email(config)
        .await
        .unwrap_or_else(|_| "your Google account".into());
    config.email = Some(email.clone());
    config.save();
    Ok(email)
}

pub fn disconnect() {
    let mut config = Config::load();
    config.refresh_token.clear();
    config.access_token.clear();
    config.expires_at = 0;
    config.email = None;
    config.enabled = false;
    config.save();
}

/// One uploaded Drive file.
pub struct UploadedDriveFile {
    pub id: String,
    pub link: String,
}

fn read_range(path: &Path, offset: u64, size: usize) -> Result<Vec<u8>, String> {
    use std::io::{Seek, SeekFrom};
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("Could not open {}: {error}", path.display()))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| format!("Could not seek the export: {error}"))?;
    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer)
        .map_err(|error| format!("Could not read the export: {error}"))?;
    Ok(buffer)
}

/// Resumable upload to `https://www.googleapis.com/upload/drive/v3/files`.
pub async fn upload_file(
    config: &mut Config,
    path: &Path,
    name: &str,
    mime_type: &str,
    progress: &(impl Fn(f64) + ?Sized),
    cancel: &AtomicBool,
) -> Result<UploadedDriveFile, String> {
    let token = access_token(config).await?;
    let size = std::fs::metadata(path)
        .map_err(|error| format!("Could not read {}: {error}", path.display()))?
        .len();
    if size == 0 {
        return Err("The file to upload is empty".into());
    }

    let metadata = json!({ "name": name, "mimeType": mime_type });
    let response = client()
        .post(format!(
            "{DRIVE_UPLOAD}?uploadType=resumable&fields=id,webViewLink&supportsAllDrives=true"
        ))
        .bearer_auth(&token)
        .header("X-Upload-Content-Type", mime_type)
        .header("X-Upload-Content-Length", size.to_string())
        .json(&metadata)
        .send()
        .await
        .map_err(|error| format!("Could not start the Google Drive upload: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Google Drive refused the upload ({}): {}",
            status,
            body.trim()
        ));
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| "Google Drive did not return an upload session".to_string())?;

    let mut offset = 0u64;
    let mut file_id = None;
    while offset < size {
        if cancel.load(Ordering::Relaxed) {
            return Err("Upload cancelled".into());
        }
        let end = (offset + CHUNK_SIZE).min(size);
        let chunk = read_range(path, offset, (end - offset) as usize)?;
        let response = client()
            .put(&location)
            .bearer_auth(&token)
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", offset, end - 1, size),
            )
            .header("Content-Type", mime_type)
            .body(chunk)
            .send()
            .await
            .map_err(|error| format!("Google Drive upload failed: {error}"))?;
        let status = response.status().as_u16();
        if status == 308 {
            offset = end;
            progress((offset as f64 / size as f64) * 0.95);
            continue;
        }
        if response.status().is_success() {
            let body: Value = response
                .json()
                .await
                .map_err(|error| format!("Could not read the Drive upload result: {error}"))?;
            file_id = body
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or(file_id);
            break;
        }
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Google Drive upload failed ({}): {}",
            status,
            body.trim()
        ));
    }

    let id = file_id.ok_or_else(|| "Google Drive did not return the uploaded file".to_string())?;
    progress(0.97);
    share_anyone_with_link(config, &id).await?;
    progress(1.0);
    Ok(UploadedDriveFile {
        link: format!("https://drive.google.com/file/d/{id}/view"),
        id,
    })
}

/// Upload in-memory bytes (screenshots) through the same resumable session.
pub async fn upload_bytes(
    config: &mut Config,
    bytes: &[u8],
    name: &str,
    mime_type: &str,
) -> Result<UploadedDriveFile, String> {
    let token = access_token(config).await?;
    let metadata = json!({ "name": name, "mimeType": mime_type });
    let response = client()
        .post(format!(
            "{DRIVE_UPLOAD}?uploadType=resumable&fields=id,webViewLink&supportsAllDrives=true"
        ))
        .bearer_auth(&token)
        .header("X-Upload-Content-Type", mime_type)
        .header("X-Upload-Content-Length", bytes.len().to_string())
        .json(&metadata)
        .send()
        .await
        .map_err(|error| format!("Could not start the Google Drive upload: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Google Drive refused the upload ({}): {}",
            status,
            body.trim()
        ));
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| "Google Drive did not return an upload session".to_string())?;

    let response = client()
        .put(&location)
        .bearer_auth(&token)
        .header(
            "Content-Range",
            format!("bytes 0-{}/{}", bytes.len().saturating_sub(1), bytes.len()),
        )
        .header("Content-Type", mime_type)
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|error| format!("Google Drive upload failed: {error}"))?;
    let status = response.status();
    if !status.is_success() && status.as_u16() != 308 {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Google Drive upload failed ({}): {}",
            status,
            body.trim()
        ));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("Could not read the Drive upload result: {error}"))?;
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Google Drive did not return the uploaded file".to_string())?;
    share_anyone_with_link(config, &id).await?;
    Ok(UploadedDriveFile {
        link: format!("https://drive.google.com/file/d/{id}/view"),
        id,
    })
}

async fn share_anyone_with_link(config: &mut Config, file_id: &str) -> Result<(), String> {
    let token = access_token(config).await?;
    let response = client()
        .post(format!("{DRIVE_FILES}/{file_id}/permissions?fields=id"))
        .bearer_auth(token)
        .json(&json!({ "role": "reader", "type": "anyone" }))
        .send()
        .await
        .map_err(|error| format!("Could not share the Drive file: {error}"))?;
    if response.status().is_success() {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    Err(format!(
        "Uploaded to Google Drive, but sharing the link failed: {}",
        body.trim()
    ))
}

/// Share an exported recording through the local Drive. Mirrors the outcome
/// contract of `upload::upload_exported_video` so the callers stay unchanged.
pub async fn upload_exported_video(
    project_path: PathBuf,
    progress: &(impl Fn(f64) + ?Sized),
    cancel: Arc<AtomicBool>,
) -> Result<UploadResult, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("Export cancelled".into());
    }
    let mut config = Config::load();
    if !config.is_connected() {
        return Ok(UploadResult::NotAuthenticated);
    }

    let mut meta = cap_project::RecordingMeta::load_for_project(&project_path)
        .map_err(|error| format!("Failed to load recording metadata: {error}"))?;
    let file_path = meta.output_path();
    if !file_path.exists() {
        return Err("Failed to upload video: Rendered video not found".into());
    }
    let name = format!(
        "{}.{}",
        meta.pretty_name,
        file_path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("mp4")
    );
    let mime_type = if name.ends_with(".mp4") {
        "video/mp4"
    } else if name.ends_with(".gif") {
        "image/gif"
    } else {
        "application/octet-stream"
    };

    progress(0.0);
    let uploaded =
        upload_file(&mut config, &file_path, &name, mime_type, progress, &cancel).await?;

    meta.sharing = Some(cap_project::SharingMeta {
        id: uploaded.id,
        link: uploaded.link.clone(),
        content_hash: None,
    });
    meta.upload = Some(cap_project::UploadMeta::Complete);
    meta.save_for_project()
        .map_err(|error| format!("Failed to persist sharing state: {error}"))?;
    crate::app_sounds::play_notification();
    crate::automation::upload_completed(&project_path, None, None);
    Ok(UploadResult::Success(uploaded.link))
}

/// Share a screenshot through the local Drive.
pub async fn upload_screenshot(
    image_bytes: Vec<u8>,
    content_type: &str,
) -> Result<ScreenshotShareOutcome, String> {
    let mut config = Config::load();
    if !config.is_connected() {
        return Ok(ScreenshotShareOutcome::NotAuthenticated);
    }
    let name = format!(
        "Cap screenshot {}.{}",
        chrono_like_stamp(),
        if content_type.eq_ignore_ascii_case("image/png") {
            "png"
        } else {
            "jpg"
        }
    );
    let uploaded = upload_bytes(&mut config, &image_bytes, &name, content_type).await?;
    Ok(ScreenshotShareOutcome::Uploaded(UploadedItem {
        link: uploaded.link,
        id: uploaded.id,
    }))
}

fn chrono_like_stamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

#[allow(dead_code)]
fn _assert_urls() {
    let _ = (AUTH_URL, TOKEN_URL, DRIVE_FILES, DRIVE_UPLOAD, USERINFO_URL);
}
