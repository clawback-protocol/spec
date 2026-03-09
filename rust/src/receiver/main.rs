// Clawback Protocol — Receiver HTTP Service (port 8002)
//
// The receiver:
// - Presents share_token to broker via HTTP
// - Receives encrypted blob + share_key
// - Decrypts locally using ChaCha20-Poly1305
// - Gets HTTP 403 if the share has been revoked

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::Engine;
use serde::Deserialize;
use std::sync::Arc;

// ── Types ───────────────────────────────────────────────────────────────────

struct ReceiverState {
    broker_url: String,
    client: reqwest::Client,
}

type AppState = Arc<ReceiverState>;

#[derive(Deserialize)]
struct ReceiveRequest {
    payload_id: Option<String>,
    share_token: Option<String>,
}

// ── Crypto helper ───────────────────────────────────────────────────────────

fn decrypt_blob(blob: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

    if blob.len() < 12 {
        return Err("blob too short".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("invalid key: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {e}"))
}

// ── Handler ─────────────────────────────────────────────────────────────────

async fn receive(
    State(state): State<AppState>,
    Json(req): Json<ReceiveRequest>,
) -> impl IntoResponse {
    let payload_id = match req.payload_id {
        Some(ref p) if !p.is_empty() => p.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "payload_id and share_token required"})),
            )
        }
    };
    let share_token = match req.share_token {
        Some(ref s) if !s.is_empty() => s.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "payload_id and share_token required"})),
            )
        }
    };

    // Fetch from broker
    let url = format!(
        "{}/fetch/{}?share_id={}",
        state.broker_url, payload_id, share_token
    );

    let broker_resp = match state.client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "broker fetch failed",
                    "detail": e.to_string()
                })),
            )
        }
    };

    let status = broker_resp.status().as_u16();

    if status == 403 {
        let body: serde_json::Value = broker_resp.json().await.unwrap_or_default();
        let broker_error = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("REVOKED")
            .to_string();
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": broker_error,
                "detail": "Access denied. This share has been revoked by the sender."
            })),
        );
    }

    if status != 200 {
        let detail = broker_resp.text().await.unwrap_or_default();
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "broker fetch failed",
                "detail": detail
            })),
        );
    }

    let body: serde_json::Value = match broker_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "broker response parse failed",
                    "detail": e.to_string()
                })),
            )
        }
    };

    let encrypted_blob_b64 = body["encrypted_blob"].as_str().unwrap_or("");
    let share_key_b64 = body["share_key"].as_str().unwrap_or("");

    let encrypted_blob = match base64::engine::general_purpose::STANDARD.decode(encrypted_blob_b64)
    {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "invalid base64 from broker"})),
            )
        }
    };
    let share_key = match base64::engine::general_purpose::STANDARD.decode(share_key_b64) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "invalid base64 from broker"})),
            )
        }
    };

    match decrypt_blob(&encrypted_blob, &share_key) {
        Ok(plaintext_bytes) => {
            let plaintext = String::from_utf8_lossy(&plaintext_bytes).to_string();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "payload_id": payload_id,
                    "share_id": share_token,
                    "plaintext": plaintext,
                    "status": "decrypted"
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "decryption failed",
                "detail": e
            })),
        ),
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("RECEIVER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8002);

    let broker_url =
        std::env::var("BROKER_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

    let receiver_state = Arc::new(ReceiverState {
        broker_url,
        client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/receive", post(receive))
        .with_state(receiver_state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("[RECEIVER] listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
