// Clawback Protocol — Sender HTTP Service (port 8011)
//
// The sender owns the data:
// - Generates master_key (NEVER transmitted)
// - Encrypts plaintext locally with ChaCha20-Poly1305
// - Derives enc_key via HKDF, uses enc_key as share_key (simulated PRE)
// - Registers encrypted blob + share_key with broker
// - Can revoke any share at any time

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::Engine;
use clawback::sender::Sender;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

// ── Internal state ──────────────────────────────────────────────────────────

struct SenderState {
    sender: Sender,
    broker_url: String,
    client: reqwest::Client,
}

type AppState = Arc<Mutex<SenderState>>;

// ── Request / Response types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct EncryptRequest {
    plaintext: Option<String>,
}

#[derive(Deserialize)]
struct RevokeRequest {
    share_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BrokerRegisterReq {
    payload_id: String,
    encrypted_blob: String,
    share_id: String,
    share_key: String,
}

#[derive(Serialize, Deserialize)]
struct BrokerAddShareReq {
    payload_id: String,
    share_id: String,
    share_key: String,
}

#[derive(Serialize, Deserialize)]
struct BrokerRevokeReq {
    share_id: String,
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn encrypt(
    State(state): State<AppState>,
    Json(req): Json<EncryptRequest>,
) -> impl IntoResponse {
    let plaintext = match req.plaintext {
        Some(ref p) if !p.is_empty() => p.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "plaintext required"})),
            )
        }
    };

    // Encrypt using library Sender
    let (payload_id, share_id, encrypted, share_key_bytes, broker_url, client) = {
        let mut s = state.lock().await;
        let (payload_id, share_id, encrypted, share_key_bytes) =
            match s.sender.encrypt(plaintext.as_bytes()) {
                Ok(result) => result,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                }
            };
        (
            payload_id,
            share_id,
            encrypted,
            share_key_bytes,
            s.broker_url.clone(),
            s.client.clone(),
        )
    };

    let payload_id_str = payload_id.to_string();
    let share_id_str = share_id.to_string();
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(encrypted.to_blob());
    let share_key_b64 = base64::engine::general_purpose::STANDARD.encode(&share_key_bytes);

    // Register with broker
    let broker_resp = client
        .post(format!("{broker_url}/register"))
        .json(&BrokerRegisterReq {
            payload_id: payload_id_str.clone(),
            encrypted_blob: blob_b64,
            share_id: share_id_str.clone(),
            share_key: share_key_b64,
        })
        .send()
        .await;

    match broker_resp {
        Ok(resp) if resp.status().as_u16() == 201 => {}
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "broker registration failed",
                    "detail": detail
                })),
            );
        }
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "broker registration failed",
                    "detail": e.to_string()
                })),
            );
        }
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "payload_id": payload_id_str,
            "share_id": share_id_str,
            "share_token": share_id_str,
            "status": "registered"
        })),
    )
}

async fn share(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
) -> impl IntoResponse {
    let payload_id: uuid::Uuid = match payload_id_str.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid payload_id"})),
            )
        }
    };

    let (share_id, share_key_bytes, broker_url, client) = {
        let s = state.lock().await;
        let (share_id, share_key_bytes) = match s.sender.issue_share(&payload_id) {
            Ok(result) => result,
            Err(_) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "unknown payload (not owned by this sender)"
                    })),
                )
            }
        };
        (share_id, share_key_bytes, s.broker_url.clone(), s.client.clone())
    };

    let share_id_str = share_id.to_string();
    let share_key_b64 = base64::engine::general_purpose::STANDARD.encode(&share_key_bytes);

    let broker_resp = client
        .post(format!("{broker_url}/add_share"))
        .json(&BrokerAddShareReq {
            payload_id: payload_id_str.clone(),
            share_id: share_id_str.clone(),
            share_key: share_key_b64,
        })
        .send()
        .await;

    match broker_resp {
        Ok(resp) if resp.status().as_u16() == 200 => {}
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "broker add_share failed",
                    "detail": detail
                })),
            );
        }
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "broker add_share failed",
                    "detail": e.to_string()
                })),
            );
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "payload_id": payload_id_str,
            "share_id": share_id_str,
            "share_token": share_id_str
        })),
    )
}

async fn revoke(
    State(state): State<AppState>,
    Path(payload_id): Path<String>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    let share_id = match req.share_id {
        Some(ref s) if !s.is_empty() => s.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "share_id required"})),
            )
        }
    };

    let (broker_url, client) = {
        let s = state.lock().await;
        (s.broker_url.clone(), s.client.clone())
    };

    let broker_resp = client
        .post(format!("{broker_url}/revoke/{payload_id}"))
        .json(&BrokerRevokeReq {
            share_id: share_id.clone(),
        })
        .send()
        .await;

    match broker_resp {
        Ok(resp) if resp.status().as_u16() == 200 => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let receipt = body.get("receipt").cloned().unwrap_or_default();

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "revoked",
                    "payload_id": payload_id,
                    "share_id": share_id,
                    "receipt": receipt
                })),
            )
        }
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "broker revocation failed",
                    "detail": detail
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "broker revocation failed",
                "detail": e.to_string()
            })),
        ),
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("SENDER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8011);

    let broker_url =
        std::env::var("BROKER_URL").unwrap_or_else(|_| "http://localhost:8010".to_string());

    let sender_state = Arc::new(Mutex::new(SenderState {
        sender: Sender::new(),
        broker_url,
        client: reqwest::Client::new(),
    }));

    let app = Router::new()
        .route("/encrypt", post(encrypt))
        .route("/share/:payload_id", post(share))
        .route("/revoke/:payload_id", post(revoke))
        .with_state(sender_state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("[SENDER] listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
