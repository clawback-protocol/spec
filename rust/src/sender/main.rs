// Clawback Protocol — Sender HTTP Service (port 8001)
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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Internal state ──────────────────────────────────────────────────────────

struct PayloadEntry {
    #[allow(dead_code)]
    master_key: Vec<u8>,
    enc_key: Vec<u8>,
    shares: HashMap<String, bool>,
}

struct SenderState {
    payloads: HashMap<String, PayloadEntry>,
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

// ── Crypto helpers (matching Python PoC) ────────────────────────────────────

fn generate_master_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn derive_enc_key(master_key: &[u8]) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = vec![0u8; 32];
    hk.expand(b"payload-encryption", &mut okm)
        .expect("HKDF expand failed");
    okm
}

fn encrypt_payload(plaintext: &[u8], enc_key: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    use rand::RngCore;

    let cipher = ChaCha20Poly1305::new_from_slice(enc_key).expect("invalid key length");
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failed");

    // Return nonce || ciphertext (matches Python format)
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    blob
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

    let payload_id = uuid::Uuid::new_v4().to_string();
    let share_id = uuid::Uuid::new_v4().to_string();
    let master_key = generate_master_key();
    let enc_key = derive_enc_key(&master_key);

    let blob = encrypt_payload(plaintext.as_bytes(), &enc_key);
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);

    // In simulated PRE, share_key = enc_key (all shares decrypt same ciphertext)
    let share_key_b64 = base64::engine::general_purpose::STANDARD.encode(&enc_key);

    // Register with broker
    let (broker_url, client) = {
        let s = state.lock().unwrap();
        (s.broker_url.clone(), s.client.clone())
    };

    let broker_resp = client
        .post(format!("{broker_url}/register"))
        .json(&BrokerRegisterReq {
            payload_id: payload_id.clone(),
            encrypted_blob: blob_b64,
            share_id: share_id.clone(),
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

    // Store keys locally — master_key never leaves this service
    {
        let mut s = state.lock().unwrap();
        let mut shares = HashMap::new();
        shares.insert(share_id.clone(), true);
        s.payloads.insert(
            payload_id.clone(),
            PayloadEntry {
                master_key,
                enc_key,
                shares,
            },
        );
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "payload_id": payload_id,
            "share_id": share_id,
            "share_token": share_id,
            "status": "registered"
        })),
    )
}

async fn share(
    State(state): State<AppState>,
    Path(payload_id): Path<String>,
) -> impl IntoResponse {
    let (enc_key, broker_url, client) = {
        let s = state.lock().unwrap();
        let entry = match s.payloads.get(&payload_id) {
            Some(e) => e,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "unknown payload (not owned by this sender)"
                    })),
                )
            }
        };
        (entry.enc_key.clone(), s.broker_url.clone(), s.client.clone())
    };

    let share_id = uuid::Uuid::new_v4().to_string();
    let share_key_b64 = base64::engine::general_purpose::STANDARD.encode(&enc_key);

    let broker_resp = client
        .post(format!("{broker_url}/add_share"))
        .json(&BrokerAddShareReq {
            payload_id: payload_id.clone(),
            share_id: share_id.clone(),
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

    {
        let mut s = state.lock().unwrap();
        if let Some(entry) = s.payloads.get_mut(&payload_id) {
            entry.shares.insert(share_id.clone(), true);
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "payload_id": payload_id,
            "share_id": share_id,
            "share_token": share_id
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
        let s = state.lock().unwrap();
        if !s.payloads.contains_key(&payload_id) {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "unknown payload"})),
            );
        }
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

            {
                let mut s = state.lock().unwrap();
                if let Some(entry) = s.payloads.get_mut(&payload_id) {
                    entry.shares.remove(&share_id);
                }
            }

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
        .unwrap_or(8001);

    let broker_url =
        std::env::var("BROKER_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

    let sender_state = Arc::new(Mutex::new(SenderState {
        payloads: HashMap::new(),
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
