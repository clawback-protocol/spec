// Clawback Protocol — Sender HTTP Service (port 8011) — Umbral PRE
//
// The sender owns the data:
// - Has Umbral keypair (secret key NEVER transmitted)
// - Encrypts plaintext locally with ChaCha20-Poly1305 (random data key)
// - Uses Umbral to encrypt data key, generates kfrags for receivers
// - Registers encrypted blob + kfrags with broker

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::Engine;
use clawback::sender::Sender;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use umbral_pre::PublicKey;

// ── Internal state ──────────────────────────────────────────────────────────

struct SenderState {
    sender: Sender,
    broker_url: String,
    receiver_url: String,
    client: reqwest::Client,
}

type AppState = Arc<Mutex<SenderState>>;

// ── Request types ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EncryptRequest {
    plaintext: Option<String>,
}

#[derive(Deserialize)]
struct RevokeRequest {
    share_id: Option<String>,
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn encrypt(
    State(state): State<AppState>,
    Json(req): Json<EncryptRequest>,
) -> impl IntoResponse {
    let plaintext = match req.plaintext {
        Some(ref p) if !p.is_empty() => p.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "plaintext required"}))),
    };

    let mut s = state.lock().await;

    // Fetch receiver's public key
    let receiver_pk = match fetch_receiver_pk(&s.client, &s.receiver_url).await {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": format!("receiver key fetch failed: {e}")}))),
    };

    // Encrypt with Umbral PRE
    let result = match s.sender.encrypt(plaintext.as_bytes(), &receiver_pk) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    };

    let payload_id_str = result.payload_id.to_string();
    let share_id_str = result.share_id.to_string();
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(result.encrypted.to_blob());
    let capsule_ct_b64 = base64::engine::general_purpose::STANDARD.encode(&*result.capsule_ciphertext);

    // Serialize Umbral types for broker
    let capsule_json = serde_json::to_value(&result.capsule).unwrap();
    let kfrags_json: Vec<serde_json::Value> = result.kfrags.iter()
        .map(|kf| serde_json::to_value(kf).unwrap())
        .collect();
    let sender_pk_json = serde_json::to_value(&s.sender.keys.public_key).unwrap();
    let verifying_pk_json = serde_json::to_value(&s.sender.keys.signer.verifying_key()).unwrap();
    let receiver_pk_json = serde_json::to_value(&receiver_pk).unwrap();

    // Register with broker
    let broker_resp = s.client
        .post(format!("{}/register", s.broker_url))
        .json(&serde_json::json!({
            "payload_id": payload_id_str,
            "encrypted_blob": blob_b64,
            "capsule": capsule_json,
            "capsule_ciphertext": capsule_ct_b64,
            "share_id": share_id_str,
            "kfrags": kfrags_json,
            "receiver_pk": receiver_pk_json,
            "delegating_pk": sender_pk_json,
            "verifying_pk": verifying_pk_json,
        }))
        .send()
        .await;

    match broker_resp {
        Ok(resp) if resp.status().as_u16() == 201 => {}
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker registration failed", "detail": detail})));
        }
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker registration failed", "detail": e.to_string()}))),
    }

    (StatusCode::CREATED, Json(serde_json::json!({
        "payload_id": payload_id_str,
        "share_id": share_id_str,
        "share_token": share_id_str,
        "status": "registered",
    })))
}

async fn share(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
) -> impl IntoResponse {
    let payload_id: uuid::Uuid = match payload_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid payload_id"}))),
    };

    let s = state.lock().await;

    let receiver_pk = match fetch_receiver_pk(&s.client, &s.receiver_url).await {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": format!("receiver key fetch failed: {e}")}))),
    };

    let result = match s.sender.issue_share(&payload_id, &receiver_pk) {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown payload (not owned by this sender)"}))),
    };

    let share_id_str = result.share_id.to_string();
    let kfrags_json: Vec<serde_json::Value> = result.kfrags.iter()
        .map(|kf| serde_json::to_value(kf).unwrap())
        .collect();
    let sender_pk_json = serde_json::to_value(&s.sender.keys.public_key).unwrap();
    let verifying_pk_json = serde_json::to_value(&s.sender.keys.signer.verifying_key()).unwrap();
    let receiver_pk_json = serde_json::to_value(&receiver_pk).unwrap();

    let broker_resp = s.client
        .post(format!("{}/add_share", s.broker_url))
        .json(&serde_json::json!({
            "payload_id": payload_id_str,
            "share_id": share_id_str,
            "kfrags": kfrags_json,
            "receiver_pk": receiver_pk_json,
            "delegating_pk": sender_pk_json,
            "verifying_pk": verifying_pk_json,
        }))
        .send()
        .await;

    match broker_resp {
        Ok(resp) if resp.status().as_u16() == 200 => {}
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker add_share failed", "detail": detail})));
        }
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker add_share failed", "detail": e.to_string()}))),
    }

    (StatusCode::OK, Json(serde_json::json!({
        "payload_id": payload_id_str,
        "share_id": share_id_str,
        "share_token": share_id_str,
    })))
}

async fn revoke(
    State(state): State<AppState>,
    Path(payload_id): Path<String>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    let share_id = match req.share_id {
        Some(ref s) if !s.is_empty() => s.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "share_id required"}))),
    };

    let s = state.lock().await;

    let broker_resp = s.client
        .post(format!("{}/revoke/{payload_id}", s.broker_url))
        .json(&serde_json::json!({"share_id": share_id}))
        .send()
        .await;

    match broker_resp {
        Ok(resp) if resp.status().as_u16() == 200 => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let receipt = body.get("receipt").cloned().unwrap_or_default();
            (StatusCode::OK, Json(serde_json::json!({
                "status": "revoked",
                "payload_id": payload_id,
                "share_id": share_id,
                "receipt": receipt,
            })))
        }
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker revocation failed", "detail": detail})))
        }
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker revocation failed", "detail": e.to_string()}))),
    }
}

async fn fetch_receiver_pk(client: &reqwest::Client, receiver_url: &str) -> anyhow::Result<PublicKey> {
    let resp = client.get(format!("{receiver_url}/public_key")).send().await?;
    let body: serde_json::Value = resp.json().await?;
    let pk: PublicKey = serde_json::from_value(body["public_key"].clone())?;
    Ok(pk)
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("SENDER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8011);

    let broker_url = std::env::var("BROKER_URL").unwrap_or_else(|_| "http://localhost:8010".to_string());
    let receiver_url = std::env::var("RECEIVER_URL").unwrap_or_else(|_| "http://localhost:8012".to_string());

    let sender_state = Arc::new(Mutex::new(SenderState {
        sender: Sender::new(),
        broker_url,
        receiver_url,
        client: reqwest::Client::new(),
    }));

    let app = Router::new()
        .route("/encrypt", post(encrypt))
        .route("/share/{payload_id}", post(share))
        .route("/revoke/{payload_id}", post(revoke))
        .with_state(sender_state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("[SENDER] listening on {addr} (Umbral PRE)");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
