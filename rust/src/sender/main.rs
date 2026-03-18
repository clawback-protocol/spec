// Clawback Protocol — Sender HTTP Service (port 8001)
//
// The sender owns the data:
// - Generates per-payload key pair (SecretKey never transmitted)
// - Encrypts plaintext to own PublicKey via Umbral PRE
// - Generates kfrags delegating decryption to each receiver
// - Registers capsule + ciphertext + kfrags with broker

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::Engine;
use clawback::crypto::PublicKey;
use clawback::sender::Sender;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use umbral_pre::DefaultSerialize;

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
    receiver_pk: Option<String>,  // base64(compressed PublicKey)
}

#[derive(Deserialize)]
struct ShareRequest {
    receiver_pk: Option<String>,  // base64(compressed PublicKey)
}

#[derive(Deserialize)]
struct RevokeRequest {
    share_id: Option<String>,
}

#[derive(Serialize)]
struct BrokerRegisterReq {
    payload_id: String,
    ciphertext: String,
    capsule: String,
    delegating_pk: String,
    verifying_pk: String,
    share_id: String,
    kfrags: Vec<String>,
    receiver_pk: String,
}

#[derive(Serialize)]
struct BrokerAddShareReq {
    payload_id: String,
    share_id: String,
    kfrags: Vec<String>,
    receiver_pk: String,
}

#[derive(Serialize)]
struct BrokerRevokeReq {
    share_id: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn parse_receiver_pk(b64: Option<&String>) -> Result<PublicKey, (StatusCode, Json<serde_json::Value>)> {
    let b64 = b64.filter(|s| !s.is_empty()).ok_or_else(|| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "receiver_pk required"})),
    ))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid base64 in receiver_pk"})),
    ))?;
    PublicKey::try_from_compressed_bytes(&bytes).map_err(|_| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid receiver public key"})),
    ))
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
    let receiver_pk = match parse_receiver_pk(req.receiver_pk.as_ref()) {
        Ok(pk) => pk,
        Err(e) => return e,
    };

    let (result, broker_url, client) = {
        let mut s = state.lock().await;
        let result = match s.sender.encrypt(plaintext.as_bytes(), &receiver_pk) {
            Ok(r) => r,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
        };
        (result, s.broker_url.clone(), s.client.clone())
    };

    let payload_id_str = result.payload_id.to_string();
    let share_id_str = result.share_id.to_string();

    // Serialize kfrags for broker
    let kfrags_b64: Vec<String> = result.kfrags.iter()
        .map(|vkf| b64_encode(&vkf.clone().unverify().to_bytes().unwrap()))
        .collect();

    let broker_resp = client
        .post(format!("{broker_url}/register"))
        .json(&BrokerRegisterReq {
            payload_id: payload_id_str.clone(),
            ciphertext: b64_encode(&result.ciphertext),
            capsule: b64_encode(&result.capsule.to_bytes().unwrap()),
            delegating_pk: b64_encode(&result.delegating_pk.to_compressed_bytes()),
            verifying_pk: b64_encode(&result.verifying_pk.to_compressed_bytes()),
            share_id: share_id_str.clone(),
            kfrags: kfrags_b64,
            receiver_pk: b64_encode(&receiver_pk.to_compressed_bytes()),
        })
        .send()
        .await;

    match broker_resp {
        Ok(resp) if resp.status().as_u16() == 201 => {}
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
                "error": "broker registration failed", "detail": detail
            })));
        }
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": "broker registration failed", "detail": e.to_string()
        }))),
    }

    (StatusCode::CREATED, Json(serde_json::json!({
        "payload_id": payload_id_str,
        "share_id": share_id_str,
        "share_token": share_id_str,
        "status": "registered"
    })))
}

async fn share(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
    Json(req): Json<ShareRequest>,
) -> impl IntoResponse {
    let payload_id: uuid::Uuid = match payload_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid payload_id"}))),
    };
    let receiver_pk = match parse_receiver_pk(req.receiver_pk.as_ref()) {
        Ok(pk) => pk,
        Err(e) => return e,
    };

    let (share_result, broker_url, client) = {
        let s = state.lock().await;
        let share_result = match s.sender.issue_share(&payload_id, &receiver_pk) {
            Ok(r) => r,
            Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown payload"}))),
        };
        (share_result, s.broker_url.clone(), s.client.clone())
    };

    let share_id_str = share_result.share_id.to_string();
    let kfrags_b64: Vec<String> = share_result.kfrags.iter()
        .map(|vkf| b64_encode(&vkf.clone().unverify().to_bytes().unwrap()))
        .collect();

    let broker_resp = client
        .post(format!("{broker_url}/add_share"))
        .json(&BrokerAddShareReq {
            payload_id: payload_id_str.clone(),
            share_id: share_id_str.clone(),
            kfrags: kfrags_b64,
            receiver_pk: b64_encode(&receiver_pk.to_compressed_bytes()),
        })
        .send()
        .await;

    match broker_resp {
        Ok(resp) if resp.status().as_u16() == 200 => {}
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
                "error": "broker add_share failed", "detail": detail
            })));
        }
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": "broker add_share failed", "detail": e.to_string()
        }))),
    }

    (StatusCode::OK, Json(serde_json::json!({
        "payload_id": payload_id_str,
        "share_id": share_id_str,
        "share_token": share_id_str
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

    let (broker_url, client) = {
        let s = state.lock().await;
        (s.broker_url.clone(), s.client.clone())
    };

    let broker_resp = client
        .post(format!("{broker_url}/revoke/{payload_id}"))
        .json(&BrokerRevokeReq { share_id: share_id.clone() })
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
                "receipt": receipt
            })))
        }
        Ok(resp) => {
            let detail = resp.text().await.unwrap_or_default();
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
                "error": "broker revocation failed", "detail": detail
            })))
        }
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": "broker revocation failed", "detail": e.to_string()
        }))),
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
    eprintln!("[SENDER] listening on {addr} (Umbral PRE)");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
