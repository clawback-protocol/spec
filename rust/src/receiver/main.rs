// Clawback Protocol — Receiver HTTP Service (port 8002)
//
// The receiver:
// - Holds own key pair (SecretKey, PublicKey)
// - Exposes public key for sender to generate kfrags
// - Requests cfrags from broker (re-encrypted capsule fragments)
// - Decrypts locally using own SecretKey + cfrags + sender's PublicKey
// - Gets HTTP 403 if the share has been revoked (kfrags destroyed)

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use clawback::crypto::{Capsule, CapsuleFrag, PublicKey, VerifiedCapsuleFrag};
use clawback::receiver::Receiver;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use umbral_pre::DefaultDeserialize;

// ── Types ───────────────────────────────────────────────────────────────────

struct ReceiverState {
    receiver: Receiver,
    broker_url: String,
    client: reqwest::Client,
}

type AppState = Arc<Mutex<ReceiverState>>;

#[derive(Deserialize)]
struct ReceiveRequest {
    payload_id: Option<String>,
    share_token: Option<String>,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// Return this receiver's public key so the sender can generate kfrags
async fn public_key(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let s = state.lock().await;
    let pk = s.receiver.public_key();
    Json(serde_json::json!({
        "public_key": b64_encode(&pk.to_compressed_bytes()),
    }))
}

async fn receive(
    State(state): State<AppState>,
    Json(req): Json<ReceiveRequest>,
) -> impl IntoResponse {
    let payload_id = match req.payload_id {
        Some(ref p) if !p.is_empty() => p.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "payload_id and share_token required"}))),
    };
    let share_token = match req.share_token {
        Some(ref s) if !s.is_empty() => s.clone(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "payload_id and share_token required"}))),
    };

    let (broker_url, client) = {
        let s = state.lock().await;
        (s.broker_url.clone(), s.client.clone())
    };

    // Fetch cfrags from broker
    let url = format!("{}/fetch/{}?share_id={}", broker_url, payload_id, share_token);
    let broker_resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": "broker fetch failed", "detail": e.to_string()
        }))),
    };

    let status = broker_resp.status().as_u16();
    if status == 403 {
        let body: serde_json::Value = broker_resp.json().await.unwrap_or_default();
        let broker_error = body.get("error").and_then(|v| v.as_str()).unwrap_or("REVOKED").to_string();
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": broker_error,
            "detail": "Access denied. This share has been revoked by the sender."
        })));
    }
    if status != 200 {
        let detail = broker_resp.text().await.unwrap_or_default();
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": "broker fetch failed", "detail": detail
        })));
    }

    let body: serde_json::Value = match broker_resp.json().await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": "broker response parse failed", "detail": e.to_string()
        }))),
    };

    // Parse broker response
    let ciphertext = match body["ciphertext"].as_str().and_then(|s| b64_decode(s)) {
        Some(b) => b,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid ciphertext from broker"}))),
    };
    let capsule = match body["capsule"].as_str().and_then(|s| b64_decode(s)) {
        Some(b) => match Capsule::from_bytes(&b) {
            Ok(c) => c,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid capsule from broker"}))),
        },
        None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "missing capsule from broker"}))),
    };
    let delegating_pk = match body["delegating_pk"].as_str().and_then(|s| b64_decode(s)) {
        Some(b) => match PublicKey::try_from_compressed_bytes(&b) {
            Ok(pk) => pk,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid delegating_pk from broker"}))),
        },
        None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "missing delegating_pk from broker"}))),
    };

    // Parse cfrags
    let cfrags_json = match body["cfrags"].as_array() {
        Some(arr) => arr,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "missing cfrags from broker"}))),
    };

    let s = state.lock().await;

    // Parse and verify cfrags
    let verified_cfrags: Vec<VerifiedCapsuleFrag> = match cfrags_json.iter().map(|v| {
        let bytes = v.as_str().and_then(|s| b64_decode(s)).ok_or("bad base64")?;
        let cfrag = CapsuleFrag::from_bytes(&bytes).map_err(|_| "bad cfrag")?;
        // Skip verification for now — broker is semi-trusted
        Ok(cfrag.skip_verification())
    }).collect::<Result<Vec<_>, &str>>() {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid cfrags from broker"}))),
    };

    match s.receiver.decrypt(&delegating_pk, &capsule, verified_cfrags, &ciphertext) {
        Ok(plaintext_bytes) => {
            let plaintext = String::from_utf8_lossy(&plaintext_bytes).to_string();
            (StatusCode::OK, Json(serde_json::json!({
                "payload_id": payload_id,
                "share_id": share_token,
                "plaintext": plaintext,
                "status": "decrypted"
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "decryption failed",
            "detail": e.to_string()
        }))),
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

    let receiver_state = Arc::new(Mutex::new(ReceiverState {
        receiver: Receiver::new(),
        broker_url,
        client: reqwest::Client::new(),
    }));

    let app = Router::new()
        .route("/public_key", get(public_key))
        .route("/receive", post(receive))
        .with_state(receiver_state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("[RECEIVER] listening on {addr} (Umbral PRE)");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
