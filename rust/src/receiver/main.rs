// Clawback Protocol — Receiver HTTP Service (port 8012) — Umbral PRE
//
// The receiver:
// - Has its own Umbral keypair
// - Exposes public key via GET /public_key
// - Receives re-encrypted capsule fragments (cfrags) from broker
// - Uses Umbral to decrypt the data key, then decrypts the payload
// - Gets HTTP 403 if the share has been revoked

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use clawback::crypto::EncryptedPayload;
use clawback::receiver::Receiver;
use serde::Deserialize;
use std::sync::Arc;
use umbral_pre::{Capsule, CapsuleFrag, PublicKey};

// ── Types ───────────────────────────────────────────────────────────────────

struct ReceiverState {
    receiver: Receiver,
    broker_url: String,
    client: reqwest::Client,
}

type AppState = Arc<ReceiverState>;

#[derive(Deserialize)]
struct ReceiveRequest {
    payload_id: Option<String>,
    share_token: Option<String>,
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn public_key(State(state): State<AppState>) -> impl IntoResponse {
    let pk_json = serde_json::to_value(&state.receiver.public_key).unwrap();
    Json(serde_json::json!({"public_key": pk_json}))
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

    // Fetch from broker
    let url = format!("{}/fetch/{}?share_id={}", state.broker_url, payload_id, share_token);

    let broker_resp = match state.client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker fetch failed", "detail": e.to_string()}))),
    };

    let status = broker_resp.status().as_u16();

    if status == 403 {
        let body: serde_json::Value = broker_resp.json().await.unwrap_or_default();
        let broker_error = body.get("error").and_then(|v| v.as_str()).unwrap_or("REVOKED").to_string();
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": broker_error, "detail": "Access denied. This share has been revoked by the sender."})));
    }

    if status != 200 {
        let detail = broker_resp.text().await.unwrap_or_default();
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker fetch failed", "detail": detail})));
    }

    let body: serde_json::Value = match broker_resp.json().await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "broker response parse failed", "detail": e.to_string()}))),
    };

    // Decode encrypted blob
    let encrypted_blob_b64 = body["encrypted_blob"].as_str().unwrap_or("");
    let encrypted_blob = match base64::engine::general_purpose::STANDARD.decode(encrypted_blob_b64) {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid base64 from broker"}))),
    };

    let payload = match EncryptedPayload::from_blob(&encrypted_blob) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid payload", "detail": e.to_string()}))),
    };

    // Deserialize Umbral types
    let capsule: Capsule = match serde_json::from_value(body["capsule"].clone()) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid capsule", "detail": e.to_string()}))),
    };

    let capsule_ct_b64 = body["capsule_ciphertext"].as_str().unwrap_or("");
    let capsule_ciphertext = match base64::engine::general_purpose::STANDARD.decode(capsule_ct_b64) {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid capsule_ciphertext base64"}))),
    };

    let sender_pk: PublicKey = match serde_json::from_value(body["delegating_pk"].clone()) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid delegating_pk", "detail": e.to_string()}))),
    };

    // Deserialize cfrags — they come as VerifiedCapsuleFrag from broker (broker already verified)
    let cfrags_json = body["cfrags"].as_array();
    if cfrags_json.is_none() || cfrags_json.unwrap().is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "no cfrags from broker"})));
    }

    // The broker serializes VerifiedCapsuleFrag, but we need to deserialize as CapsuleFrag and verify
    let mut verified_cfrags = Vec::new();
    for cf_json in cfrags_json.unwrap() {
        let cfrag: CapsuleFrag = match serde_json::from_value(cf_json.clone()) {
            Ok(cf) => cf,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "invalid cfrag", "detail": e.to_string()}))),
        };
        // We need the verifying key to verify cfrag — the broker should include it,
        // but for simplicity we skip full verification here since broker already verified.
        // In production: verify cfrag against sender's verifying key.
        match cfrag.verify(&capsule, &sender_pk, &sender_pk, &state.receiver.public_key) {
            Ok(vcf) => verified_cfrags.push(vcf),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "cfrag verification failed", "detail": format!("{:?}", e)}))),
        }
    }

    // Decrypt via Umbral PRE
    match state.receiver.decrypt_umbral(&sender_pk, &capsule, verified_cfrags, &capsule_ciphertext, &payload) {
        Ok(plaintext_bytes) => {
            let plaintext = String::from_utf8_lossy(&plaintext_bytes).to_string();
            (StatusCode::OK, Json(serde_json::json!({
                "payload_id": payload_id,
                "share_id": share_token,
                "plaintext": plaintext,
                "status": "decrypted",
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "decryption failed", "detail": e.to_string()}))),
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("RECEIVER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8012);

    let broker_url = std::env::var("BROKER_URL").unwrap_or_else(|_| "http://localhost:8010".to_string());

    let receiver_state = Arc::new(ReceiverState {
        receiver: Receiver::new(),
        broker_url,
        client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/public_key", get(public_key))
        .route("/receive", post(receive))
        .with_state(receiver_state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("[RECEIVER] listening on {addr} (Umbral PRE)");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
