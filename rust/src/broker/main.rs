// Clawback Protocol — Broker HTTP Service (port 8010) — Umbral PRE
//
// Zero-knowledge intermediary: stores encrypted payloads, holds kfrags
// (NOT encryption keys), re-encrypts capsule fragments for receivers,
// enforces revocation by destroying kfrags. Never sees plaintext.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clawback::broker::Broker;
use clawback::hash_binary_sha384;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use umbral_pre::{Capsule, KeyFrag, PublicKey};

// ── Request / Response types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterRequest {
    payload_id: String,
    encrypted_blob: String,
    capsule: serde_json::Value,
    capsule_ciphertext: String,
    share_id: String,
    kfrags: Vec<serde_json::Value>,
    receiver_pk: serde_json::Value,
    delegating_pk: serde_json::Value,
    verifying_pk: serde_json::Value,
}

#[derive(Deserialize)]
struct AddShareRequest {
    payload_id: String,
    share_id: String,
    kfrags: Vec<serde_json::Value>,
    receiver_pk: serde_json::Value,
    delegating_pk: serde_json::Value,
    verifying_pk: serde_json::Value,
}

#[derive(Deserialize)]
struct FetchQuery {
    share_id: String,
}

#[derive(Deserialize)]
struct RevokeRequest {
    share_id: String,
}

type AppState = Arc<Mutex<Broker>>;

// ── Attestation scaffold ────────────────────────────────────────────────────

#[derive(serde::Serialize, Clone)]
struct AttestationDoc {
    provider: String,
    code_hash: String,
    enclave_id: String,
    attested_at: String,
    pcr0: String,
    note: String,
}

fn simulated_attestation(attested_at: &str) -> AttestationDoc {
    AttestationDoc {
        provider: "simulated".to_string(),
        code_hash: hash_binary_sha384(),
        enclave_id: std::env::var("ENCLAVE_ID").unwrap_or_else(|_| "local-dev".to_string()),
        attested_at: attested_at.to_string(),
        pcr0: hash_binary_sha384(),
        note: "Simulated attestation. In production: AWS Nitro Enclave signed document.".to_string(),
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

async fn attestation_endpoint() -> impl IntoResponse {
    let now = chrono::Utc::now().to_rfc3339();
    let att = simulated_attestation(&now);
    Json(serde_json::json!({
        "broker_version": "0.2.0",
        "attestation": att,
        "instructions": "Compare pcrs.pcr0 against the published code hash at https://github.com/clawback-protocol/spec/releases to verify this broker is running the expected code."
    }))
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let mut broker = state.lock().await;

    let payload_id: uuid::Uuid = match req.payload_id.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid payload_id"}))),
    };
    let share_id: uuid::Uuid = match req.share_id.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid share_id"}))),
    };

    // Decode encrypted blob
    let blob_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, &req.encrypted_blob,
    ) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid base64 in encrypted_blob"}))),
    };
    if blob_bytes.len() < 12 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "encrypted_blob too short"})));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob_bytes[..12]);
    let ciphertext = blob_bytes[12..].to_vec();

    // Deserialize Umbral types
    let delegating_pk: PublicKey = match serde_json::from_value(req.delegating_pk.clone()) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid delegating_pk"}))),
    };
    let receiver_pk: PublicKey = match serde_json::from_value(req.receiver_pk.clone()) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid receiver_pk"}))),
    };
    let verifying_pk: PublicKey = match serde_json::from_value(req.verifying_pk.clone()) {
        Ok(vk) => vk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid verifying_pk"}))),
    };

    // Deserialize and verify kfrags
    let mut verified_kfrags = Vec::new();
    for kf_json in &req.kfrags {
        let kf: KeyFrag = match serde_json::from_value(kf_json.clone()) {
            Ok(kf) => kf,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid kfrag"}))),
        };
        match kf.verify(&verifying_pk, Some(&delegating_pk), Some(&receiver_pk)) {
            Ok(vkf) => verified_kfrags.push(vkf),
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "kfrag verification failed"}))),
        }
    }

    broker.register(
        payload_id, ciphertext, nonce,
        req.capsule.to_string(),
        req.capsule_ciphertext,
        req.delegating_pk.to_string(),
        verifying_pk,
        share_id, verified_kfrags, receiver_pk,
    );

    (StatusCode::CREATED, Json(serde_json::json!({"status": "registered", "payload_id": req.payload_id})))
}

async fn add_share(
    State(state): State<AppState>,
    Json(req): Json<AddShareRequest>,
) -> impl IntoResponse {
    let mut broker = state.lock().await;

    let payload_id: uuid::Uuid = match req.payload_id.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid payload_id"}))),
    };
    let share_id: uuid::Uuid = match req.share_id.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid share_id"}))),
    };

    let payload = match broker.get_payload(&payload_id) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown payload"}))),
    };
    let verifying_pk = payload.verifying_pk.clone();

    let delegating_pk: PublicKey = match serde_json::from_value(req.delegating_pk.clone()) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid delegating_pk"}))),
    };
    let receiver_pk: PublicKey = match serde_json::from_value(req.receiver_pk.clone()) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid receiver_pk"}))),
    };

    let mut verified_kfrags = Vec::new();
    for kf_json in &req.kfrags {
        let kf: KeyFrag = match serde_json::from_value(kf_json.clone()) {
            Ok(kf) => kf,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid kfrag"}))),
        };
        match kf.verify(&verifying_pk, Some(&delegating_pk), Some(&receiver_pk)) {
            Ok(vkf) => verified_kfrags.push(vkf),
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "kfrag verification failed"}))),
        }
    }

    match broker.add_share(&payload_id, share_id, verified_kfrags, receiver_pk) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "share_added", "share_id": req.share_id}))),
        Err(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown payload"}))),
    }
}

async fn fetch(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
    Query(query): Query<FetchQuery>,
) -> impl IntoResponse {
    let broker = state.lock().await;

    let payload_id: uuid::Uuid = match payload_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid payload_id"}))),
    };
    let share_id: uuid::Uuid = match query.share_id.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid share_id"}))),
    };

    // Get kfrags for this share
    let kfrags = match broker.get_share_kfrags(&payload_id, &share_id) {
        Ok(kf) => kf,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("REVOKED") {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "REVOKED", "detail": "This share has been revoked or never existed"})));
            }
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": msg})));
        }
    };

    let payload = broker.get_payload(&payload_id).unwrap();

    // Re-encrypt capsule with kfrags → produce cfrags
    let capsule: Capsule = serde_json::from_str(&payload.capsule_json).unwrap();
    let cfrags: Vec<serde_json::Value> = kfrags
        .into_iter()
        .map(|kf| {
            let cfrag = clawback::reencrypt_for_receiver(&capsule, kf);
            serde_json::to_value(&cfrag).unwrap()
        })
        .collect();

    use base64::Engine;
    let mut blob = Vec::with_capacity(12 + payload.ciphertext.len());
    blob.extend_from_slice(&payload.nonce);
    blob.extend_from_slice(&payload.ciphertext);
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);

    (StatusCode::OK, Json(serde_json::json!({
        "payload_id": payload_id_str,
        "share_id": query.share_id,
        "encrypted_blob": blob_b64,
        "capsule": serde_json::from_str::<serde_json::Value>(&payload.capsule_json).unwrap(),
        "capsule_ciphertext": payload.capsule_ciphertext_b64,
        "cfrags": cfrags,
        "delegating_pk": serde_json::from_str::<serde_json::Value>(&payload.delegating_pk_json).unwrap(),
    })))
}

async fn revoke(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    let mut broker = state.lock().await;

    let payload_id: uuid::Uuid = match payload_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid payload_id"}))),
    };
    let share_id: uuid::Uuid = match req.share_id.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid share_id"}))),
    };

    match broker.revoke(&payload_id, &share_id) {
        Ok(receipt) => {
            let attestation = simulated_attestation(&receipt.revoked_at);
            (StatusCode::OK, Json(serde_json::json!({
                "status": "revoked",
                "receipt": receipt,
                "attestation": attestation,
            })))
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

async fn receipts(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
) -> impl IntoResponse {
    let broker = state.lock().await;

    let payload_id: uuid::Uuid = match payload_id_str.parse() {
        Ok(id) => id,
        Err(_) => return Json(serde_json::json!({"payload_id": payload_id_str, "receipts": []})),
    };

    let recs: Vec<_> = broker.get_receipts(&payload_id).into_iter().cloned().collect();
    Json(serde_json::json!({"payload_id": payload_id_str, "receipts": recs}))
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("BROKER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8010);

    let secret = std::env::var("BROKER_SECRET")
        .unwrap_or_else(|_| "clawback-broker-secret-changeme".to_string());

    let broker = Arc::new(Mutex::new(Broker::new(secret.as_bytes())));

    let app = Router::new()
        .route("/health", get(health))
        .route("/attestation", get(attestation_endpoint))
        .route("/register", post(register))
        .route("/add_share", post(add_share))
        .route("/fetch/{payload_id}", get(fetch))
        .route("/revoke/{payload_id}", post(revoke))
        .route("/receipts/{payload_id}", get(receipts))
        .with_state(broker);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("[BROKER] listening on {addr} (Umbral PRE — zero-knowledge)");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
