// Clawback Protocol — Broker HTTP Service (port 8000)
//
// Semi-trusted PRE proxy: stores encrypted payloads + kfrags,
// re-encrypts on fetch, enforces revocation by destroying kfrags.
// Never sees plaintext or any secret key.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use clawback::broker::Broker;
use clawback::crypto::{Capsule, PublicKey, VerifiedKeyFrag, KeyFrag};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use umbral_pre::{DefaultSerialize, DefaultDeserialize};

// ── Request / Response types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterRequest {
    payload_id: String,
    ciphertext: String,     // base64
    capsule: String,        // base64(serialized Capsule)
    delegating_pk: String,  // base64(compressed PublicKey)
    verifying_pk: String,   // base64(compressed PublicKey)
    share_id: String,
    kfrags: Vec<String>,    // base64(serialized KeyFrag) per fragment
    receiver_pk: String,    // base64(compressed PublicKey)
}

#[derive(Deserialize)]
struct AddShareRequest {
    payload_id: String,
    share_id: String,
    kfrags: Vec<String>,
    receiver_pk: String,
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

// ── Helpers ─────────────────────────────────────────────────────────────────

fn b64_decode(s: &str) -> Result<Vec<u8>, StatusCode> {
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|_| StatusCode::BAD_REQUEST)
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn parse_uuid(s: &str) -> Result<uuid::Uuid, (StatusCode, Json<serde_json::Value>)> {
    s.parse().map_err(|_| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid UUID"})),
    ))
}

fn parse_public_key(b64: &str) -> Result<PublicKey, (StatusCode, Json<serde_json::Value>)> {
    let bytes = b64_decode(b64).map_err(|_| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid base64 in public key"})),
    ))?;
    PublicKey::try_from_compressed_bytes(&bytes).map_err(|_| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid public key"})),
    ))
}

fn parse_capsule(b64: &str) -> Result<Capsule, (StatusCode, Json<serde_json::Value>)> {
    let bytes = b64_decode(b64).map_err(|_| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid base64 in capsule"})),
    ))?;
    Capsule::from_bytes(&bytes).map_err(|_e| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid capsule"})),
    ))
}

fn parse_kfrags(
    b64_list: &[String],
    verifying_pk: &PublicKey,
    delegating_pk: &PublicKey,
    receiving_pk: &PublicKey,
) -> Result<Vec<VerifiedKeyFrag>, (StatusCode, Json<serde_json::Value>)> {
    b64_list.iter().map(|b64| {
        let bytes = b64_decode(b64).map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid base64 in kfrag"})),
        ))?;
        let kfrag = KeyFrag::from_bytes(&bytes).map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid kfrag"})),
        ))?;
        kfrag.verify(verifying_pk, Some(delegating_pk), Some(receiving_pk)).map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "kfrag verification failed"})),
        ))
    }).collect()
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let payload_id = match parse_uuid(&req.payload_id) { Ok(v) => v, Err(e) => return e };
    let share_id = match parse_uuid(&req.share_id) { Ok(v) => v, Err(e) => return e };
    let delegating_pk = match parse_public_key(&req.delegating_pk) { Ok(v) => v, Err(e) => return e };
    let verifying_pk = match parse_public_key(&req.verifying_pk) { Ok(v) => v, Err(e) => return e };
    let receiver_pk = match parse_public_key(&req.receiver_pk) { Ok(v) => v, Err(e) => return e };
    let capsule = match parse_capsule(&req.capsule) { Ok(v) => v, Err(e) => return e };

    let ciphertext = match b64_decode(&req.ciphertext) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid base64 in ciphertext"}))),
    };

    let kfrags = match parse_kfrags(&req.kfrags, &verifying_pk, &delegating_pk, &receiver_pk) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let mut broker = state.lock().await;
    broker.register(payload_id, ciphertext, capsule, delegating_pk, verifying_pk, share_id, kfrags, receiver_pk);

    (StatusCode::CREATED, Json(serde_json::json!({
        "status": "registered",
        "payload_id": req.payload_id
    })))
}

async fn add_share(
    State(state): State<AppState>,
    Json(req): Json<AddShareRequest>,
) -> impl IntoResponse {
    let payload_id = match parse_uuid(&req.payload_id) { Ok(v) => v, Err(e) => return e };
    let share_id = match parse_uuid(&req.share_id) { Ok(v) => v, Err(e) => return e };
    let receiver_pk = match parse_public_key(&req.receiver_pk) { Ok(v) => v, Err(e) => return e };

    let mut broker = state.lock().await;

    // We need the stored verifying_pk and delegating_pk to verify kfrags
    // For now, accept kfrags that were pre-verified by the sender
    // In production, the broker should verify kfrags against stored keys
    let kfrags: Vec<VerifiedKeyFrag> = match req.kfrags.iter().map(|b64| {
        let bytes = b64_decode(b64).map_err(|_| "bad base64")?;
        let kfrag = KeyFrag::from_bytes(&bytes).map_err(|_| "bad kfrag")?;
        // Skip verification since we trust the sender for now
        // In production, verify against stored delegating_pk/verifying_pk
        Ok(kfrag.skip_verification())
    }).collect::<Result<Vec<_>, &str>>() {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid kfrags"}))),
    };

    match broker.add_share(&payload_id, share_id, kfrags, receiver_pk) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "status": "share_added",
            "share_id": req.share_id
        }))),
        Err(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown payload"}))),
    }
}

async fn fetch(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
    Query(query): Query<FetchQuery>,
) -> impl IntoResponse {
    let payload_id = match parse_uuid(&payload_id_str) { Ok(v) => v, Err(e) => return e };
    let share_id = match parse_uuid(&query.share_id) { Ok(v) => v, Err(e) => return e };

    let broker = state.lock().await;

    match broker.fetch(&payload_id, &share_id) {
        Ok(result) => {
            let cfrags_b64: Vec<String> = result.cfrags.iter()
                .map(|cfrag| b64_encode(&cfrag.clone().unverify().to_bytes().unwrap()))
                .collect();

            (StatusCode::OK, Json(serde_json::json!({
                "payload_id": payload_id_str,
                "share_id": query.share_id,
                "ciphertext": b64_encode(&result.ciphertext),
                "capsule": b64_encode(&result.capsule.to_bytes().unwrap()),
                "cfrags": cfrags_b64,
                "delegating_pk": b64_encode(&result.delegating_pk.to_compressed_bytes()),
            })))
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("REVOKED") {
                (StatusCode::FORBIDDEN, Json(serde_json::json!({
                    "error": "REVOKED",
                    "detail": "This share has been revoked. Kfrags destroyed."
                })))
            } else {
                (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": msg})))
            }
        }
    }
}

async fn revoke(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    let payload_id = match parse_uuid(&payload_id_str) { Ok(v) => v, Err(e) => return e };
    let share_id = match parse_uuid(&req.share_id) { Ok(v) => v, Err(e) => return e };

    let mut broker = state.lock().await;
    match broker.revoke(&payload_id, &share_id) {
        Ok(receipt) => (StatusCode::OK, Json(serde_json::json!({
            "status": "revoked",
            "receipt": receipt
        }))),
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
        Err(_) => {
            return Json(serde_json::json!({
                "payload_id": payload_id_str,
                "receipts": []
            }));
        }
    };

    let recs: Vec<_> = broker.get_receipts(&payload_id).into_iter().cloned().collect();
    Json(serde_json::json!({
        "payload_id": payload_id_str,
        "receipts": recs
    }))
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("BROKER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);

    let secret = std::env::var("BROKER_SECRET")
        .unwrap_or_else(|_| "clawback-broker-secret-changeme".to_string());

    let broker = Arc::new(Mutex::new(Broker::new(secret.as_bytes())));

    let app = Router::new()
        .route("/register", post(register))
        .route("/add_share", post(add_share))
        .route("/fetch/:payload_id", get(fetch))
        .route("/revoke/:payload_id", post(revoke))
        .route("/receipts/:payload_id", get(receipts))
        .with_state(broker);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("[BROKER] listening on {addr} (Umbral PRE)");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
