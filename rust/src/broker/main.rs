// Clawback Protocol — Broker HTTP Service (port 8000)
//
// Zero-knowledge intermediary: stores encrypted payloads, manages share keys,
// enforces revocation, logs destruction receipts. Never sees plaintext.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clawback::broker::Broker;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

// ── Request / Response types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterRequest {
    payload_id: String,
    encrypted_blob: String, // base64(nonce || ciphertext)
    share_id: String,
    share_key: String, // base64
}

#[derive(Deserialize)]
struct AddShareRequest {
    payload_id: String,
    share_id: String,
    share_key: String, // base64
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

// ── Handlers ────────────────────────────────────────────────────────────────

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let mut broker = state.lock().await;

    let payload_id: uuid::Uuid = match req.payload_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid payload_id"})),
            )
        }
    };
    let share_id: uuid::Uuid = match req.share_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid share_id"})),
            )
        }
    };

    // Decode base64 blob → nonce || ciphertext
    let blob_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.encrypted_blob,
    ) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid base64 in encrypted_blob"})),
            )
        }
    };

    if blob_bytes.len() < 12 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "encrypted_blob too short"})),
        );
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob_bytes[..12]);
    let ciphertext = blob_bytes[12..].to_vec();

    let share_key_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.share_key,
    ) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid base64 in share_key"})),
            )
        }
    };

    broker.register(payload_id, ciphertext, nonce, share_id, share_key_bytes);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "registered",
            "payload_id": req.payload_id
        })),
    )
}

async fn add_share(
    State(state): State<AppState>,
    Json(req): Json<AddShareRequest>,
) -> impl IntoResponse {
    let mut broker = state.lock().await;

    let payload_id: uuid::Uuid = match req.payload_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid payload_id"})),
            )
        }
    };
    let share_id: uuid::Uuid = match req.share_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid share_id"})),
            )
        }
    };

    let share_key_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.share_key,
    ) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid base64 in share_key"})),
            )
        }
    };

    match broker.add_share(&payload_id, share_id, share_key_bytes) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "share_added",
                "share_id": req.share_id
            })),
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "unknown payload"})),
        ),
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
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid payload_id"})),
            )
        }
    };
    let share_id: uuid::Uuid = match query.share_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid share_id"})),
            )
        }
    };

    match broker.fetch(&payload_id, &share_id) {
        Ok((ciphertext, nonce, share_key)) => {
            use base64::Engine;
            // Reconstruct blob = nonce || ciphertext (matches Python format)
            let mut blob = Vec::with_capacity(12 + ciphertext.len());
            blob.extend_from_slice(nonce);
            blob.extend_from_slice(ciphertext);
            let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(share_key);

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "payload_id": payload_id_str,
                    "share_id": query.share_id,
                    "encrypted_blob": blob_b64,
                    "share_key": key_b64
                })),
            )
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("REVOKED") {
                (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "REVOKED",
                        "detail": "This share has been revoked or never existed"
                    })),
                )
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": msg})),
                )
            }
        }
    }
}

async fn revoke(
    State(state): State<AppState>,
    Path(payload_id_str): Path<String>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    let mut broker = state.lock().await;

    let payload_id: uuid::Uuid = match payload_id_str.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid payload_id"})),
            )
        }
    };
    let share_id: uuid::Uuid = match req.share_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid share_id"})),
            )
        }
    };

    match broker.revoke(&payload_id, &share_id) {
        Ok(receipt) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "revoked",
                "receipt": receipt
            })),
        ),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
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
            // Still return empty receipts for non-uuid paths (health-check compat)
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
    eprintln!("[BROKER] listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
