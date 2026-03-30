// Clawback Protocol — Destruction Receipt Verifier Tests
//
// Tests the verify CLI's core logic: schema validation, HMAC verification,
// and broker liveness checks.

use clawback::crypto::{generate_destruction_proof, PayloadId};

/// Helper: generate a valid destruction receipt as JSON
fn make_receipt(broker_secret: &[u8], payload_id: &PayloadId, share_id: &uuid::Uuid) -> serde_json::Value {
    let revoked_at = "2026-03-17T12:00:00Z";
    let data_hash = "a".repeat(64); // valid 64-char hex
    let proof = generate_destruction_proof(broker_secret, payload_id, revoked_at);

    serde_json::json!({
        "payload_id": payload_id.to_string(),
        "share_id": share_id.to_string(),
        "data_hash": data_hash,
        "revoked_at": revoked_at,
        "destruction_proof": proof,
        "status": "DESTROYED"
    })
}

// ── Schema validation tests ─────────────────────────────────────────────────

#[test]
fn valid_receipt_passes_verification() {
    let secret = b"test-broker-secret";
    let payload_id = PayloadId::new_v4();
    let share_id = uuid::Uuid::new_v4();
    let receipt = make_receipt(secret, &payload_id, &share_id);

    // Write receipt to temp file
    let dir = std::env::temp_dir().join("clawback_test_valid");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();

    // Run clawback-verify with --json
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "test-broker-secret",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    assert_eq!(result["verdict"], "VERIFIED");
    assert_eq!(result["schema_valid"], true);
    assert_eq!(result["proof_valid"], true);
    assert_eq!(result["payload_id"], payload_id.to_string());
    assert!(output.status.success(), "exit code should be 0");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn tampered_proof_fails_verification() {
    let secret = b"test-broker-secret";
    let payload_id = PayloadId::new_v4();
    let share_id = uuid::Uuid::new_v4();
    let mut receipt = make_receipt(secret, &payload_id, &share_id);

    // Tamper with the destruction proof
    receipt["destruction_proof"] = serde_json::json!("b".repeat(64));

    let dir = std::env::temp_dir().join("clawback_test_tampered");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "test-broker-secret",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    assert_eq!(result["verdict"], "INVALID");
    assert_eq!(result["schema_valid"], true);
    assert_eq!(result["proof_valid"], false);
    assert!(!output.status.success(), "exit code should be non-zero");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_secret_fails_verification() {
    let secret = b"test-broker-secret";
    let payload_id = PayloadId::new_v4();
    let share_id = uuid::Uuid::new_v4();
    let receipt = make_receipt(secret, &payload_id, &share_id);

    let dir = std::env::temp_dir().join("clawback_test_wrong_secret");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();

    // Use wrong secret
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "wrong-secret",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    assert_eq!(result["verdict"], "INVALID");
    assert_eq!(result["proof_valid"], false);
    assert!(!output.status.success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_payload_id_fails_verification() {
    let secret = b"test-broker-secret";
    let payload_id = PayloadId::new_v4();
    let share_id = uuid::Uuid::new_v4();
    let mut receipt = make_receipt(secret, &payload_id, &share_id);

    // Replace payload_id with a different UUID — proof no longer matches
    let wrong_id = PayloadId::new_v4();
    receipt["payload_id"] = serde_json::json!(wrong_id.to_string());

    let dir = std::env::temp_dir().join("clawback_test_wrong_pid");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "test-broker-secret",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    assert_eq!(result["verdict"], "INVALID");
    assert_eq!(result["proof_valid"], false);
    assert!(!output.status.success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn missing_fields_fails_schema_validation() {
    let receipt = serde_json::json!({
        "payload_id": uuid::Uuid::new_v4().to_string(),
        "status": "DESTROYED"
        // missing: share_id, data_hash, revoked_at, destruction_proof
    });

    let dir = std::env::temp_dir().join("clawback_test_missing");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "test-broker-secret",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    assert_eq!(result["verdict"], "INVALID");
    assert_eq!(result["schema_valid"], false);
    let errors = result["errors"].as_array().unwrap();
    assert!(errors.len() >= 3, "should have multiple missing field errors, got: {errors:?}");
    assert!(!output.status.success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn invalid_status_fails() {
    let secret = b"test-broker-secret";
    let payload_id = PayloadId::new_v4();
    let share_id = uuid::Uuid::new_v4();
    let mut receipt = make_receipt(secret, &payload_id, &share_id);
    receipt["status"] = serde_json::json!("ACTIVE");

    let dir = std::env::temp_dir().join("clawback_test_status");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "test-broker-secret",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    assert_eq!(result["verdict"], "INVALID");
    assert_eq!(result["schema_valid"], false);
    assert!(!output.status.success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn invalid_json_fails() {
    let dir = std::env::temp_dir().join("clawback_test_badjson");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, "not valid json{{{").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "test-broker-secret",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    assert_eq!(result["verdict"], "INVALID");
    assert!(!output.status.success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn broker_unreachable_still_verifies_proof() {
    let secret = b"test-broker-secret";
    let payload_id = PayloadId::new_v4();
    let share_id = uuid::Uuid::new_v4();
    let receipt = make_receipt(secret, &payload_id, &share_id);

    let dir = std::env::temp_dir().join("clawback_test_broker_unreach");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();

    // Point at a port nothing is listening on
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "test-broker-secret",
            "--broker-url", "http://127.0.0.1:19999",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    // Proof is valid, but broker unreachable — verdict depends on implementation
    // Current impl: VERIFIED if proof_valid && broker_confirmed != Some(false)
    // broker_confirmed is None when unreachable, so verdict is VERIFIED
    assert_eq!(result["proof_valid"], true);
    assert!(result["broker_confirmed"].is_null(), "broker_confirmed should be null when unreachable");
    // But there should be an error about not reaching the broker
    let errors = result["errors"].as_array().unwrap();
    assert!(errors.iter().any(|e| e.as_str().unwrap().contains("Could not reach broker")));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn human_output_shows_verified() {
    let secret = b"test-broker-secret";
    let payload_id = PayloadId::new_v4();
    let share_id = uuid::Uuid::new_v4();
    let receipt = make_receipt(secret, &payload_id, &share_id);

    let dir = std::env::temp_dir().join("clawback_test_human");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();

    // No --json flag
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "test-broker-secret",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VERIFIED"), "human output should contain VERIFIED");
    assert!(stdout.contains("HMAC verified"), "should show HMAC verified");
    assert!(output.status.success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn full_lifecycle_with_broker_module() {
    // Use the actual Broker module to create a real receipt, then verify it
    use clawback::crypto::PayloadId;

    let broker_secret = b"lifecycle-test-secret";
    let mut broker = clawback::broker::Broker::new(broker_secret);

    // Create sender and receiver with Umbral PRE
    let mut sender = clawback::sender::Sender::new();
    let receiver = clawback::receiver::Receiver::new();

    let result = sender.encrypt(b"Clawback lifecycle test data", &receiver.public_key).unwrap();
    let payload_id = result.payload_id;
    let share_id = result.share_id;

    // Register with broker
    let capsule_json = serde_json::to_string(&result.capsule).unwrap();
    let capsule_ct_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &*result.capsule_ciphertext,
    );
    let delegating_pk_json = serde_json::to_string(&sender.keys.public_key).unwrap();

    broker.register(
        payload_id, result.encrypted.ciphertext.clone(), result.encrypted.nonce,
        capsule_json, capsule_ct_b64, delegating_pk_json,
        sender.keys.signer.verifying_key(),
        share_id, result.kfrags, receiver.public_key.clone(),
    );

    // Revoke — get destruction receipt
    let receipt = broker.revoke(&payload_id, &share_id).unwrap();

    // Serialize receipt to JSON
    let receipt_json = serde_json::to_string_pretty(&receipt).unwrap();

    let dir = std::env::temp_dir().join("clawback_test_lifecycle");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, &receipt_json).unwrap();

    // Verify with clawback-verify
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clawback-verify"))
        .args([
            path.to_str().unwrap(),
            "--secret", "lifecycle-test-secret",
            "--json",
        ])
        .output()
        .expect("failed to run clawback-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Bad JSON output: {e}\nstdout: {stdout}"));

    assert_eq!(result["verdict"], "VERIFIED");
    assert_eq!(result["schema_valid"], true);
    assert_eq!(result["proof_valid"], true);
    assert_eq!(result["payload_id"], payload_id.to_string());
    assert_eq!(result["share_id"], share_id.to_string());
    assert!(output.status.success());

    // Also verify that post-revoke fetch is denied
    let fetch_result = broker.fetch_for_receiver(&payload_id, &share_id);
    assert!(fetch_result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}
