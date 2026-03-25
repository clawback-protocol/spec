// Clawback Protocol — Stress Tests (Simulated PRE)
//
// Exercises the protocol under load:
// 1. Crypto throughput (key gen, encrypt, decrypt, HKDF derivation)
// 2. Broker throughput (register, fetch, revoke)
// 3. Full lifecycle at scale (encrypt → register → fetch → decrypt → revoke → denied)
// 4. Multi-share stress (many shares per payload)
// 5. Revocation correctness (no access after key destruction)
// 6. Edge cases (double revoke, nonexistent lookups)

use clawback::broker::Broker;
use clawback::crypto::{
    MasterKey, EncryptedPayload,
    generate_destruction_proof, hash_ciphertext,
    PayloadId, ShareId,
};
use clawback::receiver::Receiver;
use clawback::sender::Sender;
use std::time::Instant;

const BROKER_SECRET: &[u8] = b"stress-test-broker-secret";

// ── Helpers ──────────────────────────────────────────────────────────────────

fn report(label: &str, count: usize, elapsed: std::time::Duration) {
    let ops_per_sec = count as f64 / elapsed.as_secs_f64();
    let avg_us = elapsed.as_micros() as f64 / count as f64;
    println!(
        "  {:<50} {:>8} ops in {:>8.2?}  ({:>10.0} ops/s, {:>8.1} \u{00b5}s/op)",
        label, count, elapsed, ops_per_sec, avg_us
    );
}

// ── 1. Crypto Throughput ─────────────────────────────────────────────────────

#[test]
fn stress_crypto_key_generation() {
    println!("\n=== Crypto: Key Generation (Simulated PRE) ===");
    let n = 5_000;

    let start = Instant::now();
    for _ in 0..n {
        let _master = MasterKey::generate();
    }
    report("MasterKey::generate()", n, start.elapsed());

    let start = Instant::now();
    for _ in 0..n {
        let master = MasterKey::generate();
        let _enc_key = master.derive_enc_key();
    }
    report("MasterKey + derive_enc_key (HKDF)", n, start.elapsed());
}

#[test]
fn stress_crypto_encrypt_decrypt() {
    println!("\n=== Crypto: Encrypt/Decrypt Throughput (Simulated PRE) ===");

    let payloads: &[(&str, usize)] = &[
        ("64 B (token/key)", 64),
        ("1 KB (small doc)", 1_024),
        ("64 KB (image thumb)", 65_536),
    ];

    for &(label, size) in payloads {
        let plaintext = vec![0xABu8; size];
        let n = if size <= 1_024 { 2_000 } else { 200 };

        let master = MasterKey::generate();
        let enc_key = master.derive_enc_key();

        // Encrypt
        let start = Instant::now();
        for _ in 0..n {
            let _encrypted = enc_key.encrypt(&plaintext).unwrap();
        }
        report(&format!("encrypt {}", label), n, start.elapsed());

        // Encrypt + decrypt roundtrip
        let encrypted = enc_key.encrypt(&plaintext).unwrap();
        let share_key = clawback::crypto::ShareKey::from_bytes(enc_key.as_bytes()).unwrap();

        let start = Instant::now();
        for _ in 0..n {
            let decrypted = share_key.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted.len(), size);
        }
        report(&format!("decrypt {}", label), n, start.elapsed());
    }
}

#[test]
fn stress_crypto_blob_roundtrip() {
    println!("\n=== Crypto: Blob Serialization Roundtrip ===");
    let n = 5_000;

    let master = MasterKey::generate();
    let enc_key = master.derive_enc_key();
    let encrypted = enc_key.encrypt(b"blob roundtrip benchmark").unwrap();

    let start = Instant::now();
    for _ in 0..n {
        let blob = encrypted.to_blob();
        let restored = EncryptedPayload::from_blob(&blob).unwrap();
        assert_eq!(restored.nonce, encrypted.nonce);
    }
    report("to_blob + from_blob", n, start.elapsed());
}

#[test]
fn stress_crypto_destruction_proofs() {
    println!("\n=== Crypto: Destruction Proof Generation ===");
    let n = 10_000;
    let payload_id = PayloadId::new_v4();
    let timestamp = "2026-03-17T00:00:00Z";

    let start = Instant::now();
    for _ in 0..n {
        let proof = generate_destruction_proof(BROKER_SECRET, &payload_id, timestamp);
        assert_eq!(proof.len(), 64);
    }
    report("HMAC-SHA256 destruction proof", n, start.elapsed());

    let start = Instant::now();
    let data = vec![0u8; 65_536];
    for _ in 0..n {
        let hash = hash_ciphertext(&data);
        assert_eq!(hash.len(), 64);
    }
    report("SHA-256 hash (64 KB)", n, start.elapsed());
}

// ── 2. Broker Throughput ─────────────────────────────────────────────────────

#[test]
fn stress_broker_register_and_fetch() {
    println!("\n=== Broker: Register + Fetch ===");
    let n = 2_000;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut ids = Vec::with_capacity(n);

    // Register payloads
    let start = Instant::now();
    for _ in 0..n {
        let mut sender = Sender::new();
        let (payload_id, share_id, encrypted, share_key_bytes) =
            sender.encrypt(b"broker stress payload").unwrap();
        broker.register(
            payload_id,
            encrypted.ciphertext,
            encrypted.nonce,
            share_id,
            share_key_bytes.clone(),
        );
        ids.push((payload_id, share_id));
    }
    report("broker.register()", n, start.elapsed());

    // Fetch
    let start = Instant::now();
    for (pid, sid) in &ids {
        let result = broker.fetch(pid, sid);
        assert!(result.is_ok());
    }
    report("broker.fetch()", n, start.elapsed());
}

#[test]
fn stress_broker_revoke() {
    println!("\n=== Broker: Revoke + Receipt Generation ===");
    let n = 2_000;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut ids = Vec::with_capacity(n);

    for _ in 0..n {
        let mut sender = Sender::new();
        let (payload_id, share_id, encrypted, share_key_bytes) =
            sender.encrypt(b"revocation stress").unwrap();
        broker.register(payload_id, encrypted.ciphertext, encrypted.nonce,
            share_id, share_key_bytes);
        ids.push((payload_id, share_id));
    }

    let start = Instant::now();
    for (pid, sid) in &ids {
        let receipt = broker.revoke(pid, sid).unwrap();
        assert_eq!(receipt.status, "DESTROYED");
    }
    report("broker.revoke() + receipt [key destruction]", n, start.elapsed());

    // Verify all fetches now fail
    let start = Instant::now();
    for (pid, sid) in &ids {
        let err = broker.fetch(pid, sid).unwrap_err();
        assert!(err.to_string().contains("REVOKED"));
    }
    report("post-revoke fetch \u{2192} REVOKED", n, start.elapsed());
}

#[test]
fn stress_broker_multi_share() {
    println!("\n=== Broker: Multi-Share Per Payload ===");
    let shares_per_payload = 50;
    let num_payloads = 50;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut all_shares = Vec::new();

    let start = Instant::now();
    for _ in 0..num_payloads {
        let mut sender = Sender::new();
        let (payload_id, share_id, encrypted, share_key_bytes) =
            sender.encrypt(b"multi-share stress").unwrap();
        broker.register(payload_id, encrypted.ciphertext, encrypted.nonce,
            share_id, share_key_bytes);
        all_shares.push((payload_id, share_id));

        // Each additional share uses issue_share
        for _ in 1..shares_per_payload {
            let (new_share_id, new_share_key) = sender.issue_share(&payload_id).unwrap();
            broker.add_share(&payload_id, new_share_id, new_share_key).unwrap();
            all_shares.push((payload_id, new_share_id));
        }
    }
    let total = num_payloads * shares_per_payload;
    report(
        &format!("register {} payloads \u{00d7} {} shares", num_payloads, shares_per_payload),
        total,
        start.elapsed(),
    );

    // Fetch all shares
    let start = Instant::now();
    for (pid, sid) in &all_shares {
        assert!(broker.fetch(pid, sid).is_ok());
    }
    report("fetch all shares", total, start.elapsed());

    // Revoke every other share — verify isolation
    let start = Instant::now();
    let mut revoked = 0;
    for (i, (pid, sid)) in all_shares.iter().enumerate() {
        if i % 2 == 0 {
            broker.revoke(pid, sid).unwrap();
            revoked += 1;
        }
    }
    report("revoke 50% of shares", revoked, start.elapsed());

    // Verify: revoked → error, active → ok
    for (i, (pid, sid)) in all_shares.iter().enumerate() {
        if i % 2 == 0 {
            assert!(broker.fetch(pid, sid).is_err(), "revoked share should fail");
        } else {
            assert!(broker.fetch(pid, sid).is_ok(), "active share should succeed");
        }
    }
    println!("  Share isolation verified: {} revoked, {} still active", revoked, total - revoked);
}

// ── 3. Full Lifecycle Stress ─────────────────────────────────────────────────

#[test]
fn stress_full_lifecycle() {
    println!("\n=== Full Lifecycle: Encrypt \u{2192} Register \u{2192} Fetch \u{2192} Decrypt \u{2192} Revoke \u{2192} Denied ===");
    let n = 1_000;
    let mut broker = Broker::new(BROKER_SECRET);

    struct LifecycleEntry {
        payload_id: PayloadId,
        share_id: ShareId,
        plaintext: String,
    }
    let mut entries = Vec::with_capacity(n);

    // Phase 1: Encrypt + register
    let start = Instant::now();
    for i in 0..n {
        let mut sender = Sender::new();
        let plaintext = format!("Sensitive document #{} — classified", i);

        let (payload_id, share_id, encrypted, share_key_bytes) =
            sender.encrypt(plaintext.as_bytes()).unwrap();
        broker.register(
            payload_id, encrypted.ciphertext, encrypted.nonce,
            share_id, share_key_bytes,
        );
        entries.push(LifecycleEntry {
            payload_id,
            share_id,
            plaintext,
        });
    }
    report("encrypt + register", n, start.elapsed());

    // Phase 2: Fetch + decrypt
    let start = Instant::now();
    for entry in &entries {
        let (ciphertext, nonce, share_key) = broker.fetch(&entry.payload_id, &entry.share_id).unwrap();
        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(ciphertext);
        let payload = EncryptedPayload::from_blob(&blob).unwrap();
        let decrypted = Receiver::decrypt(share_key, &payload).unwrap();
        assert_eq!(decrypted, entry.plaintext.as_bytes());
    }
    report("fetch + decrypt + verify", n, start.elapsed());

    // Phase 3: Revoke all
    let start = Instant::now();
    for entry in &entries {
        let receipt = broker.revoke(&entry.payload_id, &entry.share_id).unwrap();
        assert_eq!(receipt.status, "DESTROYED");
    }
    report("revoke all [key destruction]", n, start.elapsed());

    // Phase 4: Verify all access denied
    let start = Instant::now();
    for entry in &entries {
        assert!(broker.fetch(&entry.payload_id, &entry.share_id)
            .unwrap_err().to_string().contains("REVOKED"));
    }
    report("verify all REVOKED", n, start.elapsed());

    println!("  Full lifecycle completed: {} payloads through entire protocol flow", n);
}

// ── 4. Destruction Receipt Integrity ─────────────────────────────────────────

#[test]
fn stress_receipt_integrity() {
    println!("\n=== Receipt Integrity Under Load ===");
    let n = 1_000;
    let mut broker = Broker::new(BROKER_SECRET);

    struct Entry {
        pid: PayloadId,
        sid: ShareId,
        expected_hash: String,
    }
    let mut entries = Vec::with_capacity(n);

    for _ in 0..n {
        let mut sender = Sender::new();
        let (payload_id, share_id, encrypted, share_key_bytes) =
            sender.encrypt(b"receipt integrity test").unwrap();
        let expected_hash = hash_ciphertext(&encrypted.ciphertext);
        broker.register(payload_id, encrypted.ciphertext, encrypted.nonce,
            share_id, share_key_bytes);
        entries.push(Entry { pid: payload_id, sid: share_id, expected_hash });
    }

    let start = Instant::now();
    for entry in &entries {
        let receipt = broker.revoke(&entry.pid, &entry.sid).unwrap();
        assert_eq!(receipt.payload_id, entry.pid.to_string());
        assert_eq!(receipt.share_id, entry.sid.to_string());
        assert_eq!(receipt.data_hash, entry.expected_hash);
        assert_eq!(receipt.status, "DESTROYED");
        assert_eq!(receipt.destruction_proof.len(), 64);
        assert!(!receipt.revoked_at.is_empty());

        let recomputed = generate_destruction_proof(BROKER_SECRET, &entry.pid, &receipt.revoked_at);
        assert_eq!(receipt.destruction_proof, recomputed);
    }
    report("revoke + full receipt verification", n, start.elapsed());

    for entry in entries.iter().take(100) {
        let receipts = broker.get_receipts(&entry.pid);
        assert_eq!(receipts.len(), 1);
    }
    println!("  All {} receipts verified for integrity and determinism", n);
}

// ── 5. Edge Cases Under Load ─────────────────────────────────────────────────

#[test]
fn stress_double_revoke() {
    println!("\n=== Edge Case: Double Revoke ===");
    let n = 500;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut ids = Vec::with_capacity(n);

    for _ in 0..n {
        let mut sender = Sender::new();
        let (payload_id, share_id, encrypted, share_key_bytes) =
            sender.encrypt(b"double revoke test").unwrap();
        broker.register(payload_id, encrypted.ciphertext, encrypted.nonce,
            share_id, share_key_bytes);
        ids.push((payload_id, share_id));
    }

    for (pid, sid) in &ids {
        assert!(broker.revoke(pid, sid).is_ok());
    }

    let mut errors = 0;
    let mut successes = 0;
    for (pid, sid) in &ids {
        match broker.revoke(pid, sid) {
            Ok(_) => successes += 1,
            Err(_) => errors += 1,
        }
    }
    println!("  Double revoke: {} succeeded again, {} errored (both acceptable)", successes, errors);

    for (pid, sid) in &ids {
        assert!(broker.fetch(pid, sid).unwrap_err().to_string().contains("REVOKED"));
    }
    println!("  All {} shares confirmed REVOKED after double-revoke", n);
}

#[test]
fn stress_nonexistent_lookups() {
    println!("\n=== Edge Case: Nonexistent Payload/Share Lookups ===");
    let n = 10_000;
    let broker = Broker::new(BROKER_SECRET);

    let start = Instant::now();
    for _ in 0..n {
        let fake_pid = PayloadId::new_v4();
        let fake_sid = ShareId::new_v4();
        assert!(broker.fetch(&fake_pid, &fake_sid).is_err());
    }
    report("fetch nonexistent", n, start.elapsed());
    println!("  All {} bogus lookups correctly rejected", n);
}

// ── 6. Selective Revocation ──────────────────────────────────────────────────

#[test]
fn stress_selective_revocation() {
    println!("\n=== Selective Revocation (revoke one share, others unaffected) ===");
    let n = 200;
    let mut broker = Broker::new(BROKER_SECRET);

    for _ in 0..n {
        let mut sender = Sender::new();
        let (payload_id, share_id_a, encrypted, share_key_a) =
            sender.encrypt(b"selective revocation test").unwrap();
        broker.register(payload_id, encrypted.ciphertext, encrypted.nonce,
            share_id_a, share_key_a);

        // Issue second share
        let (share_id_b, share_key_b) = sender.issue_share(&payload_id).unwrap();
        broker.add_share(&payload_id, share_id_b, share_key_b).unwrap();

        // Both can fetch
        assert!(broker.fetch(&payload_id, &share_id_a).is_ok());
        assert!(broker.fetch(&payload_id, &share_id_b).is_ok());

        // Revoke share A
        broker.revoke(&payload_id, &share_id_a).unwrap();

        // A locked out, B still has access
        assert!(broker.fetch(&payload_id, &share_id_a).unwrap_err().to_string().contains("REVOKED"));
        assert!(broker.fetch(&payload_id, &share_id_b).is_ok());
    }
    println!("  All {} selective revocation tests passed (A revoked, B unaffected)", n);
}

// ── 7. Wrong Key Cannot Decrypt ──────────────────────────────────────────────

#[test]
fn stress_wrong_key_cannot_decrypt() {
    println!("\n=== Wrong Key Cannot Decrypt ===");
    let n = 200;

    for _ in 0..n {
        let mut sender = Sender::new();
        let (_payload_id, _share_id, encrypted, _share_key) =
            sender.encrypt(b"secret data").unwrap();

        // A different sender's key should NOT decrypt this payload
        let mut wrong_sender = Sender::new();
        let (_wp, _ws, _we, wrong_key) = wrong_sender.encrypt(b"other data").unwrap();

        let payload = EncryptedPayload::from_blob(&encrypted.to_blob()).unwrap();
        let result = Receiver::decrypt(&wrong_key, &payload);
        assert!(result.is_err(), "wrong key should not be able to decrypt");
    }
    println!("  All {} wrong-key decryption attempts correctly rejected", n);
}
