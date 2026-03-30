// Clawback Protocol — Stress Tests (Umbral PRE)
//
// Exercises the protocol under load:
// 1. Crypto throughput (key gen, encrypt, decrypt, kfrag gen, reencrypt)
// 2. Broker throughput (register, fetch with re-encryption, revoke)
// 3. Full lifecycle at scale
// 4. Multi-share stress (many receivers per payload)
// 5. Revocation correctness
// 6. PRE-specific: threshold, receiver isolation

use clawback::broker::Broker;
use clawback::crypto::{
    generate_destruction_proof, hash_ciphertext, PayloadId, ShareId,
};
use clawback::receiver::Receiver;
use clawback::sender::Sender;
use umbral_pre::{self, SecretKey, Signer};
use std::time::Instant;

const BROKER_SECRET: &[u8] = b"stress-test-broker-secret";

fn report(label: &str, count: usize, elapsed: std::time::Duration) {
    let ops_per_sec = count as f64 / elapsed.as_secs_f64();
    let avg_us = elapsed.as_micros() as f64 / count as f64;
    println!(
        "  {:<50} {:>8} ops in {:>8.2?}  ({:>10.0} ops/s, {:>8.1} \u{00b5}s/op)",
        label, count, elapsed, ops_per_sec, avg_us
    );
}

/// Helper: register a SenderEncryptResult with the broker
fn register_result(
    broker: &mut Broker,
    result: &clawback::sender::SenderEncryptResult,
    sender: &Sender,
    receiver_pk: &umbral_pre::PublicKey,
) {
    let capsule_json = serde_json::to_string(&result.capsule).unwrap();
    let capsule_ct_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &*result.capsule_ciphertext,
    );
    let delegating_pk_json = serde_json::to_string(&sender.keys.public_key).unwrap();
    let verifying_pk = sender.keys.signer.verifying_key();

    broker.register(
        result.payload_id,
        result.encrypted.ciphertext.clone(),
        result.encrypted.nonce,
        capsule_json,
        capsule_ct_b64,
        delegating_pk_json,
        verifying_pk,
        result.share_id,
        result.kfrags.clone(),
        receiver_pk.clone(),
    );
}

/// Helper: register a new share with the broker
fn register_share(
    broker: &mut Broker,
    payload_id: &PayloadId,
    share_result: &clawback::sender::SenderShareResult,
    sender: &Sender,
    receiver_pk: &umbral_pre::PublicKey,
) {
    broker.add_share(
        payload_id,
        share_result.share_id,
        share_result.kfrags.clone(),
        receiver_pk.clone(),
    ).unwrap();
}

// ── 1. Crypto Throughput ─────────────────────────────────────────────────────

#[test]
fn stress_crypto_key_generation() {
    println!("\n=== Crypto: Key Generation (Umbral PRE) ===");
    let n = 5_000;

    let start = Instant::now();
    for _ in 0..n {
        let _sk = SecretKey::random();
    }
    report("SecretKey::random()", n, start.elapsed());

    let start = Instant::now();
    for _ in 0..n {
        let sk = SecretKey::random();
        let _pk = sk.public_key();
    }
    report("SecretKey + PublicKey derivation", n, start.elapsed());
}

#[test]
fn stress_crypto_encrypt_decrypt() {
    println!("\n=== Crypto: Encrypt/Decrypt Throughput (Umbral PRE) ===");

    let payloads: &[(&str, usize)] = &[
        ("64 B (token/key)", 64),
        ("1 KB (small doc)", 1_024),
        ("64 KB (image thumb)", 65_536),
    ];

    for &(label, size) in payloads {
        let plaintext = vec![0xABu8; size];
        let n = if size <= 1_024 { 2_000 } else { 200 };

        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        let start = Instant::now();
        for _ in 0..n {
            let _result = umbral_pre::encrypt(&delegating_pk, &plaintext).unwrap();
        }
        report(&format!("encrypt {}", label), n, start.elapsed());

        // Full PRE roundtrip: encrypt → kfrags → reencrypt → decrypt
        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();
        let signer = Signer::new(SecretKey::random());

        let (capsule, ciphertext) = umbral_pre::encrypt(&delegating_pk, &plaintext).unwrap();
        let kfrags = umbral_pre::generate_kfrags(
            &delegating_sk, &receiving_pk, &signer, 1, 1, true, true,
        );

        let start = Instant::now();
        for _ in 0..n {
            let cfrags: Vec<_> = kfrags.iter()
                .map(|vkf| umbral_pre::reencrypt(&capsule, vkf.clone()))
                .collect();
            let decrypted = umbral_pre::decrypt_reencrypted(
                &receiving_sk, &delegating_pk, &capsule, cfrags, &ciphertext,
            ).unwrap();
            assert_eq!(decrypted.len(), size);
        }
        report(&format!("reencrypt+decrypt {}", label), n, start.elapsed());
    }
}

#[test]
fn stress_crypto_kfrag_generation() {
    println!("\n=== Crypto: KFrag Generation ===");
    let n = 1_000;
    let delegating_sk = SecretKey::random();
    let signer = Signer::new(SecretKey::random());

    let start = Instant::now();
    for _ in 0..n {
        let receiving_pk = SecretKey::random().public_key();
        let _kfrags = umbral_pre::generate_kfrags(
            &delegating_sk, &receiving_pk, &signer, 1, 1, true, true,
        );
    }
    report("generate_kfrags (1-of-1)", n, start.elapsed());

    let start = Instant::now();
    for _ in 0..n {
        let receiving_pk = SecretKey::random().public_key();
        let _kfrags = umbral_pre::generate_kfrags(
            &delegating_sk, &receiving_pk, &signer, 3, 5, true, true,
        );
    }
    report("generate_kfrags (3-of-5 threshold)", n, start.elapsed());
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
    println!("\n=== Broker: Register + Fetch (with PRE re-encryption) ===");
    let n = 2_000;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut ids = Vec::with_capacity(n);

    let start = Instant::now();
    for _ in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let result = sender.encrypt(b"broker stress payload", &receiver.public_key).unwrap();
        register_result(&mut broker, &result, &sender, &receiver.public_key);
        ids.push((result.payload_id, result.share_id));
    }
    report("broker.register() [PRE]", n, start.elapsed());

    let start = Instant::now();
    for (pid, sid) in &ids {
        let result = broker.fetch_for_receiver(pid, sid);
        assert!(result.is_ok());
    }
    report("broker.fetch() [re-encryption]", n, start.elapsed());
}

#[test]
fn stress_broker_revoke() {
    println!("\n=== Broker: Revoke + Receipt Generation (PRE) ===");
    let n = 2_000;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut ids = Vec::with_capacity(n);

    for _ in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let result = sender.encrypt(b"revocation stress", &receiver.public_key).unwrap();
        register_result(&mut broker, &result, &sender, &receiver.public_key);
        ids.push((result.payload_id, result.share_id));
    }

    let start = Instant::now();
    for (pid, sid) in &ids {
        let receipt = broker.revoke(pid, sid).unwrap();
        assert_eq!(receipt.status, "DESTROYED");
    }
    report("broker.revoke() + receipt [kfrag destruction]", n, start.elapsed());

    let start = Instant::now();
    for (pid, sid) in &ids {
        let err = broker.fetch_for_receiver(pid, sid).unwrap_err();
        assert!(err.to_string().contains("REVOKED"));
    }
    report("post-revoke fetch \u{2192} REVOKED", n, start.elapsed());
}

// ── 3. Full Lifecycle Stress ─────────────────────────────────────────────────

#[test]
fn stress_full_lifecycle() {
    println!("\n=== Full PRE Lifecycle ===");
    let n = 1_000;
    let mut broker = Broker::new(BROKER_SECRET);

    struct Entry {
        payload_id: PayloadId,
        share_id: ShareId,
        plaintext: String,
        receiver: Receiver,
    }
    let mut entries = Vec::with_capacity(n);

    let start = Instant::now();
    for i in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let plaintext = format!("Sensitive document #{}", i);
        let result = sender.encrypt(plaintext.as_bytes(), &receiver.public_key).unwrap();
        register_result(&mut broker, &result, &sender, &receiver.public_key);
        entries.push(Entry {
            payload_id: result.payload_id,
            share_id: result.share_id,
            plaintext,
            receiver,
        });
    }
    report("encrypt + register [PRE]", n, start.elapsed());

    let start = Instant::now();
    for entry in &entries {
        let fetch = broker.fetch_for_receiver(&entry.payload_id, &entry.share_id).unwrap();
        let payload = clawback::EncryptedPayload { ciphertext: fetch.ciphertext, nonce: fetch.nonce };
        let decrypted = entry.receiver.decrypt_umbral(
            &fetch.delegating_pk, &fetch.capsule, fetch.cfrags, &fetch.capsule_ciphertext, &payload,
        ).unwrap();
        assert_eq!(decrypted, entry.plaintext.as_bytes());
    }
    report("fetch [re-encrypt] + decrypt + verify", n, start.elapsed());

    let start = Instant::now();
    for entry in &entries {
        let receipt = broker.revoke(&entry.payload_id, &entry.share_id).unwrap();
        assert_eq!(receipt.status, "DESTROYED");
    }
    report("revoke all [kfrag destruction]", n, start.elapsed());

    let start = Instant::now();
    for entry in &entries {
        assert!(broker.fetch_for_receiver(&entry.payload_id, &entry.share_id)
            .unwrap_err().to_string().contains("REVOKED"));
    }
    report("verify all REVOKED", n, start.elapsed());
}

// ── 4. Multi-Share ──────────────────────────────────────────────────────────

#[test]
fn stress_broker_multi_share() {
    println!("\n=== Broker: Multi-Share Per Payload ===");
    let shares_per_payload = 50;
    let num_payloads = 50;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut all_shares: Vec<(PayloadId, ShareId)> = Vec::new();

    let start = Instant::now();
    for _ in 0..num_payloads {
        let mut sender = Sender::new();
        let first_receiver = Receiver::new();
        let result = sender.encrypt(b"multi-share PRE", &first_receiver.public_key).unwrap();
        let pid = result.payload_id;
        register_result(&mut broker, &result, &sender, &first_receiver.public_key);
        all_shares.push((pid, result.share_id));

        for _ in 1..shares_per_payload {
            let new_receiver = Receiver::new();
            let share = sender.issue_share(&pid, &new_receiver.public_key).unwrap();
            register_share(&mut broker, &pid, &share, &sender, &new_receiver.public_key);
            all_shares.push((pid, share.share_id));
        }
    }
    let total = num_payloads * shares_per_payload;
    report(&format!("{} payloads \u{00d7} {} shares", num_payloads, shares_per_payload), total, start.elapsed());

    let start = Instant::now();
    for (pid, sid) in &all_shares {
        assert!(broker.fetch_for_receiver(pid, sid).is_ok());
    }
    report("fetch all shares [re-encryption]", total, start.elapsed());

    // Revoke every other share — verify isolation
    let mut revoked = 0;
    for (i, (pid, sid)) in all_shares.iter().enumerate() {
        if i % 2 == 0 {
            broker.revoke(pid, sid).unwrap();
            revoked += 1;
        }
    }

    for (i, (pid, sid)) in all_shares.iter().enumerate() {
        if i % 2 == 0 {
            assert!(broker.fetch_for_receiver(pid, sid).is_err());
        } else {
            assert!(broker.fetch_for_receiver(pid, sid).is_ok());
        }
    }
    println!("  Share isolation verified: {} revoked, {} active", revoked, total - revoked);
}

// ── 5. Receipt Integrity ────────────────────────────────────────────────────

#[test]
fn stress_receipt_integrity() {
    println!("\n=== Receipt Integrity Under Load ===");
    let n = 1_000;
    let mut broker = Broker::new(BROKER_SECRET);

    struct Entry { pid: PayloadId, sid: ShareId, expected_hash: String }
    let mut entries = Vec::with_capacity(n);

    for _ in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let result = sender.encrypt(b"receipt integrity test", &receiver.public_key).unwrap();
        let expected_hash = hash_ciphertext(&result.encrypted.ciphertext);
        register_result(&mut broker, &result, &sender, &receiver.public_key);
        entries.push(Entry { pid: result.payload_id, sid: result.share_id, expected_hash });
    }

    let start = Instant::now();
    for entry in &entries {
        let receipt = broker.revoke(&entry.pid, &entry.sid).unwrap();
        assert_eq!(receipt.data_hash, entry.expected_hash);
        assert_eq!(receipt.status, "DESTROYED");
        assert_eq!(receipt.destruction_proof.len(), 64);
        let recomputed = generate_destruction_proof(BROKER_SECRET, &entry.pid, &receipt.revoked_at);
        assert_eq!(receipt.destruction_proof, recomputed);
    }
    report("revoke + full receipt verification", n, start.elapsed());
}

// ── 6. PRE-Specific ─────────────────────────────────────────────────────────

#[test]
fn stress_pre_wrong_receiver_cannot_decrypt() {
    println!("\n=== PRE: Wrong Receiver Cannot Decrypt ===");
    let n = 200;
    let mut broker = Broker::new(BROKER_SECRET);

    for _ in 0..n {
        let mut sender = Sender::new();
        let intended = Receiver::new();
        let wrong = Receiver::new();

        let result = sender.encrypt(b"secret data", &intended.public_key).unwrap();
        register_result(&mut broker, &result, &sender, &intended.public_key);

        let fetch = broker.fetch_for_receiver(&result.payload_id, &result.share_id).unwrap();
        let payload = clawback::EncryptedPayload { ciphertext: fetch.ciphertext.clone(), nonce: fetch.nonce };

        // Intended CAN decrypt
        let decrypted = intended.decrypt_umbral(
            &fetch.delegating_pk, &fetch.capsule, fetch.cfrags.clone(), &fetch.capsule_ciphertext, &payload,
        ).unwrap();
        assert_eq!(&*decrypted, b"secret data");

        // Wrong CANNOT decrypt
        let wrong_result = wrong.decrypt_umbral(
            &fetch.delegating_pk, &fetch.capsule, fetch.cfrags, &fetch.capsule_ciphertext, &payload,
        );
        assert!(wrong_result.is_err());
    }
    println!("  All {} wrong-receiver decryption attempts rejected", n);
}

#[test]
fn stress_pre_selective_revocation() {
    println!("\n=== PRE: Selective Revocation ===");
    let n = 200;
    let mut broker = Broker::new(BROKER_SECRET);

    for _ in 0..n {
        let mut sender = Sender::new();
        let recv_a = Receiver::new();
        let recv_b = Receiver::new();

        let result = sender.encrypt(b"selective revoke", &recv_a.public_key).unwrap();
        let pid = result.payload_id;
        let sid_a = result.share_id;
        register_result(&mut broker, &result, &sender, &recv_a.public_key);

        let share_b = sender.issue_share(&pid, &recv_b.public_key).unwrap();
        let sid_b = share_b.share_id;
        register_share(&mut broker, &pid, &share_b, &sender, &recv_b.public_key);

        // Both can fetch
        assert!(broker.fetch_for_receiver(&pid, &sid_a).is_ok());
        assert!(broker.fetch_for_receiver(&pid, &sid_b).is_ok());

        // Revoke A
        broker.revoke(&pid, &sid_a).unwrap();

        // A locked out, B still active
        assert!(broker.fetch_for_receiver(&pid, &sid_a).is_err());
        assert!(broker.fetch_for_receiver(&pid, &sid_b).is_ok());
    }
    println!("  All {} selective revocation tests passed", n);
}

#[test]
fn stress_pre_threshold_reencryption() {
    println!("\n=== PRE: Threshold Re-encryption (3-of-5) ===");
    let n = 200;

    for _ in 0..n {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();
        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();
        let signer = Signer::new(SecretKey::random());

        let plaintext = b"threshold PRE test data";
        let (capsule, ciphertext) = umbral_pre::encrypt(&delegating_pk, plaintext).unwrap();

        let kfrags = umbral_pre::generate_kfrags(
            &delegating_sk, &receiving_pk, &signer, 3, 5, true, true,
        );
        assert_eq!(kfrags.len(), 5);

        // Any 3 of 5 should work
        let cfrags: Vec<_> = kfrags[0..3].iter()
            .map(|vkf| umbral_pre::reencrypt(&capsule, vkf.clone()))
            .collect();
        let decrypted = umbral_pre::decrypt_reencrypted(
            &receiving_sk, &delegating_pk, &capsule, cfrags, &ciphertext,
        ).unwrap();
        assert_eq!(&*decrypted, plaintext);

        // Different subset also works
        let cfrags2: Vec<_> = kfrags[2..5].iter()
            .map(|vkf| umbral_pre::reencrypt(&capsule, vkf.clone()))
            .collect();
        let decrypted2 = umbral_pre::decrypt_reencrypted(
            &receiving_sk, &delegating_pk, &capsule, cfrags2, &ciphertext,
        ).unwrap();
        assert_eq!(&*decrypted2, plaintext);
    }
    println!("  All {} threshold (3-of-5) tests passed", n);
}

#[test]
fn stress_double_revoke() {
    println!("\n=== Edge Case: Double Revoke ===");
    let n = 500;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut ids = Vec::with_capacity(n);

    for _ in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let result = sender.encrypt(b"double revoke", &receiver.public_key).unwrap();
        register_result(&mut broker, &result, &sender, &receiver.public_key);
        ids.push((result.payload_id, result.share_id));
    }

    for (pid, sid) in &ids {
        assert!(broker.revoke(pid, sid).is_ok());
    }

    for (pid, sid) in &ids {
        assert!(broker.revoke(pid, sid).is_err());
    }

    for (pid, sid) in &ids {
        assert!(broker.fetch_for_receiver(pid, sid).unwrap_err().to_string().contains("REVOKED"));
    }
    println!("  All {} double-revoke checks passed", n);
}
