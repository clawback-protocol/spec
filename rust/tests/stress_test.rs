// Clawback Protocol — Stress Tests (True Umbral PRE)
//
// Exercises the protocol under load:
// 1. Crypto throughput (key gen, encrypt, decrypt, kfrag gen, reencrypt)
// 2. Broker throughput (register, fetch with re-encryption, revoke)
// 3. Full lifecycle at scale (encrypt → kfrags → register → reencrypt → decrypt → revoke → denied)
// 4. Multi-share stress (many receivers per payload)
// 5. Revocation correctness (no re-encryption possible after kfrag destruction)
// 6. PRE-specific: delegate, re-encrypt, threshold, receiver isolation

use clawback::broker::Broker;
use clawback::crypto::{
    encrypt, decrypt_reencrypted, generate_kfrags, reencrypt,
    generate_destruction_proof, hash_ciphertext,
    SecretKey, Signer, PayloadId, ShareId, VerifiedCapsuleFrag,
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

    let start = Instant::now();
    for _ in 0..n {
        let sk = SecretKey::random();
        let _signer = Signer::new(sk);
    }
    report("SecretKey + Signer creation", n, start.elapsed());
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

        // Encrypt (sender encrypts to own key)
        let start = Instant::now();
        for _ in 0..n {
            let _result = encrypt(&delegating_pk, &plaintext).unwrap();
        }
        report(&format!("encrypt {}", label), n, start.elapsed());

        // Full PRE roundtrip: encrypt → kfrags → reencrypt → decrypt
        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();
        let signer = Signer::new(SecretKey::random());

        let (capsule, ciphertext) = encrypt(&delegating_pk, &plaintext).unwrap();
        let kfrags = generate_kfrags(
            &delegating_sk, &receiving_pk, &signer,
            1, 1, true, true,
        );

        let start = Instant::now();
        for _ in 0..n {
            let cfrags: Vec<VerifiedCapsuleFrag> = kfrags.iter()
                .map(|vkf| reencrypt(&capsule, vkf.clone()))
                .collect();
            let decrypted = decrypt_reencrypted(
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
        let _kfrags = generate_kfrags(
            &delegating_sk, &receiving_pk, &signer,
            1, 1, true, true,
        );
    }
    report("generate_kfrags (1-of-1)", n, start.elapsed());

    // Threshold kfrag generation (3-of-5)
    let start = Instant::now();
    for _ in 0..n {
        let receiving_pk = SecretKey::random().public_key();
        let _kfrags = generate_kfrags(
            &delegating_sk, &receiving_pk, &signer,
            3, 5, true, true,
        );
    }
    report("generate_kfrags (3-of-5 threshold)", n, start.elapsed());
}

#[test]
fn stress_crypto_reencryption() {
    println!("\n=== Crypto: Re-encryption Throughput ===");
    let n = 2_000;

    let delegating_sk = SecretKey::random();
    let delegating_pk = delegating_sk.public_key();
    let receiving_sk = SecretKey::random();
    let receiving_pk = receiving_sk.public_key();
    let signer = Signer::new(SecretKey::random());

    let (capsule, _ciphertext) = encrypt(&delegating_pk, b"reencryption benchmark").unwrap();
    let kfrags = generate_kfrags(
        &delegating_sk, &receiving_pk, &signer,
        1, 1, true, true,
    );

    let start = Instant::now();
    for _ in 0..n {
        let _cfrag = reencrypt(&capsule, kfrags[0].clone());
    }
    report("reencrypt (single kfrag)", n, start.elapsed());
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

    // Register payloads
    let start = Instant::now();
    for _ in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let result = sender.encrypt(b"broker stress payload", &receiver.public_key()).unwrap();
        let payload_id = result.payload_id;
        let share_id = result.share_id;
        broker.register(
            payload_id,
            result.ciphertext,
            result.capsule,
            result.delegating_pk,
            result.verifying_pk,
            share_id,
            result.kfrags,
            receiver.public_key(),
        );
        ids.push((payload_id, share_id, receiver));
    }
    report("broker.register() [PRE]", n, start.elapsed());

    // Fetch (broker performs re-encryption on each fetch)
    let start = Instant::now();
    for (pid, sid, _) in &ids {
        let result = broker.fetch(pid, sid);
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
        let result = sender.encrypt(b"revocation stress", &receiver.public_key()).unwrap();
        let pid = result.payload_id;
        let sid = result.share_id;
        broker.register(pid, result.ciphertext, result.capsule, result.delegating_pk,
            result.verifying_pk, sid, result.kfrags, receiver.public_key());
        ids.push((pid, sid));
    }

    let start = Instant::now();
    for (pid, sid) in &ids {
        let receipt = broker.revoke(pid, sid).unwrap();
        assert_eq!(receipt.status, "DESTROYED");
    }
    report("broker.revoke() + receipt [kfrag destruction]", n, start.elapsed());

    // Verify all fetches now fail (kfrags destroyed → no re-encryption)
    let start = Instant::now();
    for (pid, sid) in &ids {
        let err = broker.fetch(pid, sid).unwrap_err();
        assert!(err.to_string().contains("REVOKED"));
    }
    report("post-revoke fetch \u{2192} REVOKED", n, start.elapsed());
}

#[test]
fn stress_broker_multi_share() {
    println!("\n=== Broker: Multi-Share Per Payload (distinct receivers) ===");
    let shares_per_payload = 50;
    let num_payloads = 50;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut all_shares = Vec::new();

    let start = Instant::now();
    for _ in 0..num_payloads {
        let mut sender = Sender::new();
        let first_receiver = Receiver::new();
        let result = sender.encrypt(b"multi-share PRE stress", &first_receiver.public_key()).unwrap();
        let pid = result.payload_id;
        broker.register(pid, result.ciphertext, result.capsule, result.delegating_pk,
            result.verifying_pk, result.share_id, result.kfrags, first_receiver.public_key());
        all_shares.push((pid, result.share_id, first_receiver));

        // Each additional share targets a different receiver
        for _ in 1..shares_per_payload {
            let new_receiver = Receiver::new();
            let share_result = sender.issue_share(&pid, &new_receiver.public_key()).unwrap();
            broker.add_share(&pid, share_result.share_id, share_result.kfrags,
                new_receiver.public_key()).unwrap();
            all_shares.push((pid, share_result.share_id, new_receiver));
        }
    }
    let total = num_payloads * shares_per_payload;
    report(
        &format!("register {} payloads \u{00d7} {} shares", num_payloads, shares_per_payload),
        total,
        start.elapsed(),
    );

    // Fetch all shares (each involves re-encryption)
    let start = Instant::now();
    for (pid, sid, _) in &all_shares {
        assert!(broker.fetch(pid, sid).is_ok());
    }
    report("fetch all shares [re-encryption]", total, start.elapsed());

    // Revoke every other share — verify isolation
    let start = Instant::now();
    let mut revoked = 0;
    for (i, (pid, sid, _)) in all_shares.iter().enumerate() {
        if i % 2 == 0 {
            broker.revoke(pid, sid).unwrap();
            revoked += 1;
        }
    }
    report("revoke 50% of shares", revoked, start.elapsed());

    // Verify: revoked → error, active → ok
    for (i, (pid, sid, _)) in all_shares.iter().enumerate() {
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
    println!("\n=== Full PRE Lifecycle: Encrypt \u{2192} KFrags \u{2192} Register \u{2192} Re-encrypt \u{2192} Decrypt \u{2192} Revoke \u{2192} Denied ===");
    let n = 1_000;
    let mut broker = Broker::new(BROKER_SECRET);

    struct LifecycleEntry {
        payload_id: PayloadId,
        share_id: ShareId,
        plaintext: String,
        receiver: Receiver,
    }
    let mut entries = Vec::with_capacity(n);

    // Phase 1: Encrypt + register
    let start = Instant::now();
    for i in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let plaintext = format!("Sensitive document #{} — classified", i);

        let result = sender.encrypt(plaintext.as_bytes(), &receiver.public_key()).unwrap();
        broker.register(
            result.payload_id, result.ciphertext, result.capsule,
            result.delegating_pk, result.verifying_pk,
            result.share_id, result.kfrags, receiver.public_key(),
        );
        entries.push(LifecycleEntry {
            payload_id: result.payload_id,
            share_id: result.share_id,
            plaintext,
            receiver,
        });
    }
    report("encrypt + register [PRE]", n, start.elapsed());

    // Phase 2: Fetch (broker re-encrypts) + receiver decrypts
    let start = Instant::now();
    for entry in &entries {
        let fetch_result = broker.fetch(&entry.payload_id, &entry.share_id).unwrap();
        let decrypted = entry.receiver.decrypt(
            &fetch_result.delegating_pk,
            &fetch_result.capsule,
            fetch_result.cfrags,
            &fetch_result.ciphertext,
        ).unwrap();
        assert_eq!(decrypted, entry.plaintext.as_bytes());
    }
    report("fetch [re-encrypt] + decrypt + verify", n, start.elapsed());

    // Phase 3: Revoke all
    let start = Instant::now();
    for entry in &entries {
        let receipt = broker.revoke(&entry.payload_id, &entry.share_id).unwrap();
        assert_eq!(receipt.status, "DESTROYED");
    }
    report("revoke all [kfrag destruction]", n, start.elapsed());

    // Phase 4: Verify all access denied
    let start = Instant::now();
    for entry in &entries {
        assert!(broker.fetch(&entry.payload_id, &entry.share_id)
            .unwrap_err().to_string().contains("REVOKED"));
    }
    report("verify all REVOKED", n, start.elapsed());

    println!("  Full PRE lifecycle completed: {} payloads through entire protocol flow", n);
}

// ── 4. Destruction Receipt Integrity ─────────────────────────────────────────

#[test]
fn stress_receipt_integrity() {
    println!("\n=== Receipt Integrity Under Load (PRE) ===");
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
        let receiver = Receiver::new();
        let result = sender.encrypt(b"receipt integrity test", &receiver.public_key()).unwrap();
        let expected_hash = hash_ciphertext(&result.ciphertext);
        let pid = result.payload_id;
        let sid = result.share_id;
        broker.register(pid, result.ciphertext, result.capsule, result.delegating_pk,
            result.verifying_pk, sid, result.kfrags, receiver.public_key());
        entries.push(Entry { pid, sid, expected_hash });
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
    println!("\n=== Edge Case: Double Revoke (PRE) ===");
    let n = 500;
    let mut broker = Broker::new(BROKER_SECRET);
    let mut ids = Vec::with_capacity(n);

    for _ in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let result = sender.encrypt(b"double revoke test", &receiver.public_key()).unwrap();
        let pid = result.payload_id;
        let sid = result.share_id;
        broker.register(pid, result.ciphertext, result.capsule, result.delegating_pk,
            result.verifying_pk, sid, result.kfrags, receiver.public_key());
        ids.push((pid, sid));
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

// ── 6. PRE-Specific Tests ────────────────────────────────────────────────────

#[test]
fn stress_pre_delegate_reencrypt_revoke() {
    println!("\n=== PRE: Delegate \u{2192} Re-encrypt \u{2192} Revoke \u{2192} Verify Lockout ===");
    let n = 500;
    let mut broker = Broker::new(BROKER_SECRET);

    for i in 0..n {
        let mut sender = Sender::new();
        let receiver = Receiver::new();
        let plaintext = format!("PRE delegation test #{}", i);

        // Step 1: Sender encrypts + generates kfrags
        let result = sender.encrypt(plaintext.as_bytes(), &receiver.public_key()).unwrap();
        let pid = result.payload_id;
        let sid = result.share_id;

        broker.register(pid, result.ciphertext, result.capsule, result.delegating_pk,
            result.verifying_pk, sid, result.kfrags, receiver.public_key());

        // Step 2: Broker re-encrypts → receiver decrypts
        let fetch_result = broker.fetch(&pid, &sid).unwrap();
        let decrypted = receiver.decrypt(
            &fetch_result.delegating_pk, &fetch_result.capsule,
            fetch_result.cfrags, &fetch_result.ciphertext,
        ).unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());

        // Step 3: Revoke — kfrags destroyed
        let receipt = broker.revoke(&pid, &sid).unwrap();
        assert_eq!(receipt.status, "DESTROYED");

        // Step 4: Verify receiver permanently locked out
        assert!(broker.fetch(&pid, &sid).unwrap_err().to_string().contains("REVOKED"));
    }
    println!("  All {} delegate \u{2192} re-encrypt \u{2192} revoke \u{2192} lockout cycles passed", n);
}

#[test]
fn stress_pre_wrong_receiver_cannot_decrypt() {
    println!("\n=== PRE: Wrong Receiver Cannot Decrypt ===");
    let n = 200;
    let mut broker = Broker::new(BROKER_SECRET);

    for _ in 0..n {
        let mut sender = Sender::new();
        let intended_receiver = Receiver::new();
        let wrong_receiver = Receiver::new();

        let result = sender.encrypt(b"secret data", &intended_receiver.public_key()).unwrap();
        let pid = result.payload_id;
        let sid = result.share_id;

        broker.register(pid, result.ciphertext, result.capsule, result.delegating_pk,
            result.verifying_pk, sid, result.kfrags, intended_receiver.public_key());

        // Broker re-encrypts (targeted at intended_receiver)
        let fetch_result = broker.fetch(&pid, &sid).unwrap();

        // Intended receiver CAN decrypt
        let decrypted = intended_receiver.decrypt(
            &fetch_result.delegating_pk, &fetch_result.capsule,
            fetch_result.cfrags.clone(), &fetch_result.ciphertext,
        ).unwrap();
        assert_eq!(&*decrypted, b"secret data");

        // Wrong receiver CANNOT decrypt (cfrags are targeted at intended_receiver's key)
        let wrong_result = wrong_receiver.decrypt(
            &fetch_result.delegating_pk, &fetch_result.capsule,
            fetch_result.cfrags, &fetch_result.ciphertext,
        );
        assert!(wrong_result.is_err(), "wrong receiver should not be able to decrypt");
    }
    println!("  All {} wrong-receiver decryption attempts correctly rejected", n);
}

#[test]
fn stress_pre_selective_revocation() {
    println!("\n=== PRE: Selective Revocation (revoke one receiver, others unaffected) ===");
    let n = 200;
    let mut broker = Broker::new(BROKER_SECRET);

    for _ in 0..n {
        let mut sender = Sender::new();
        let receiver_a = Receiver::new();
        let receiver_b = Receiver::new();

        // Encrypt for receiver_a
        let result = sender.encrypt(b"selective revocation test", &receiver_a.public_key()).unwrap();
        let pid = result.payload_id;
        let sid_a = result.share_id;

        broker.register(pid, result.ciphertext, result.capsule, result.delegating_pk,
            result.verifying_pk, sid_a, result.kfrags, receiver_a.public_key());

        // Issue share for receiver_b
        let share_b = sender.issue_share(&pid, &receiver_b.public_key()).unwrap();
        let sid_b = share_b.share_id;
        broker.add_share(&pid, sid_b, share_b.kfrags, receiver_b.public_key()).unwrap();

        // Both can decrypt
        let fetch_a = broker.fetch(&pid, &sid_a).unwrap();
        assert!(receiver_a.decrypt(&fetch_a.delegating_pk, &fetch_a.capsule,
            fetch_a.cfrags, &fetch_a.ciphertext).is_ok());

        let fetch_b = broker.fetch(&pid, &sid_b).unwrap();
        assert!(receiver_b.decrypt(&fetch_b.delegating_pk, &fetch_b.capsule,
            fetch_b.cfrags, &fetch_b.ciphertext).is_ok());

        // Revoke receiver_a
        broker.revoke(&pid, &sid_a).unwrap();

        // receiver_a locked out
        assert!(broker.fetch(&pid, &sid_a).unwrap_err().to_string().contains("REVOKED"));

        // receiver_b still has access
        let fetch_b2 = broker.fetch(&pid, &sid_b).unwrap();
        assert!(receiver_b.decrypt(&fetch_b2.delegating_pk, &fetch_b2.capsule,
            fetch_b2.cfrags, &fetch_b2.ciphertext).is_ok());
    }
    println!("  All {} selective revocation tests passed (A revoked, B unaffected)", n);
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
        let (capsule, ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        // Generate 5 kfrags with threshold 3
        let kfrags = generate_kfrags(
            &delegating_sk, &receiving_pk, &signer,
            3, 5, true, true,
        );
        assert_eq!(kfrags.len(), 5);

        // Any 3 of 5 should suffice for decryption
        let cfrags: Vec<VerifiedCapsuleFrag> = kfrags[0..3].iter()
            .map(|vkf| reencrypt(&capsule, vkf.clone()))
            .collect();

        let decrypted = decrypt_reencrypted(
            &receiving_sk, &delegating_pk, &capsule, cfrags, &ciphertext,
        ).unwrap();
        assert_eq!(&*decrypted, plaintext);

        // Different subset of 3 also works
        let cfrags2: Vec<VerifiedCapsuleFrag> = kfrags[2..5].iter()
            .map(|vkf| reencrypt(&capsule, vkf.clone()))
            .collect();

        let decrypted2 = decrypt_reencrypted(
            &receiving_sk, &delegating_pk, &capsule, cfrags2, &ciphertext,
        ).unwrap();
        assert_eq!(&*decrypted2, plaintext);
    }
    println!("  All {} threshold (3-of-5) re-encryption tests passed", n);
}
