// Clawback Protocol — Destruction Receipt Verifier CLI
//
// Standalone tool to independently verify that a payload was cryptographically
// destroyed per the Clawback Protocol.
//
// Usage:
//   clawback-verify receipt.json --secret <broker-secret>
//   cat receipt.json | clawback-verify - --secret <broker-secret>
//   clawback-verify receipt.json --secret <broker-secret> --broker-url http://localhost:8000
//   clawback-verify receipt.json --secret <broker-secret> --json

use std::process;

use clawback::crypto::generate_destruction_proof;
use serde::{Deserialize, Serialize};

// ── Receipt schema ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DestructionReceipt {
    payload_id: Option<String>,
    share_id: Option<String>,
    data_hash: Option<String>,
    revoked_at: Option<String>,
    destruction_proof: Option<String>,
    status: Option<String>,
}

// ── Verification result ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct VerificationResult {
    verdict: String,
    payload_id: String,
    share_id: String,
    revoked_at: String,
    schema_valid: bool,
    proof_valid: bool,
    broker_confirmed: Option<bool>,
    broker_status: Option<u16>,
    errors: Vec<String>,
}

// ── Schema validation ────────────────────────────────────────────────────────

struct ValidatedReceipt {
    payload_id: String,
    share_id: String,
    data_hash: String,
    revoked_at: String,
    destruction_proof: String,
}

fn validate_schema(receipt: &DestructionReceipt) -> Result<ValidatedReceipt, Vec<String>> {
    let mut errors = Vec::new();

    let payload_id = match &receipt.payload_id {
        Some(id) if !id.is_empty() => {
            if id.parse::<uuid::Uuid>().is_err() {
                errors.push(format!("payload_id is not a valid UUID: {id}"));
            }
            id.clone()
        }
        _ => { errors.push("missing required field: payload_id".into()); String::new() }
    };

    let share_id = match &receipt.share_id {
        Some(id) if !id.is_empty() => {
            if id.parse::<uuid::Uuid>().is_err() {
                errors.push(format!("share_id is not a valid UUID: {id}"));
            }
            id.clone()
        }
        _ => { errors.push("missing required field: share_id".into()); String::new() }
    };

    let data_hash = match &receipt.data_hash {
        Some(h) if !h.is_empty() => {
            if h.len() != 64 || hex::decode(h).is_err() {
                errors.push(format!("data_hash is not a valid SHA-256 hex string (expected 64 hex chars, got {})", h.len()));
            }
            h.clone()
        }
        _ => { errors.push("missing required field: data_hash".into()); String::new() }
    };

    let revoked_at = match &receipt.revoked_at {
        Some(ts) if !ts.is_empty() => {
            if chrono::DateTime::parse_from_rfc3339(ts).is_err() {
                errors.push(format!("revoked_at is not valid ISO-8601: {ts}"));
            }
            ts.clone()
        }
        _ => { errors.push("missing required field: revoked_at".into()); String::new() }
    };

    let destruction_proof = match &receipt.destruction_proof {
        Some(p) if !p.is_empty() => {
            if p.len() != 64 || hex::decode(p).is_err() {
                errors.push(format!("destruction_proof is not a valid HMAC-SHA256 hex string (expected 64 hex chars, got {})", p.len()));
            }
            p.clone()
        }
        _ => { errors.push("missing required field: destruction_proof".into()); String::new() }
    };

    match &receipt.status {
        Some(s) if s == "DESTROYED" => {}
        Some(s) => errors.push(format!("status must be \"DESTROYED\", got \"{s}\"")),
        None => errors.push("missing required field: status".into()),
    }

    if errors.is_empty() {
        Ok(ValidatedReceipt { payload_id, share_id, data_hash, revoked_at, destruction_proof })
    } else {
        Err(errors)
    }
}

// ── HMAC verification ────────────────────────────────────────────────────────

fn verify_proof(receipt: &ValidatedReceipt, broker_secret: &[u8]) -> bool {
    let payload_uuid: uuid::Uuid = receipt.payload_id.parse().unwrap();
    let expected = generate_destruction_proof(broker_secret, &payload_uuid, &receipt.revoked_at);
    expected == receipt.destruction_proof
}

// ── Broker liveness check ────────────────────────────────────────────────────

async fn check_broker(broker_url: &str, payload_id: &str, share_id: &str) -> (Option<bool>, Option<u16>) {
    let url = format!("{}/fetch/{}?share_id={}", broker_url.trim_end_matches('/'), payload_id, share_id);
    let client = reqwest::Client::new();
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            (Some(status == 403), Some(status))
        }
        Err(_) => (None, None)
    }
}

// ── CLI argument parsing (minimal, no extra deps) ────────────────────────────

struct Args {
    input: String,         // file path or "-" for stdin
    secret: String,
    broker_url: Option<String>,
    json_output: bool,
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        return Err(format!(
            "Usage: {} <receipt.json | -> --secret <broker-secret> [--broker-url <url>] [--json]\n\n\
             Verify a Clawback Protocol destruction receipt.\n\n\
             Arguments:\n  \
               <receipt.json>   Path to receipt JSON file, or \"-\" for stdin\n  \
               --secret <key>   Broker secret used to generate the HMAC proof\n  \
               --broker-url     Optional: verify live against a running broker\n  \
               --json           Output machine-readable JSON instead of human text",
            args[0]
        ));
    }

    let input = args[1].clone();
    let mut secret = None;
    let mut broker_url = None;
    let mut json_output = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--secret" => {
                i += 1;
                secret = Some(args.get(i).ok_or("--secret requires a value")?.clone());
            }
            "--broker-url" => {
                i += 1;
                broker_url = Some(args.get(i).ok_or("--broker-url requires a value")?.clone());
            }
            "--json" => { json_output = true; }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    let secret = secret.ok_or("--secret is required")?;
    Ok(Args { input, secret, broker_url, json_output })
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            process::exit(2);
        }
    };

    // Read receipt JSON
    let json_str = if args.input == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error reading stdin: {e}");
            process::exit(2);
        });
        buf
    } else {
        std::fs::read_to_string(&args.input).unwrap_or_else(|e| {
            eprintln!("Error reading {}: {e}", args.input);
            process::exit(2);
        })
    };

    // Parse JSON
    let receipt: DestructionReceipt = match serde_json::from_str(&json_str) {
        Ok(r) => r,
        Err(e) => {
            if args.json_output {
                let result = VerificationResult {
                    verdict: "INVALID".into(),
                    payload_id: String::new(),
                    share_id: String::new(),
                    revoked_at: String::new(),
                    schema_valid: false,
                    proof_valid: false,
                    broker_confirmed: None,
                    broker_status: None,
                    errors: vec![format!("Invalid JSON: {e}")],
                };
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                eprintln!("\u{274c} INVALID \u{2014} Cannot parse receipt JSON: {e}");
            }
            process::exit(1);
        }
    };

    // Validate schema
    let validated = match validate_schema(&receipt) {
        Ok(v) => v,
        Err(errors) => {
            if args.json_output {
                let result = VerificationResult {
                    verdict: "INVALID".into(),
                    payload_id: receipt.payload_id.unwrap_or_default(),
                    share_id: receipt.share_id.unwrap_or_default(),
                    revoked_at: receipt.revoked_at.unwrap_or_default(),
                    schema_valid: false,
                    proof_valid: false,
                    broker_confirmed: None,
                    broker_status: None,
                    errors,
                };
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                eprintln!("\u{274c} INVALID \u{2014} Receipt schema validation failed:");
                for err in &errors {
                    eprintln!("   \u{2022} {err}");
                }
            }
            process::exit(1);
        }
    };

    // Verify HMAC proof
    let proof_valid = verify_proof(&validated, args.secret.as_bytes());

    // Check broker if URL provided
    let (broker_confirmed, broker_status) = if let Some(ref url) = args.broker_url {
        check_broker(url, &validated.payload_id, &validated.share_id).await
    } else {
        (None, None)
    };

    // Determine verdict
    let mut errors = Vec::new();
    if !proof_valid {
        errors.push("HMAC destruction proof does not match. Receipt may be tampered.".into());
    }
    if let Some(false) = broker_confirmed {
        errors.push(format!(
            "Broker did not return 403 REVOKED (got HTTP {}). Payload may still be accessible.",
            broker_status.unwrap_or(0)
        ));
    }
    if broker_confirmed.is_none() && args.broker_url.is_some() {
        errors.push("Could not reach broker to confirm revocation.".into());
    }

    let verdict = if proof_valid && broker_confirmed != Some(false) {
        "VERIFIED"
    } else {
        "INVALID"
    };

    let result = VerificationResult {
        verdict: verdict.into(),
        payload_id: validated.payload_id.clone(),
        share_id: validated.share_id.clone(),
        revoked_at: validated.revoked_at.clone(),
        schema_valid: true,
        proof_valid,
        broker_confirmed,
        broker_status,
        errors: errors.clone(),
    };

    if args.json_output {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        let pid_short = if validated.payload_id.len() > 8 {
            &validated.payload_id[..8]
        } else {
            &validated.payload_id
        };

        if verdict == "VERIFIED" {
            println!();
            println!("\u{2705} VERIFIED \u{2014} Payload {pid_short}... was cryptographically destroyed at {}", validated.revoked_at);
            println!("   Proof: HMAC verified \u{2713}");
            if let Some(true) = broker_confirmed {
                println!("   Broker confirms: 403 REVOKED \u{2713}");
            } else if args.broker_url.is_none() {
                println!("   Broker: not checked (use --broker-url to verify live)");
            }
            println!();
        } else {
            println!();
            println!("\u{274c} INVALID \u{2014} Verification failed for payload {pid_short}...");
            for err in &errors {
                println!("   \u{2022} {err}");
            }
            println!();
        }
    }

    process::exit(if verdict == "VERIFIED" { 0 } else { 1 });
}
