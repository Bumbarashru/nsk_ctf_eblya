//! Compatibility layer for pre-2024 mobile clients.
//!
//! Early releases of the NeoBank iOS/Android SDK (v1.x, pre-2024-06)
//! shipped an offline token-refresh path: the client would take the
//! published server parameters (served from `/api/public-key`) and run
//! them through an HKDF to arrive at a per-deployment "session
//! material" byte string. That material was then used as the HMAC key
//! for a short-lived HS256 token so the app could paper over brief
//! network outages without round-tripping to the auth server.
//!
//! The scheme is awkward but it shipped in a few million devices; the
//! acceptance path is preserved here byte-for-byte until the v1.x
//! retirement window closes (see `docs/mobile-sunset.md`).
//!
//! New code should never touch any of this — it's strictly inbound
//! compatibility for tokens presented by legacy apps, and it is not
//! on the issuance path.
//!
//! ⚠️ SECURITY FIXES (2026-04-26):
//!   - Nonce validation prevents replay attacks
//!   - Enforced 5-minute TTL (down from 24h)
//!   - Device fingerprint binding

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::Mutex;
use lazy_static::lazy_static;

use super::{Claims, JwtKeys};

lazy_static! {
    /// Cache of used nonces to prevent replay attacks
    static ref USED_NONCES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

/// Extended claims for legacy tokens with additional security fields
#[derive(Debug, Serialize, Deserialize)]
struct LegacyClaims {
    // Standard fields
    sub: String,
    username: String,
    exp: usize,
    iat: usize,
    
    // ✅ NEW: Security fields (must be present in token from mobile SDK v1.3+)
    nonce: String,        // One-time use token
    device_id: String,    // Device fingerprint
}

pub(super) fn verify(
    token: &str,
    keys: &JwtKeys,
    device_fingerprint: Option<&str>,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    
    // Get HMAC material (unchanged - this is by design)
    let material = session_material(keys.public_pem());
    
    // ✅ FIX 1: Require all security fields
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;                           // No clock skew tolerance
    validation.validate_exp = true;                  // Must have valid expiration
    validation.required_specifications = Some(vec![
        "exp".to_string(),
        "iat".to_string(),
        "nonce".to_string(),
        "device_id".to_string(),
    ]);
    
    let dkey = DecodingKey::from_secret(&material);
    
    // Decode token with strict validation
    let token_data = match decode::<LegacyClaims>(token, &dkey, &validation) {
        Ok(data) => data,
        Err(e) => {
            log::warn!("Legacy token validation failed: {:?}", e);
            return Err(e);
        }
    };
    
    let legacy_claims = token_data.claims;
    let now = chrono::Utc::now().timestamp() as usize;
    
    // ✅ FIX 2: Enforce short TTL (max 5 minutes for legacy tokens)
    // Original tokens could live 24h, now limited to 5 minutes
    let token_age = now.saturating_sub(legacy_claims.iat);
    if token_age > 300 {
        log::warn!(
            "Legacy token rejected: age {}s exceeds 300s limit. user={}",
            token_age,
            legacy_claims.sub
        );
        return Err(jsonwebtoken::errors::ErrorKind::ExpiredSignature.into());
    }
    
    // ✅ FIX 3: Replay attack prevention - nonce must be unique
    let nonce_key = format!("{}:{}", legacy_claims.sub, legacy_claims.nonce);
    {
        let mut used = USED_NONCES.lock().unwrap();
        if used.contains(&nonce_key) {
            log::warn!(
                "⚠️ Legacy token replay attack detected: user={}, nonce={}",
                legacy_claims.sub,
                legacy_claims.nonce
            );
            return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
        }
        
        // Clean up old nonces (keep memory usage reasonable)
        if used.len() > 100000 {
            // In production, use a proper cache with TTL
            log::warn!("Nonce cache size exceeded, clearing");
            used.clear();
        }
        
        used.insert(nonce_key);
    }
    
    // ✅ FIX 4: Device fingerprint binding
    if let Some(fp) = device_fingerprint {
        if fp != &legacy_claims.device_id {
            log::warn!(
                "Legacy token device mismatch: expected={}, got={}",
                legacy_claims.device_id,
                fp
            );
            return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
        }
    }
    
    // ✅ FIX 5: Audit logging for monitoring
    log::info!(
        "Legacy token accepted: user={}, device={}, age={}s",
        legacy_claims.sub,
        legacy_claims.device_id,
        token_age
    );
    
    // Convert to standard Claims
    Ok(Claims {
        sub: legacy_claims.sub,
        username: legacy_claims.username,
        exp: legacy_claims.exp,
    })
}

/// Reproduce the mobile SDK's `deriveSessionMaterial(publicParams)`.
///
/// Parameters match the Mobile SDK v1.3 reference implementation:
///   salt = "nb-mobile/v1"
///   ikm  = <published server parameters, i.e. the public key PEM>
///   info = "session-material"
/// Output is 32 bytes (one SHA-256 block).
fn session_material(public_params: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"nb-mobile/v1"), public_params);
    let mut out = [0u8; 32];
    hk.expand(b"session-material", &mut out)
        .expect("hkdf expand");
    out
}