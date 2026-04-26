//! JWT issuance and verification.
//!
//! Tokens are signed with RS256 using an ephemeral server RSA keypair
//! generated on startup. For inbound tokens we also accept the legacy
//! mobile-SDK format — see [`legacy`] for the details. New clients
//! should only ever issue RS256.

mod legacy;

use actix_web::{HttpRequest, HttpResponse};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub exp: usize,
}

pub struct JwtKeys {
    rsa_private_pem: Vec<u8>,
    rsa_public_pem: Vec<u8>,
}

impl JwtKeys {
    pub fn new(rsa_private_pem: Vec<u8>, rsa_public_pem: Vec<u8>) -> Self {
        Self {
            rsa_private_pem,
            rsa_public_pem,
        }
    }

    pub fn public_pem(&self) -> &[u8] {
        &self.rsa_public_pem
    }

    pub(crate) fn private_pem(&self) -> &[u8] {
        &self.rsa_private_pem
    }
}

pub fn create_token(
    user_id: &str,
    username: &str,
    keys: &JwtKeys,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
    };
    let key = EncodingKey::from_rsa_pem(keys.private_pem())?;
    encode(&Header::new(Algorithm::RS256), &claims, &key)
}

/// Verify JWT token, supporting both RS256 (modern) and HS256 (legacy)
pub fn verify_token(
    token: &str,
    keys: &JwtKeys,
    device_fingerprint: Option<&str>,  // ← Required for legacy validation
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let header = decode_header(token)?;
    
    match header.alg {
        Algorithm::RS256 => {
            // Modern tokens use RS256
            let mut validation = Validation::new(Algorithm::RS256);
            validation.validate_exp = true;
            validation.leeway = 0;
            validation.insecure_disable_signature_validation = false;
            
            let dkey = DecodingKey::from_rsa_pem(keys.public_pem())?;
            let token_data = decode::<Claims>(token, &dkey, &validation)?;
            Ok(token_data.claims)
        }
        
        Algorithm::HS256 => {
            // Legacy tokens - delegate to legacy module with security checks
            log::debug!("Processing legacy HS256 token");
            legacy::verify(token, keys, device_fingerprint)
        }
        
        _ => {
            log::warn!("Rejected token with unsupported algorithm: {:?}", header.alg);
            Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into())
        }
    }
}

/// Pull the `Authorization: Bearer` token off the request and verify it.
pub fn require_claims(
    req: &HttpRequest,
    keys: &JwtKeys,
) -> Result<Claims, HttpResponse> {
    let auth = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            log::debug!("Missing or invalid Authorization header");
            HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Authentication required"}))
        })?;

    // Extract device fingerprint from headers for legacy token validation
    let device_fingerprint = req
        .headers()
        .get("X-Device-Fingerprint")
        .and_then(|v| v.to_str().ok());

    verify_token(auth, keys, device_fingerprint).map_err(|e| {
        log::debug!("Token verification failed: {:?}", e);
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"}))
    })
}

pub fn generate_rsa_keys() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode private");
    let public_pem = public_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("encode public");

    (
        private_pem.as_bytes().to_vec(),
        public_pem.as_bytes().to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rs256_token_works() {
        let (priv_pem, pub_pem) = generate_rsa_keys();
        let keys = JwtKeys::new(priv_pem, pub_pem);
        
        let token = create_token("123", "testuser", &keys).unwrap();
        let claims = verify_token(&token, &keys, None).unwrap();
        
        assert_eq!(claims.sub, "123");
        assert_eq!(claims.username, "testuser");
    }
    
    #[test]
    fn test_hs256_token_without_nonce_fails() {
        let (priv_pem, pub_pem) = generate_rsa_keys();
        let keys = JwtKeys::new(priv_pem, pub_pem);
        
        // Create HS256 token WITHOUT nonce (should fail)
        use jsonwebtoken::{Header, EncodingKey};
        
        let fake_claims = Claims {
            sub: "123".to_string(),
            username: "testuser".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
        };
        
        let hs256_token = encode(
            &Header::new(Algorithm::HS256),
            &fake_claims,
            &EncodingKey::from_secret(keys.public_pem()),
        ).unwrap();
        
        // Should fail because missing nonce and device_id
        assert!(verify_token(&hs256_token, &keys, None).is_err());
    }
}