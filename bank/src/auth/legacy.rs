//! Compatibility layer for pre-2024 mobile clients.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::Mutex;

use super::{Claims, JwtKeys};

// ✅ Исправление 1: Используем lazy_static или обычную функцию
// Так как у нас нет lazy_static в зависимостях, используем Mutex::new с пустым HashSet
// и заполняем при первом использовании
static USED_NONCES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn get_used_nonces() -> std::sync::MutexGuard<'static, Option<HashSet<String>>> {
    let mut guard = USED_NONCES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashSet::new());
    }
    guard
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyClaims {
    sub: String,
    username: String,
    exp: usize,
    iat: usize,
    nonce: String,
    device_id: String,
}

pub(super) fn verify(
    token: &str,
    keys: &JwtKeys,
    device_fingerprint: Option<&str>,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let material = session_material(keys.public_pem());
    
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    validation.validate_exp = true;
    
    // ✅ Исправление 2: required_spec_claims ожидает HashSet
    let mut required = HashSet::new();
    required.insert("exp".to_string());
    required.insert("iat".to_string());
    required.insert("nonce".to_string());
    required.insert("device_id".to_string());
    validation.required_spec_claims = required;
    
    let dkey = DecodingKey::from_secret(&material);
    
    let token_data = match decode::<LegacyClaims>(token, &dkey, &validation) {
        Ok(data) => data,
        Err(e) => return Err(e),
    };
    
    let legacy_claims = token_data.claims;
    let now = chrono::Utc::now().timestamp() as usize;
    
    // TTL 5 минут
    if now.saturating_sub(legacy_claims.iat) > 300 {
        return Err(jsonwebtoken::errors::ErrorKind::ExpiredSignature.into());
    }
    
    // Replay protection
    let nonce_key = format!("{}:{}", legacy_claims.sub, legacy_claims.nonce);
    {
        let mut used = get_used_nonces();
        let used_set = used.as_mut().unwrap();
        if used_set.contains(&nonce_key) {
            return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
        }
        if used_set.len() > 100000 {
            used_set.clear();
        }
        used_set.insert(nonce_key);
    }
    
    // Device fingerprint binding
    if let Some(fp) = device_fingerprint {
        if fp != &legacy_claims.device_id {
            return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
        }
    }
    
    Ok(Claims {
        sub: legacy_claims.sub,
        username: legacy_claims.username,
        exp: legacy_claims.exp,
    })
}

fn session_material(public_params: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"nb-mobile/v1"), public_params);
    let mut out = [0u8; 32];
    hk.expand(b"session-material", &mut out).expect("hkdf expand");
    out
}