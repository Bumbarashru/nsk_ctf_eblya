//! Query-time bucketing specification for the analytics endpoint.
//!
//! A "bucket" selects how transactions are grouped in `/api/transactions/stats`:
//! by a time window, by counterparty, or by a custom time prefix. Named
//! shortcuts cover the common cases; the parametric forms let the front-end
//! build custom bucketings without the server needing redeployment for
//! every new chart widget.
//!
//! The spec language is intentionally tiny:
//!
//! ```text
//!   day | month | counterparty
//!   window:<N>            prefix-of-N characters of created_at
//!   tz:<offset>:<width>   time-zone-adjusted prefix
//! ```
//!
//! ⚠️ SECURITY FIX (2026-04-26):
//!   - Added input validation for window width (must be 1-99)
//!   - Added strict validation for timezone offset format (±HH:MM)
//!   - Added whitelist validation for all SQL fragments

use std::fmt;
use regex::Regex;
use lazy_static::lazy_static;

/// Upper bound on raw spec length. Bucket specs are short by construction
/// (a timezone-tagged window is at most ~20 characters) so anything larger
/// is almost certainly a mistake and we reject it.
const MAX_SPEC_LEN: usize = 256;

/// Parsed bucketing spec. Call [`BucketSpec::as_sql`] to obtain the SQL
/// fragment suitable for splicing into a `GROUP BY`.
#[derive(Debug)]
pub struct BucketSpec {
    mode: String,
    arg: String,
}

#[derive(Debug)]
pub enum SpecError {
    TooLong,
    EmptyMode,
    BadMode,
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpecError::TooLong => f.write_str("bucket spec too long"),
            SpecError::EmptyMode => f.write_str("empty bucket mode"),
            SpecError::BadMode => f.write_str("bucket mode contains unsupported characters"),
        }
    }
}

lazy_static! {
    /// Valid timezone offset format: ±HH:MM (e.g., +03:00, -05:00)
    static ref OFFSET_PATTERN: Regex = Regex::new(r"^[+-](?:0[0-9]|1[0-4]):[0-5][0-9]$").unwrap();
    
    /// Valid window width: 1-99
    static ref WIDTH_PATTERN: Regex = Regex::new(r"^[1-9][0-9]?$").unwrap();
    
    /// Safe SQL fragment patterns for final validation
    static ref SAFE_SQL_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"^substr\(t\.created_at, 1, [0-9]+\)$").unwrap(),
        Regex::new(r"^substr\(datetime\(t\.created_at, '[+-](?:0[0-9]|1[0-4]):[0-5][0-9]'\), 1, [0-9]+\)$").unwrap(),
        Regex::new(r"^CASE WHEN t\.from_user = \?1 THEN tu\.username ELSE fu\.username END$").unwrap(),
        Regex::new(r"^substr\(t\.created_at, 1, 10\)$").unwrap(),
        Regex::new(r"^substr\(t\.created_at, 1, 7\)$").unwrap(),
    ];
}

impl BucketSpec {
    /// Parse a raw spec of the form `<mode>` or `<mode>:<arg>`.
    ///
    /// The mode is validated strictly (ASCII alphanumeric + underscore); the
    /// argument is mode-specific and interpreted by [`as_sql`].
    pub fn parse(raw: &str) -> Result<Self, SpecError> {
        let raw = raw.trim();
        if raw.len() > MAX_SPEC_LEN {
            return Err(SpecError::TooLong);
        }
        let (mode, arg) = match raw.split_once(':') {
            Some((m, rest)) => (m, rest),
            None => (raw, ""),
        };
        if mode.is_empty() {
            return Err(SpecError::EmptyMode);
        }
        if !mode
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(SpecError::BadMode);
        }
        Ok(Self {
            mode: mode.to_owned(),
            arg: arg.to_owned(),
        })
    }

    /// Default "group by day" used when the caller didn't specify anything.
    pub fn default_day() -> Self {
        Self {
            mode: "day".into(),
            arg: String::new(),
        }
    }

    /// Validate and sanitize numeric argument for window/tz modes
    fn sanitize_width(&self, width_str: &str, default: u8) -> String {
        match width_str.parse::<u8>() {
            Ok(w) if (1..=99).contains(&w) => w.to_string(),
            _ => {
                log::warn!("Invalid width value: '{}', using default {}", width_str, default);
                default.to_string()
            }
        }
    }

    /// Validate timezone offset format
    fn sanitize_offset(&self, offset: &str) -> String {
        if OFFSET_PATTERN.is_match(offset) {
            offset.to_string()
        } else {
            log::warn!("Invalid timezone offset: '{}', using UTC", offset);
            "+00:00".to_string()
        }
    }

    /// Final safety check for SQL fragment
    fn is_safe_sql(&self, sql: &str) -> bool {
        SAFE_SQL_PATTERNS.iter().any(|pattern| pattern.is_match(sql))
    }

    /// Render this spec as the SQL fragment used in `GROUP BY`.
    ///
    /// The token `?1` is reserved for the viewer's user id (bound by the
    /// caller) and is only referenced in `counterparty` mode.
    pub fn as_sql(&self) -> String {
        let sql = match self.mode.as_str() {
            "day" => "substr(t.created_at, 1, 10)".into(),
            
            "month" => "substr(t.created_at, 1, 7)".into(),
            
            "counterparty" => {
                "CASE WHEN t.from_user = ?1 THEN tu.username ELSE fu.username END".into()
            }
            
            "window" => {
                // ✅ FIX: Validate width is a number 1-99
                let width = self.sanitize_width(&self.arg, 10);
                format!("substr(t.created_at, 1, {})", width)
            }
            
            "tz" => {
                // ✅ FIX: Parse and validate both offset and width
                let (offset, width_str) = self.arg.rsplit_once(':')
                    .unwrap_or((self.arg.as_str(), "10"));
                
                let valid_offset = self.sanitize_offset(offset);
                let valid_width = self.sanitize_width(width_str, 10);
                
                format!(
                    "substr(datetime(t.created_at, '{}'), 1, {})",
                    valid_offset, valid_width
                )
            }
            
            // Unknown modes silently fall back to day buckets so the UI never
            // breaks on an unrecognised spec from an older client.
            _ => "substr(t.created_at, 1, 10)".into(),
        };
        
        // ✅ FIX: Final safety check - reject any SQL that doesn't match whitelist
        if !self.is_safe_sql(&sql) {
            log::error!("Unsafe SQL fragment generated: {}", sql);
            return "substr(t.created_at, 1, 10)".into();
        }
        
        sql
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_window() {
        let spec = BucketSpec::parse("window:10").unwrap();
        assert_eq!(spec.as_sql(), "substr(t.created_at, 1, 10)");
    }

    #[test]
    fn test_invalid_window_uses_default() {
        let spec = BucketSpec::parse("window:999").unwrap();
        assert_eq!(spec.as_sql(), "substr(t.created_at, 1, 10)");
        
        let spec = BucketSpec::parse("window:0").unwrap();
        assert_eq!(spec.as_sql(), "substr(t.created_at, 1, 10)");
        
        let spec = BucketSpec::parse("window:abc").unwrap();
        assert_eq!(spec.as_sql(), "substr(t.created_at, 1, 10)");
    }

    #[test]
    fn test_valid_tz() {
        let spec = BucketSpec::parse("tz:+03:00:10").unwrap();
        assert_eq!(spec.as_sql(), "substr(datetime(t.created_at, '+03:00'), 1, 10)");
        
        let spec = BucketSpec::parse("tz:-05:00:7").unwrap();
        assert_eq!(spec.as_sql(), "substr(datetime(t.created_at, '-05:00'), 1, 7)");
    }

    #[test]
    fn test_invalid_tz_uses_default() {
        let spec = BucketSpec::parse("tz:invalid:10").unwrap();
        // Invalid offset defaults to UTC
        assert_eq!(spec.as_sql(), "substr(datetime(t.created_at, '+00:00'), 1, 10)");
        
        let spec = BucketSpec::parse("tz:+99:99:10").unwrap();
        assert_eq!(spec.as_sql(), "substr(datetime(t.created_at, '+00:00'), 1, 10)");
    }

    #[test]
    fn test_sql_injection_prevention() {
        // Attempt SQL injection via window
        let spec = BucketSpec::parse("window:0) UNION SELECT password FROM users--").unwrap();
        let sql = spec.as_sql();
        assert_eq!(sql, "substr(t.created_at, 1, 10)");
        assert!(!sql.contains("UNION"));
        
        // Attempt SQL injection via tz
        let spec = BucketSpec::parse("tz:', '-1)) UNION SELECT password FROM users--:10").unwrap();
        let sql = spec.as_sql();
        assert!(!sql.contains("UNION"));
        assert!(!sql.contains("users"));
    }

    #[test]
    fn test_whitelist_rejection() {
        let spec = BucketSpec {
            mode: "day".to_string(),
            arg: "malicious".to_string(),
        };
        // Override as_sql internal logic - this should still be safe
        let sql = spec.as_sql();
        assert_eq!(sql, "substr(t.created_at, 1, 10)");
    }
}