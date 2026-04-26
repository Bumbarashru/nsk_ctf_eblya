use std::fmt;

use log::warn;

const MAX_SPEC_LEN: usize = 256;

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

impl BucketSpec {
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
        if !mode.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(SpecError::BadMode);
        }
        Ok(Self {
            mode: mode.to_owned(),
            arg: arg.to_owned(),
        })
    }

    pub fn default_day() -> Self {
        Self {
            mode: "day".into(),
            arg: String::new(),
        }
    }

    fn validate_width(&self, width_str: &str) -> String {
        match width_str.parse::<u8>() {
            Ok(w) if (1..=99).contains(&w) => w.to_string(),
            _ => "10".to_string(),
        }
    }

    fn validate_offset(&self, offset: &str) -> String {
        if offset.len() == 6 {
            let chars: Vec<char> = offset.chars().collect();
            if (chars[0] == '+' || chars[0] == '-')
                && chars[1].is_ascii_digit()
                && chars[2].is_ascii_digit()
                && chars[3] == ':'
                && chars[4].is_ascii_digit()
                && chars[5].is_ascii_digit()
            {
                let hours = format!("{}{}", chars[1], chars[2]).parse::<u8>().unwrap_or(99);
                if hours <= 14 {
                    return offset.to_string();
                }
            }
        }
        "+00:00".to_string()
    }

    pub fn as_sql(&self) -> String {
        match self.mode.as_str() {
            "day" => "substr(t.created_at, 1, 10)".into(),
            "month" => "substr(t.created_at, 1, 7)".into(),
            "counterparty" => {
                "CASE WHEN t.from_user = ?1 THEN tu.username ELSE fu.username END".into()
            }
            "window" => {
                format!("substr(t.created_at, 1, {})", self.validate_width(&self.arg))
            }
            "tz" => {
                let (offset, width_str) = self
                    .arg
                    .rsplit_once(':')
                    .unwrap_or((self.arg.as_str(), "10"));
                format!(
                    "substr(datetime(t.created_at, '{}'), 1, {})",
                    self.validate_offset(offset),
                    self.validate_width(width_str)
                )
            }
            _ => "substr(t.created_at, 1, 10)".into(),
        }
    }
}