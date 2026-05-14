use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    message: String,
}

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn field(field: &str, message: impl AsRef<str>) -> Self {
        Self::new(format!("{field}: {}", message.as_ref()))
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for ValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ValidationError {}

pub(crate) fn ensure_non_empty(field: &str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        Err(ValidationError::field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_eq(field: &str, actual: &str, expected: &str) -> Result<(), ValidationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ValidationError::field(
            field,
            format!("expected {expected:?}, got {actual:?}"),
        ))
    }
}

pub(crate) fn ensure_sha256_hex(field: &str, value: &str) -> Result<(), ValidationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ValidationError::field(
            field,
            "must be a 64-character hex SHA-256 digest",
        ))
    }
}
