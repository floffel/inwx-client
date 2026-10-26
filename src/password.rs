//! Password storage shared by the account and DynDNS request types.
//!
//! Passwords are never cloned and their backing buffer is zeroized on drop.
//! Equality goes through [`subtle`] so comparing two passwords does not leak
//! their contents through an early return.

use std::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// A validated password whose memory is cleared before it is released.
pub(crate) struct Password(Zeroizing<String>);

impl Password {
    /// Validates a buffer that was already moved into zeroizing storage.
    pub(crate) fn from_zeroizing(
        field: &'static str,
        value: Zeroizing<String>,
        max_chars: Option<usize>,
    ) -> Result<Self> {
        let length = value.chars().count();
        if length == 0 {
            return Err(Error::validation(field, "must not be empty"));
        }
        if let Some(max_chars) = max_chars {
            if length > max_chars {
                return Err(Error::validation(
                    field,
                    format!("must be at most {max_chars} characters"),
                ));
            }
        }
        if value.chars().any(char::is_control) {
            return Err(Error::validation(
                field,
                "must not contain control characters",
            ));
        }
        Ok(Self(value))
    }

    /// Borrows the password for serialisation.
    #[must_use]
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl ConstantTimeEq for Password {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expose().as_bytes().ct_eq(other.expose().as_bytes())
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Password {}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(value: impl Into<String>, max_chars: Option<usize>) -> Result<Password> {
        Password::from_zeroizing("password", Zeroizing::new(value.into()), max_chars)
    }

    #[test]
    fn passwords_compare_by_value() {
        let password = build("correct horse", None).unwrap();
        let same = build("correct horse", None).unwrap();
        let different = build("correct horsf", None).unwrap();
        let shorter = build("correct", None).unwrap();

        assert_eq!(password, same);
        assert_ne!(password, different);
        assert_ne!(password, shorter);
    }

    #[test]
    fn empty_and_control_character_passwords_are_refused() {
        let empty = build("", None).unwrap_err();
        assert!(matches!(
            empty,
            Error::Validation {
                field: "password",
                ..
            }
        ));

        for value in ["pass\nword", "pass\rword", "pass\u{0}word"] {
            let error = build(value, None).unwrap_err();
            assert!(matches!(
                error,
                Error::Validation {
                    field: "password",
                    ..
                }
            ));
        }
    }

    #[test]
    fn the_character_limit_has_a_boundary_pair() {
        assert!(build("x".repeat(63), Some(64)).is_ok());
        assert!(build("x".repeat(64), Some(64)).is_ok());
        let error = build("x".repeat(65), Some(64)).unwrap_err();
        assert!(matches!(
            error,
            Error::Validation {
                field: "password",
                ..
            }
        ));
    }
}
