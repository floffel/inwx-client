//! Private storage for passwords.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// A password that cannot be cloned, is zeroed on drop, and compares in
/// constant time.
pub(crate) struct Password(Zeroizing<String>);

impl Password {
    /// Takes ownership of the password's backing allocation.
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrows the password when a request body needs it.
    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password(<redacted>)")
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.expose()
            .as_bytes()
            .ct_eq(other.expose().as_bytes())
            .into()
    }
}

impl Eq for Password {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_compare_by_value_and_redact_debug() {
        let password = Password::new("hunter2".to_owned());
        let same = Password::new("hunter2".to_owned());
        let different = Password::new("hunter3".to_owned());
        let different_length = Password::new("hunter22".to_owned());

        assert_eq!(password, same);
        assert_ne!(password, different);
        assert_ne!(password, different_length);
        assert_eq!(format!("{password:?}"), "Password(<redacted>)");
    }
}
