//! Shared parameter rules for the reseller/partner objects.
//!
//! The reseller methods (`application.*`, `authinfo2.*`, `customer.*`,
//! `document.*`, `host.*`, `message.*`, `news.*`, `nichandle.*`, `pdf.*`) page
//! the same way, identify their object by a positive id and move documents
//! around base64-encoded. Keeping those four rules here means a limit is
//! enforced identically in every module instead of once per builder.

use base64::Engine as _;
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::types::reject_control_chars;

/// Largest page size the crate is willing to ask for.
///
/// The reseller list methods all take a `pagelimit`; a huge value is either a
/// mistake or a denial-of-service against the caller's own memory, so it is
/// refused locally.
pub(crate) const MAX_PAGE_LIMIT: u32 = 1_000;

/// Largest document payload the crate encodes or decodes (8 MiB).
///
/// Checked against the *input* length before any allocation, so a mistyped
/// multi-gigabyte blob fails at the call site instead of during base64
/// encoding.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;

/// Rejects an id the API cannot resolve: INWX object ids are positive.
pub(crate) fn object_id(field: &'static str, id: i64) -> Result<i64> {
    if id <= 0 {
        return Err(Error::validation(
            field,
            format!("must be a positive id, got {id}"),
        ));
    }
    Ok(id)
}

/// Page (clamped to 1) and page size (bounded by [`MAX_PAGE_LIMIT`]).
pub(crate) fn paging(page: u32, limit: u32) -> Result<(u32, u32)> {
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(Error::validation(
            "pagelimit",
            format!("must be 1 to {MAX_PAGE_LIMIT}, got {limit}"),
        ));
    }
    Ok((page.max(1), limit))
}

/// A two-letter ISO 3166-1 alpha-2 country code, upper-cased.
pub(crate) fn country_code(field: &'static str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.chars().count() != 2 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(Error::validation(
            field,
            format!("{value:?} is not a two-letter ISO 3166-1 country code"),
        ));
    }
    Ok(trimmed.to_ascii_uppercase())
}

/// Refuses a request that would send nothing beyond its own identifier.
///
/// An empty `*.update` is a guaranteed `2003 Required parameter missing`, and an
/// empty `*.create` orders an unspecified product; both are cheaper to catch
/// here than after the round trip.
pub(crate) fn require_payload(field: &'static str, count: usize) -> Result<()> {
    if count == 0 {
        return Err(Error::validation(
            field,
            "needs at least one parameter; the API rejects an empty request with 2003",
        ));
    }
    Ok(())
}

/// Encodes a document payload, checking the size before allocating.
pub(crate) fn encode_document(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() {
        return Err(Error::validation(
            "document.data",
            "must not be empty (an empty document is never what the caller meant)",
        ));
    }
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::validation(
            "document.data",
            format!(
                "must be at most {MAX_DOCUMENT_BYTES} bytes, got {}",
                bytes.len()
            ),
        ));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Decodes a document payload, checking the encoded size before allocating.
pub(crate) fn decode_document(encoded: &str) -> Result<Vec<u8>> {
    let trimmed = encoded.trim();
    if trimmed.is_empty() {
        return Err(Error::validation(
            "document.data",
            "the answer carries no document body",
        ));
    }
    // base64 grows 4 bytes per 3 input bytes; check the budget first.
    let budget = MAX_DOCUMENT_BYTES / 3 * 4 + 4;
    if trimmed.len() > budget {
        return Err(Error::validation(
            "document.data",
            format!(
                "base64 payload of {} bytes exceeds the {MAX_DOCUMENT_BYTES} byte limit",
                trimmed.len()
            ),
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|error| {
            Error::validation("document.data", format!("is not valid base64: {error}"))
        })
}

/// A JSON-RPC parameter name: a short ASCII identifier without control
/// characters or padding — a key with a stray space is a mistake, not a silently
/// renamed field.
fn parameter_name(key: &str) -> Result<String> {
    let trimmed = key;
    reject_control_chars("params.key", trimmed)?;
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(Error::validation(
            "params.key",
            format!("must be 1 to 64 characters, got {:?}", trimmed.len()),
        ));
    }
    let mut characters = trimmed.chars();
    let first = characters.next().unwrap_or(' ');
    if !first.is_ascii_alphabetic() || !characters.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(Error::validation(
            "params.key",
            format!("{key:?} is not a parameter name (letters, digits and `_`)"),
        ));
    }
    Ok(trimmed.to_owned())
}

/// Parameters a caller sets by name.
///
/// The reseller objects carry product-specific fields that this crate does not
/// model one by one; the builders that take them run every key through
/// [`parameter_name`] and refuse a key a typed setter already owns.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ExtraFields {
    entries: Map<String, Value>,
}

impl ExtraFields {
    /// Adds one parameter, refusing a malformed or reserved key.
    pub(crate) fn set(&mut self, key: &str, value: Value, reserved: &[&str]) -> Result<()> {
        let name = parameter_name(key)?;
        if reserved.contains(&name.as_str()) {
            return Err(Error::validation(
                "params.key",
                format!("`{name}` is owned by the builder; use its typed setter instead"),
            ));
        }
        self.entries.insert(name, value);
        Ok(())
    }

    /// Number of parameters held.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing was set.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Copies the parameters into a request map.
    pub(crate) fn write_into(&self, params: &mut Map<String, Value>) {
        for (key, value) in &self.entries {
            params.insert(key.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ids_must_be_positive() {
        assert_eq!(object_id("applicationId", 1).unwrap(), 1);
        assert!(object_id("applicationId", 0).is_err());
        assert!(object_id("applicationId", -1).is_err());
    }

    #[test]
    fn page_limit_has_a_hard_pair() {
        assert_eq!(paging(0, 1).unwrap(), (1, 1));
        assert_eq!(paging(3, MAX_PAGE_LIMIT).unwrap(), (3, MAX_PAGE_LIMIT));
        assert!(paging(1, 0).is_err());
        assert!(paging(1, MAX_PAGE_LIMIT + 1).is_err());
    }

    #[test]
    fn country_codes_are_two_letters_and_upper_cased() {
        assert_eq!(country_code("country", " de ").unwrap(), "DE");
        assert!(country_code("country", "D").is_err());
        assert!(country_code("country", "DEU").is_err());
        assert!(country_code("country", "D1").is_err());
    }

    #[test]
    fn empty_payloads_are_refused() {
        assert!(require_payload("application.update", 1).is_ok());
        assert!(require_payload("application.update", 0).is_err());
    }

    #[test]
    fn documents_round_trip_and_are_bounded() {
        let encoded = encode_document(b"%PDF-1.4").unwrap();
        assert_eq!(decode_document(&encoded).unwrap(), b"%PDF-1.4");
        assert!(encode_document(b"").is_err());

        let oversized = vec![0u8; MAX_DOCUMENT_BYTES + 1];
        assert!(encode_document(&oversized).is_err());

        let just_inside = vec![0u8; MAX_DOCUMENT_BYTES];
        assert!(encode_document(&just_inside).is_ok());

        // The decoded ceiling, expressed in encoded bytes: the last multiple of
        // four that still fits decodes, the next one is refused before the
        // decoder allocates.
        let budget = MAX_DOCUMENT_BYTES / 3 * 4 + 4;
        let inside_base64 = "A".repeat(budget / 4 * 4);
        assert!(decode_document(&inside_base64).is_ok());
        let outside_base64 = "A".repeat(budget / 4 * 4 + 4);
        assert!(decode_document(&outside_base64).is_err());
        assert!(decode_document("not base64!").is_err());
        assert!(decode_document("  ").is_err());
    }

    #[test]
    fn extra_keys_are_validated_and_reserved_keys_refused() {
        let mut fields = ExtraFields::default();
        assert!(fields.is_empty());
        assert_eq!(fields.len(), 0);

        fields
            .set("freeText", json!("hello"), &["customerId"])
            .unwrap();
        assert_eq!(fields.len(), 1);
        assert!(fields.set("customerId", json!(1), &["customerId"]).is_err());
        assert!(fields.set("has space", json!(1), &[]).is_err());
        assert!(fields.set("padded ", json!(1), &[]).is_err());
        assert!(fields.set("1nvalid", json!(1), &[]).is_err());
        assert!(fields.set(&"a".repeat(65), json!(1), &[]).is_err());
        assert!(fields.set("with\nnewline", json!(1), &[]).is_err());

        let mut params = Map::new();
        fields.write_into(&mut params);
        assert_eq!(params["freeText"], "hello");
    }
}
