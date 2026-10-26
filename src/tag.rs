//! Tags (`tag.*`): named labels attached to domains.
//!
//! A tag is a label such as `tenant-a` that can be attached to any number of
//! domains and used to group them. The API can also change a tag's name, which
//! takes precedence over the add/remove lists — this crate refuses the
//! combination instead of letting the rename silently win.
//!
//! ```
//! use inwx_client::TagUpdate;
//!
//! let update = TagUpdate::new(3)?
//!     .tagging(&[101, 102])?
//!     .untagging(&[103])?;
//! let params = update.params()?;
//! assert_eq!(params["add"]["domainId"][0], 101);
//! assert_eq!(params["rem"]["domainId"][0], 103);
//! # Ok::<(), inwx_client::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, validate_token, DomainName};

/// One tag, from `tag.info`, `tag.create` or `tag.list`.
///
/// ```
/// use inwx_client::Tag;
///
/// let tag: Tag = serde_json::from_str(r#"{"id":3,"name":"tenant-a"}"#)?;
/// assert_eq!(tag.id, Some(3));
/// assert_eq!(tag.name.as_deref(), Some("tenant-a"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Tag {
    /// Tag id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Tag name as stored (the API strips invalid characters).
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Number of tagged domains, only present when searching by id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
}

/// One tag together with the domains it labels (`tag.list` with a `domain`
/// filter).
///
/// ```
/// use inwx_client::TaggedDomains;
///
/// let listing: TaggedDomains = serde_json::from_str(
///     r#"{"id":3,"name":"tenant-a","count":{"domain":2}}"#,
/// )?;
/// assert_eq!(listing.count.domain, Some(2));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct TaggedDomains {
    /// Tag id.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Tag name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// How many domains carry the tag.
    #[serde(default)]
    pub count: TagUsage,
}

/// The `count` object of a tag listing.
///
/// ```
/// use inwx_client::TagUsage;
///
/// let usage: TagUsage = serde_json::from_str(r#"{"domain":4}"#)?;
/// assert_eq!(usage.domain, Some(4));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TagUsage {
    /// Number of domains using the tag.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub domain: Option<i64>,
}

/// A `tag.update` request.
///
/// ```
/// use inwx_client::TagUpdate;
///
/// let rename = TagUpdate::new(3)?.renaming("tenant-b")?;
/// assert_eq!(rename.params()?["name"], "tenant-b");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagUpdate {
    id: i64,
    name: Option<String>,
    add: Vec<i64>,
    rem: Vec<i64>,
}

impl TagUpdate {
    /// An empty update for tag `id`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id.
    ///
    /// ```
    /// use inwx_client::TagUpdate;
    ///
    /// assert!(TagUpdate::new(3).is_ok());
    /// assert!(TagUpdate::new(0).is_err());
    /// assert!(TagUpdate::new(3).unwrap().params().is_err());
    /// ```
    pub fn new(id: i64) -> Result<Self> {
        if id <= 0 {
            return Err(Error::validation(
                "tag.id",
                format!("must be a positive tag id, got {id}"),
            ));
        }
        Ok(Self {
            id,
            name: None,
            add: Vec::new(),
            rem: Vec::new(),
        })
    }

    /// Renames the tag.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is unusable.
    ///
    /// ```
    /// use inwx_client::TagUpdate;
    ///
    /// let update = TagUpdate::new(3)?.renaming("tenant-b")?;
    /// assert_eq!(update.params()?["name"], "tenant-b");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn renaming(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_token("tag.name", &name)?;
        self.name = Some(name.trim().to_owned());
        Ok(self)
    }

    /// Tags the given domains (`add`, a list of domain ids).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list, a non-positive id, an id that
    /// appears twice, or an id that is also being untagged.
    ///
    /// ```
    /// use inwx_client::TagUpdate;
    ///
    /// let update = TagUpdate::new(3)?.tagging(&[101, 102])?;
    /// assert_eq!(update.params()?["add"]["domainId"][1], 102);
    /// assert!(TagUpdate::new(3)?.tagging(&[]).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn tagging(mut self, domain_ids: &[i64]) -> Result<Self> {
        validate_ids("tag.add", domain_ids)?;
        for id in domain_ids {
            if self.rem.contains(id) {
                return Err(Error::validation(
                    "tag.add",
                    format!("domain {id} cannot be tagged and untagged in one call"),
                ));
            }
        }
        self.add.extend_from_slice(domain_ids);
        Ok(self)
    }

    /// Untags the given domains (`rem`, a list of domain ids).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list, a non-positive id, an id that
    /// appears twice, or an id that is also being tagged.
    ///
    /// ```
    /// use inwx_client::TagUpdate;
    ///
    /// let update = TagUpdate::new(3)?.untagging(&[103])?;
    /// assert_eq!(update.params()?["rem"]["domainId"][0], 103);
    /// assert!(TagUpdate::new(3)?.untagging(&[0]).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn untagging(mut self, domain_ids: &[i64]) -> Result<Self> {
        validate_ids("tag.rem", domain_ids)?;
        for id in domain_ids {
            if self.add.contains(id) {
                return Err(Error::validation(
                    "tag.rem",
                    format!("domain {id} cannot be tagged and untagged in one call"),
                ));
            }
        }
        self.rem.extend_from_slice(domain_ids);
        Ok(self)
    }

    /// The `tag.update` parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a rename is combined with add/remove: the API
    /// documents the rename as taking precedence, which would discard the
    /// lists without saying so.
    ///
    /// ```
    /// use inwx_client::TagUpdate;
    ///
    /// let both = TagUpdate::new(3)?.renaming("x")?.tagging(&[101])?;
    /// assert!(both.params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        if self.name.is_some() && (!self.add.is_empty() || !self.rem.is_empty()) {
            return Err(Error::validation(
                "tag.update",
                "a rename takes precedence in the API and would discard the add/rem lists",
            ));
        }
        if self.name.is_none() && self.add.is_empty() && self.rem.is_empty() {
            return Err(Error::validation(
                "tag.update",
                "sets no field; add a rename, a tag or an untag",
            ));
        }
        let mut params = Map::new();
        params.insert("id".to_owned(), json!(self.id));
        if let Some(name) = &self.name {
            params.insert("name".to_owned(), json!(name));
        }
        if !self.add.is_empty() {
            params.insert("add".to_owned(), json!({ "domainId": self.add }));
        }
        if !self.rem.is_empty() {
            params.insert("rem".to_owned(), json!({ "domainId": self.rem }));
        }
        Ok(Value::Object(params))
    }
}

/// Rejects an empty id list, a non-positive id, or a duplicate.
fn validate_ids(field: &'static str, ids: &[i64]) -> Result<()> {
    if ids.is_empty() {
        return Err(Error::validation(field, "must list at least one domain id"));
    }
    for (index, id) in ids.iter().enumerate() {
        if *id <= 0 {
            return Err(Error::validation(
                field,
                format!("domain ids must be positive, got {id}"),
            ));
        }
        if ids[..index].contains(id) {
            return Err(Error::validation(
                field,
                format!("domain id {id} is listed twice"),
            ));
        }
    }
    Ok(())
}

impl<T: Transport> InwxClient<T> {
    /// Creates a tag, or returns the existing one (`tag.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let tag = client.create_tag("tenant-a").await?;
    /// println!("{:?} {:?}", tag.id, tag.name);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is unusable, plus the usual transport
    /// and API errors.
    pub async fn create_tag(&self, name: &str) -> Result<Tag> {
        validate_token("tag.name", name)?;
        let data = self
            .call("tag.create", json!({ "name": name.trim() }))
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Untags every object and deletes the tag (`tag.delete`).
    ///
    /// The domains stay; only the labels go.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_tag(3).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn delete_tag(&self, id: i64) -> Result<()> {
        if id <= 0 {
            return Err(Error::validation(
                "tag.id",
                format!("must be a positive tag id, got {id}"),
            ));
        }
        self.call("tag.delete", json!({ "id": id })).await?;
        Ok(())
    }

    /// Reads one tag (`tag.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// println!("{:?}", client.tag_info(3).await?.name);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors — `2303` when the tag does not exist.
    pub async fn tag_info(&self, id: i64) -> Result<Tag> {
        if id <= 0 {
            return Err(Error::validation(
                "tag.id",
                format!("must be a positive tag id, got {id}"),
            ));
        }
        let data = self.call("tag.info", json!({ "id": id })).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Lists tags, optionally filtered by domain or tag id (`tag.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let tagged = client
    ///     .list_tags(Some(&[DomainName::parse("example.com")?]), None)
    ///     .await?;
    /// for tag in tagged {
    ///     println!("{:?} {}", tag.name, tag.count.domain.unwrap_or_default());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty filter list, plus the usual transport
    /// and API errors.
    pub async fn list_tags(
        &self,
        domains: Option<&[DomainName]>,
        ids: Option<&[i64]>,
    ) -> Result<Vec<TaggedDomains>> {
        let mut params = Map::new();
        if let Some(domains) = domains {
            if domains.is_empty() {
                return Err(Error::validation(
                    "tag.domain",
                    "must not be empty; use None for every tag",
                ));
            }
            params.insert(
                "domain".to_owned(),
                json!(domains.iter().map(DomainName::as_str).collect::<Vec<_>>()),
            );
        }
        if let Some(ids) = ids {
            if ids.is_empty() {
                return Err(Error::validation(
                    "tag.id",
                    "must not be empty; use None for every tag",
                ));
            }
            params.insert("id".to_owned(), json!(ids));
        }
        let data = self.call("tag.list", Value::Object(params)).await?;
        let entries = match data.get("tag") {
            Some(Value::Array(entries)) => entries.clone(),
            _ => Vec::new(),
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value(entry).ok())
            .collect())
    }

    /// Renames a tag or adds/removes domains (`tag.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport, TagUpdate};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let update = TagUpdate::new(3)?.tagging(&[101])?;
    /// let renamed = client.update_tag(&update).await?;
    /// println!("{:?}", renamed.name);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`TagUpdate::params`], plus the usual
    /// transport and API errors.
    pub async fn update_tag(&self, update: &TagUpdate) -> Result<Tag> {
        let data = self.call("tag.update", update.params()?).await?;
        serde_json::from_value(data).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rename_cannot_be_combined_with_add_or_remove() {
        let update = TagUpdate::new(3)
            .unwrap()
            .renaming("new")
            .unwrap()
            .tagging(&[101])
            .unwrap();
        assert!(update.params().is_err());
    }

    #[test]
    fn an_id_cannot_be_tagged_and_untagged_at_once() {
        assert!(TagUpdate::new(3)
            .unwrap()
            .tagging(&[101])
            .unwrap()
            .untagging(&[101])
            .is_err());
        assert!(TagUpdate::new(3)
            .unwrap()
            .untagging(&[101])
            .unwrap()
            .tagging(&[101])
            .is_err());
    }

    #[test]
    fn duplicate_and_non_positive_ids_are_rejected() {
        assert!(TagUpdate::new(3).unwrap().tagging(&[1, 1]).is_err());
        assert!(TagUpdate::new(3).unwrap().tagging(&[-1]).is_err());
        assert!(TagUpdate::new(3).unwrap().untagging(&[0]).is_err());
    }

    #[test]
    fn an_empty_update_is_rejected() {
        assert!(TagUpdate::new(3).unwrap().params().is_err());
    }
}
