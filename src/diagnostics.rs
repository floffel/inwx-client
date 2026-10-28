//! Diagnostics: why a command was rejected, and what a `TLD` requires
//! (`domain.log`, `domain.stats`, `domain.getRules`, `domain.getTldGroups`).
//!
//! These four are the read endpoints that answer a question *before* a write:
//! `domain.log` explains what happened to a domain, `domain.getRules` and
//! `domain.getTldGroups` say which extra data a `TLD` demands and which
//! namespaces group it, and `domain.stats` reports the account's domain
//! counters. Reading them after a failed `domain.create` is too late; reading
//! them before it turns a `2191`/`2192` into a local error.
//!
//! The four live in ch02 §2.9 of the INWX documentation
//! (<https://account.inwx.com/en/help/apidoc/f/ch02s09.html>), the same page as
//! `domain.create`. The parameter names this crate sends are listed in
//! `docs/contracts.md`; the `resData` field lists are *not* recorded there, and
//! no live endpoint was available to check them, so the response types here are
//! written defensively: every field is optional, the list may arrive as a JSON
//! array or as the numerically keyed object INWX produces when a result set has
//! one entry, both `camelCase` and `snake_case` spellings are accepted, and
//! everything unknown is kept in [`extra`](DomainLogEntry::extra) instead of
//! being dropped. See the `Unverified` section of `docs/contracts.md`.

use std::collections::BTreeMap;

use serde::de::{DeserializeOwned, Deserializer};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, reject_control_chars, validate_dns_name, DomainName, Timestamp};

/// Largest `pagelimit` [`DomainLogQuery`] accepts.
///
/// `pagelimit` is a plain `int` and no maximum is recorded for it, so this is
/// the crate's own bound: it keeps a mistyped `100_000` from asking the
/// API for a response nobody can hold in memory. A larger value the API
/// dislikes is still answered with `2004 Parameter value range error`.
///
/// ```
/// use inwx_client::MAX_PAGE_LIMIT;
///
/// assert_eq!(MAX_PAGE_LIMIT, 1_000);
/// // Just inside and just outside the bound.
/// assert!(inwx_client::DomainLogQuery::new(inwx_client::DomainName::parse("example.com")?)
///     .with_page(1, MAX_PAGE_LIMIT)
///     .is_ok());
/// assert!(inwx_client::DomainLogQuery::new(inwx_client::DomainName::parse("example.com")?)
///     .with_page(1, MAX_PAGE_LIMIT + 1)
///     .is_err());
/// # Ok::<(), inwx_client::Error>(())
/// ```
pub const MAX_PAGE_LIMIT: u32 = 1_000;

/// A query for `domain.log` — the action log of one domain.
///
/// The domain is required (the API answers a missing one with `2101`), paging
/// is optional.
///
/// ```
/// use inwx_client::{DomainLogQuery, DomainName, Timestamp};
///
/// let query = DomainLogQuery::new(DomainName::parse("example.com")?)
///     .with_page(1, 50)?
///     .with_range(
///         Timestamp::parse("2026-01-01T00:00:00")?,
///         Timestamp::parse("2026-02-01T00:00:00")?,
///     )?;
/// assert_eq!(query.params()["domain"], "example.com");
/// assert_eq!(query.params()["pagelimit"], 50);
/// assert!(query.params().get("dateFrom").is_some());
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainLogQuery {
    domain: DomainName,
    page: Option<u32>,
    limit: Option<u32>,
    from: Option<Timestamp>,
    to: Option<Timestamp>,
}

impl DomainLogQuery {
    /// A query for one domain, unpaged and unrestricted in time.
    ///
    /// ```
    /// use inwx_client::{DomainLogQuery, DomainName};
    ///
    /// let query = DomainLogQuery::new(DomainName::parse("example.com")?);
    /// assert_eq!(query.domain().as_str(), "example.com");
    /// assert!(query.params().get("page").is_none());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn new(domain: DomainName) -> Self {
        Self {
            domain,
            page: None,
            limit: None,
            from: None,
            to: None,
        }
    }

    /// Restricts the answer to one page of `limit` entries.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `page` is `0` (INWX pages start at `1`), or
    /// `limit` is `0` or above [`MAX_PAGE_LIMIT`].
    ///
    /// ```
    /// use inwx_client::{DomainLogQuery, DomainName};
    ///
    /// let query = DomainLogQuery::new(DomainName::parse("example.com")?).with_page(2, 25)?;
    /// assert_eq!(query.params()["page"], 2);
    /// assert!(DomainLogQuery::new(DomainName::parse("example.com")?).with_page(0, 25).is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_page(mut self, page: u32, limit: u32) -> Result<Self> {
        if page == 0 {
            return Err(Error::validation(
                "page",
                "must be at least 1 (pages start at 1)",
            ));
        }
        if limit == 0 {
            return Err(Error::validation("pagelimit", "must be at least 1"));
        }
        if limit > MAX_PAGE_LIMIT {
            return Err(Error::validation(
                "pagelimit",
                format!("must be at most {MAX_PAGE_LIMIT}, got {limit}"),
            ));
        }
        self.page = Some(page);
        self.limit = Some(limit);
        Ok(self)
    }

    /// Restricts the answer to actions after `from` and up to `to`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `to` is not strictly after `from`.
    ///
    /// ```
    /// use inwx_client::{DomainLogQuery, DomainName, Timestamp};
    ///
    /// let from = Timestamp::parse("2026-01-01T00:00:00")?;
    /// let to = Timestamp::parse("2026-02-01T00:00:00")?;
    /// let query = DomainLogQuery::new(DomainName::parse("example.com")?)
    ///     .with_range(from.clone(), to.clone())?;
    /// assert_eq!(query.params()["dateTo"], "2026-02-01T00:00:00");
    /// // An empty range is a mistake, not a query.
    /// assert!(DomainLogQuery::new(DomainName::parse("example.com")?)
    ///     .with_range(from.clone(), from)
    ///     .is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_range(mut self, from: Timestamp, to: Timestamp) -> Result<Self> {
        if to <= from {
            return Err(Error::validation("dateTo", "must be after dateFrom"));
        }
        self.from = Some(from);
        self.to = Some(to);
        Ok(self)
    }

    /// The domain the log is asked for.
    ///
    /// ```
    /// use inwx_client::{DomainLogQuery, DomainName};
    ///
    /// let query = DomainLogQuery::new(DomainName::parse("example.com")?);
    /// assert_eq!(query.domain().as_str(), "example.com");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The `domain.log` parameters.
    ///
    /// ```
    /// use inwx_client::{DomainLogQuery, DomainName};
    ///
    /// let params = DomainLogQuery::new(DomainName::parse("example.com")?).params();
    /// assert_eq!(params, serde_json::json!({"domain": "example.com"}));
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        // `domain` is a plain string here, as it is for `domain.info` and
        // `domain.renew`; only `domain.check`/`list`/`getPrices` take an array.
        let mut params = Map::new();
        params.insert("domain".to_owned(), json!(self.domain.as_str()));
        if let Some(page) = self.page {
            params.insert("page".to_owned(), json!(page));
        }
        if let Some(limit) = self.limit {
            params.insert("pagelimit".to_owned(), json!(limit));
        }
        if let Some(from) = &self.from {
            params.insert("dateFrom".to_owned(), json!(from));
        }
        if let Some(to) = &self.to {
            params.insert("dateTo".to_owned(), json!(to));
        }
        Value::Object(params)
    }
}

/// One line of a domain's action log (`domain.log`).
///
/// The documented field names are inconsistent across INWX's own pages, so
/// every field is optional and carries aliases: the timestamp arrives as
/// `date`, `timestamp` or `actionDate`, the action as `action`, `type` or
/// `event`. Anything else stays in [`extra`](Self::extra).
///
/// ```
/// use inwx_client::DomainLogEntry;
///
/// let entry: DomainLogEntry = serde_json::from_str(
///     r#"{"date":"2026-10-26T08:00:00","action":"create","text":"domain registered",
///         "user":"example-user","ip":"203.0.113.7"}"#,
/// )?;
/// assert_eq!(entry.action.as_deref(), Some("create"));
/// assert_eq!(entry.ip.as_deref(), Some("203.0.113.7"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DomainLogEntry {
    /// When the action happened, as the API wrote it.
    #[serde(
        default,
        alias = "timestamp",
        alias = "actionDate",
        alias = "action_date",
        deserialize_with = "de::opt_string"
    )]
    pub date: Option<String>,
    /// What happened, for example `create`, `renew`, `transfer`.
    #[serde(
        default,
        alias = "type",
        alias = "event",
        alias = "actionName",
        alias = "action_name",
        deserialize_with = "de::opt_string"
    )]
    pub action: Option<String>,
    /// The human readable explanation — the "why was this rejected" field.
    #[serde(
        default,
        alias = "message",
        alias = "description",
        alias = "reason",
        alias = "msg",
        deserialize_with = "de::opt_string"
    )]
    pub text: Option<String>,
    /// Account or handle that triggered the action.
    #[serde(
        default,
        alias = "account",
        alias = "handle",
        alias = "userId",
        deserialize_with = "de::opt_string"
    )]
    pub user: Option<String>,
    /// Address the action came from.
    #[serde(
        default,
        alias = "ipAddress",
        alias = "ip_address",
        alias = "host",
        deserialize_with = "de::opt_string"
    )]
    pub ip: Option<String>,
    /// Every field this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl DomainLogEntry {
    /// The timestamp as a [`Timestamp`], when the API sent one it can parse.
    ///
    /// Some log endpoints separate date and time with a space instead of a `T`;
    /// that spelling is accepted too.
    ///
    /// ```
    /// use inwx_client::DomainLogEntry;
    ///
    /// let entry: DomainLogEntry =
    ///     serde_json::from_str(r#"{"date":"2026-10-26 08:00:00"}"#)?;
    /// let at = entry.occurred_at().expect("parsed");
    /// assert_eq!(at.as_str(), "2026-10-26T08:00:00");
    ///
    /// let unclear: DomainLogEntry = serde_json::from_str(r#"{"date":"last tuesday"}"#)?;
    /// assert!(unclear.occurred_at().is_none());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn occurred_at(&self) -> Option<Timestamp> {
        let raw = self.date.as_deref()?;
        Timestamp::parse(raw)
            .or_else(|_| Timestamp::parse(&raw.replace(' ', "T")))
            .ok()
    }
}

/// The answer to `domain.log`.
///
/// ```
/// use inwx_client::DomainLog;
///
/// let log: DomainLog = serde_json::from_str(
///     r#"{"count":3,"logs":[{"date":"2026-10-26T08:00:00","action":"create"}]}"#,
/// )?;
/// assert_eq!(log.count, Some(3));
/// assert_eq!(log.len(), 1);
/// assert!(log.has_more());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DomainLog {
    /// Total number of log lines the query matched, not just this page.
    #[serde(default, alias = "total", deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The log lines, newest first as far as INWX orders them.
    #[serde(
        default,
        rename = "logs",
        alias = "log",
        alias = "data",
        alias = "domain",
        alias = "entries",
        deserialize_with = "flexible_list"
    )]
    pub entries: Vec<DomainLogEntry>,
    /// Every field this crate does not model — the echoed `page`/`pagelimit`
    /// for instance — kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl DomainLog {
    /// Number of entries on this page.
    ///
    /// ```
    /// use inwx_client::DomainLog;
    /// assert_eq!(DomainLog::default().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the answer carries no entries at all.
    ///
    /// ```
    /// use inwx_client::DomainLog;
    /// assert!(DomainLog::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether more log lines exist beyond this page.
    ///
    /// ```
    /// use inwx_client::DomainLog;
    ///
    /// let page: DomainLog =
    ///     serde_json::from_str(r#"{"count":9,"logs":[{"action":"create"}]}"#)?;
    /// assert!(page.has_more());
    ///
    /// let last: DomainLog =
    ///     serde_json::from_str(r#"{"count":1,"logs":[{"action":"create"}]}"#)?;
    /// assert!(!last.has_more());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.count
            .is_some_and(|count| i64::try_from(self.entries.len()).unwrap_or(i64::MAX) < count)
    }
}

/// One counter of `domain.stats` — a `TLD`, a status, or an action counted for
/// the account or for one domain.
///
/// ```
/// use inwx_client::DomainStat;
///
/// let stat: DomainStat = serde_json::from_str(
///     r#"{"domain":"de","count":"12","amount":"108.50","description":"registered"}"#,
/// )?;
/// assert_eq!(stat.name.as_deref(), Some("de"));
/// assert_eq!(stat.count, Some(12));
/// assert_eq!(stat.amount, Some(108.5));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DomainStat {
    /// What is counted — a `TLD`, a status, a domain.
    #[serde(
        default,
        alias = "domain",
        alias = "tld",
        alias = "key",
        deserialize_with = "de::opt_string"
    )]
    pub name: Option<String>,
    /// How often it occurred.
    #[serde(default, alias = "value", deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The amount that belongs to the counter, when the API reports one.
    #[serde(default, deserialize_with = "de::opt_f64")]
    pub amount: Option<f64>,
    /// Human readable label for the counter.
    #[serde(
        default,
        alias = "description",
        alias = "text",
        deserialize_with = "de::opt_string"
    )]
    pub text: Option<String>,
    /// Every field this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// The answer to `domain.stats`.
///
/// INWX answers this method both with a list and with a flat object that puts
/// each counter under its own key (`{"totalDomains":"12", "de":"4"}`).
/// [`counter`](Self::counter), [`amount_for`](Self::amount_for) and
/// [`text_for`](Self::text_for) read both shapes, so a caller does not have to
/// know which one arrived.
///
/// ```
/// use inwx_client::DomainStats;
///
/// let list: DomainStats = serde_json::from_str(
///     r#"{"count":2,"stats":[{"domain":"de","count":"12"},{"domain":"com","count":"3"}]}"#,
/// )?;
/// assert_eq!(list.len(), 2);
/// assert_eq!(list.counter("de"), Some(12));
///
/// let flat: DomainStats = serde_json::from_str(r#"{"totalDomains":"12","de":"4"}"#)?;
/// assert!(!list.has_more());
/// assert_eq!(flat.counter("totaldomains"), Some(12));
/// assert_eq!(flat.counter("nope"), None);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct DomainStats {
    /// Total number of counters the answer describes.
    #[serde(default, alias = "total", deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The counters, when the API answers with a list.
    #[serde(
        default,
        rename = "stats",
        alias = "stat",
        alias = "data",
        alias = "domain",
        alias = "entries",
        deserialize_with = "flexible_list"
    )]
    pub stats: Vec<DomainStat>,
    /// Every field this crate does not model, kept verbatim — including the
    /// counters of the flat answer shape.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl DomainStats {
    /// Number of list entries.
    ///
    /// ```
    /// use inwx_client::DomainStats;
    /// assert_eq!(DomainStats::default().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.stats.len()
    }

    /// Whether the answer carries no list entries.
    ///
    /// ```
    /// use inwx_client::DomainStats;
    /// assert!(DomainStats::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stats.is_empty()
    }

    /// Whether more counters exist beyond what was parsed.
    ///
    /// ```
    /// use inwx_client::DomainStats;
    ///
    /// let stats: DomainStats =
    ///     serde_json::from_str(r#"{"count":5,"stats":[{"domain":"de","count":"12"}]}"#)?;
    /// assert!(stats.has_more());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.count
            .is_some_and(|count| i64::try_from(self.stats.len()).unwrap_or(i64::MAX) < count)
    }

    /// The entry named `key`, compared case-insensitively and ignoring a
    /// leading dot.
    ///
    /// ```
    /// use inwx_client::DomainStats;
    ///
    /// let stats: DomainStats =
    ///     serde_json::from_str(r#"{"stats":[{"domain":"DE","count":"12"}]}"#)?;
    /// assert!(stats.find(".de").is_some());
    /// assert!(stats.find("com").is_none());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn find(&self, key: &str) -> Option<&DomainStat> {
        let wanted = normalize_key(key);
        self.stats.iter().find(|stat| {
            stat.name
                .as_deref()
                .is_some_and(|name| normalize_key(name) == wanted)
        })
    }

    /// The counter for `key`, from the list or from the flat answer shape.
    ///
    /// A numeric string (`"12"`) counts as a number.
    ///
    /// ```
    /// use inwx_client::DomainStats;
    ///
    /// let flat: DomainStats = serde_json::from_str(r#"{"totalDomains":"12"}"#)?;
    /// assert_eq!(flat.counter("totalDomains"), Some(12));
    ///
    /// let list: DomainStats = serde_json::from_str(r#"{"stats":[{"domain":"de","count":4}]}"#)?;
    /// assert_eq!(list.counter("de"), Some(4));
    /// assert_eq!(list.counter("com"), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn counter(&self, key: &str) -> Option<i64> {
        if let Some(value) = lookup_i64(&self.extra, key) {
            return Some(value);
        }
        self.find(key).and_then(|stat| stat.count)
    }

    /// The amount for `key`, from either answer shape.
    ///
    /// ```
    /// use inwx_client::DomainStats;
    ///
    /// let flat: DomainStats = serde_json::from_str(r#"{"totalAmount":"108.50"}"#)?;
    /// assert_eq!(flat.amount_for("totalAmount"), Some(108.5));
    ///
    /// let list: DomainStats = serde_json::from_str(r#"{"stats":[{"domain":"de","amount":12}]}"#)?;
    /// assert_eq!(list.amount_for("de"), Some(12.0));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn amount_for(&self, key: &str) -> Option<f64> {
        if let Some(value) = lookup_f64(&self.extra, key) {
            return Some(value);
        }
        self.find(key).and_then(|stat| stat.amount)
    }

    /// The label for `key`, from either answer shape.
    ///
    /// ```
    /// use inwx_client::DomainStats;
    ///
    /// let flat: DomainStats = serde_json::from_str(r#"{"state":"active"}"#)?;
    /// assert_eq!(flat.text_for("state"), Some("active"));
    ///
    /// let list: DomainStats =
    ///     serde_json::from_str(r#"{"stats":[{"domain":"de","text":"registered"}]}"#)?;
    /// assert_eq!(list.text_for("de"), Some("registered"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn text_for(&self, key: &str) -> Option<&str> {
        lookup_str(&self.extra, key)
            .or_else(|| self.find(key).and_then(|stat| stat.text.as_deref()))
    }
}

/// One rule of a `TLD` (`domain.getRules`).
///
/// ```
/// use inwx_client::DomainRule;
///
/// let rule: DomainRule = serde_json::from_str(
///     r#"{"name":"BIRTH-ADDRESS-CITY","value":"true","type":"boolean",
///         "description":"City of birth"}"#,
/// )?;
/// assert_eq!(rule.name.as_deref(), Some("BIRTH-ADDRESS-CITY"));
/// assert_eq!(rule.flag(), Some(true));
/// assert_eq!(rule.rule_type.as_deref(), Some("boolean"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DomainRule {
    /// Rule name, for example `BIRTH-DATE` or `TRADE-HANDLE`.
    #[serde(
        default,
        alias = "key",
        alias = "rule",
        alias = "ruleName",
        alias = "rule_name",
        deserialize_with = "de::opt_string"
    )]
    pub name: Option<String>,
    /// The rule's setting, as the API wrote it. `1`, `"true"`, `"10"`, `"de"`.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub value: Option<String>,
    /// What the rule means.
    #[serde(
        default,
        alias = "text",
        alias = "hint",
        alias = "label",
        deserialize_with = "de::opt_string"
    )]
    pub description: Option<String>,
    /// Declared type of the rule: `boolean`, `int`, `string`, `date`.
    #[serde(
        default,
        rename = "type",
        alias = "ruleType",
        alias = "rule_type",
        deserialize_with = "de::opt_string"
    )]
    pub rule_type: Option<String>,
    /// Every field this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl DomainRule {
    /// The value read as an integer, when it parses as one.
    ///
    /// ```
    /// use inwx_client::DomainRule;
    ///
    /// let rule: DomainRule = serde_json::from_str(r#"{"name":"MIN-PERIOD","value":"12"}"#)?;
    /// assert_eq!(rule.integer(), Some(12));
    ///
    /// let flag: DomainRule = serde_json::from_str(r#"{"name":"X","value":"true"}"#)?;
    /// assert_eq!(flag.integer(), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn integer(&self) -> Option<i64> {
        self.value.as_deref()?.trim().parse().ok()
    }

    /// The value read as a number, when it parses as one.
    ///
    /// ```
    /// use inwx_client::DomainRule;
    ///
    /// let rule: DomainRule = serde_json::from_str(r#"{"name":"FEE","value":"10.5"}"#)?;
    /// assert_eq!(rule.number(), Some(10.5));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn number(&self) -> Option<f64> {
        self.value.as_deref()?.trim().parse().ok()
    }

    /// The value read as a flag: `1`/`true`/`yes`/`on` against
    /// `0`/`false`/`no`/`off`, case-insensitively.
    ///
    /// ```
    /// use inwx_client::DomainRule;
    ///
    /// let yes: DomainRule = serde_json::from_str(r#"{"value":"1"}"#)?;
    /// let no: DomainRule = serde_json::from_str(r#"{"value":"FALSE"}"#)?;
    /// let other: DomainRule = serde_json::from_str(r#"{"value":"maybe"}"#)?;
    /// assert_eq!(yes.flag(), Some(true));
    /// assert_eq!(no.flag(), Some(false));
    /// assert_eq!(other.flag(), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn flag(&self) -> Option<bool> {
        parse_flag(self.value.as_deref()?)
    }
}

/// The answer to `domain.getRules`: what one `TLD` requires and allows.
///
/// ```
/// use inwx_client::TldRules;
///
/// let rules: TldRules = serde_json::from_str(
///     r#"{"tld":"de","count":2,"rules":[
///             {"name":"BIRTH-ADDRESS-CITY","value":"true","description":"City of birth"},
///             {"name":"MIN-PERIOD","value":"1"}]}"#,
/// )?;
/// assert_eq!(rules.tld.as_deref(), Some("de"));
/// assert_eq!(rules.value_for("birth-address-city"), Some("true"));
/// assert_eq!(rules.integer_for("MIN-PERIOD"), Some(1));
/// assert!(rules.find("UNKNOWN").is_none());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TldRules {
    /// The `TLD` the rules belong to, echoed back when the API echoes it.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub tld: Option<String>,
    /// Total number of rules the answer describes.
    #[serde(default, alias = "total", deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The rules.
    #[serde(
        default,
        rename = "rules",
        alias = "rule",
        alias = "data",
        deserialize_with = "flexible_list"
    )]
    pub rules: Vec<DomainRule>,
    /// Every field this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl TldRules {
    /// Number of rules.
    ///
    /// ```
    /// use inwx_client::TldRules;
    /// assert_eq!(TldRules::default().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the answer carries no rule at all.
    ///
    /// ```
    /// use inwx_client::TldRules;
    /// assert!(TldRules::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether more rules exist than were parsed.
    ///
    /// ```
    /// use inwx_client::TldRules;
    ///
    /// let rules: TldRules =
    ///     serde_json::from_str(r#"{"count":7,"rules":[{"name":"MIN-PERIOD","value":"1"}]}"#)?;
    /// assert!(rules.has_more());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.count
            .is_some_and(|count| i64::try_from(self.rules.len()).unwrap_or(i64::MAX) < count)
    }

    /// The rule named `name`, compared case-insensitively.
    ///
    /// ```
    /// use inwx_client::TldRules;
    ///
    /// let rules: TldRules = serde_json::from_str(r#"{"rules":[{"name":"MIN-PERIOD","value":"1"}]}"#)?;
    /// assert!(rules.find("min-period").is_some());
    /// assert!(rules.find("MIN-PERIOD ").is_some());
    /// assert!(rules.find("max-period").is_none());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&DomainRule> {
        let wanted = name.trim().to_ascii_uppercase();
        self.rules.iter().find(|rule| {
            rule.name
                .as_deref()
                .is_some_and(|name| name.trim().to_ascii_uppercase() == wanted)
        })
    }

    /// The value of one rule.
    ///
    /// ```
    /// use inwx_client::TldRules;
    ///
    /// let rules: TldRules = serde_json::from_str(r#"{"rules":[{"name":"BIRTH-DATE","value":"true"}]}"#)?;
    /// assert_eq!(rules.value_for("BIRTH-DATE"), Some("true"));
    /// assert!(rules.value_for("BIRTH-DATE").is_some_and(|value| value == "true"));
    /// assert_eq!(rules.value_for("NOPE"), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn value_for(&self, name: &str) -> Option<&str> {
        self.find(name)?.value.as_deref()
    }

    /// The value of one rule as an integer.
    ///
    /// ```
    /// use inwx_client::TldRules;
    ///
    /// let rules: TldRules = serde_json::from_str(r#"{"rules":[{"name":"MIN-PERIOD","value":"1"}]}"#)?;
    /// assert_eq!(rules.integer_for("MIN-PERIOD"), Some(1));
    /// assert_eq!(rules.integer_for("BIRTH-DATE"), None);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn integer_for(&self, name: &str) -> Option<i64> {
        self.find(name)?.integer()
    }
}

/// One `TLD` group (`domain.getTldGroups`).
///
/// ```
/// use inwx_client::TldGroup;
///
/// let group: TldGroup = serde_json::from_str(
///     r#"{"roId":12,"tldGroup":"ccTLDs","description":"country code TLDs","tld":["de","at"]}"#,
/// )?;
/// assert_eq!(group.id, Some(12));
/// assert_eq!(group.name.as_deref(), Some("ccTLDs"));
/// assert_eq!(group.tld_count(), 2);
/// assert!(group.contains("DE"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TldGroup {
    /// Record id of the group.
    #[serde(
        default,
        alias = "roId",
        alias = "ro_id",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// Name of the group.
    #[serde(
        default,
        alias = "tldGroup",
        alias = "tldgroup",
        alias = "tld_group",
        alias = "group",
        alias = "handle",
        deserialize_with = "de::opt_string"
    )]
    pub name: Option<String>,
    /// What the group is for.
    #[serde(
        default,
        alias = "text",
        alias = "title",
        deserialize_with = "de::opt_string"
    )]
    pub description: Option<String>,
    /// The `TLD`s in the group. A single string is a one-element list.
    #[serde(
        default,
        rename = "tld",
        alias = "tlds",
        deserialize_with = "de::vec_string"
    )]
    pub tlds: Vec<String>,
    /// Every field this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl TldGroup {
    /// Number of `TLD`s in the group.
    ///
    /// ```
    /// use inwx_client::TldGroup;
    ///
    /// let group: TldGroup = serde_json::from_str(r#"{"tld":["de","at","ch"]}"#)?;
    /// assert_eq!(group.tld_count(), 3);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn tld_count(&self) -> usize {
        self.tlds.len()
    }

    /// Whether the group lists no `TLD`.
    ///
    /// ```
    /// use inwx_client::TldGroup;
    /// assert!(TldGroup::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tlds.is_empty()
    }

    /// Whether the group holds a `TLD`, case-insensitively and tolerating a
    /// leading dot.
    ///
    /// ```
    /// use inwx_client::TldGroup;
    ///
    /// let group: TldGroup = serde_json::from_str(r#"{"tld":"de"}"#)?;
    /// assert!(group.contains(".DE"));
    /// assert!(!group.contains("com"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn contains(&self, tld: &str) -> bool {
        let wanted = normalize_key(tld);
        self.tlds.iter().any(|tld| normalize_key(tld) == wanted)
    }
}

/// The answer to `domain.getTldGroups`.
///
/// ```
/// use inwx_client::TldGroupList;
///
/// let list: TldGroupList = serde_json::from_str(
///     r#"{"count":2,"tldGroup":[{"roId":1,"tldGroup":"ccTLDs","tld":["de","at"]},
///             {"roId":2,"tldGroup":"newGfx","tld":["berlin"]}]}"#,
/// )?;
/// assert_eq!(list.len(), 2);
/// assert!(list.find("cctlds").is_some_and(|group| group.contains("de")));
/// assert!(!list.has_more());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TldGroupList {
    /// Total number of groups.
    #[serde(default, alias = "total", deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The groups.
    #[serde(
        default,
        rename = "tldGroup",
        alias = "tldgroup",
        alias = "tldGroups",
        alias = "tld_groups",
        alias = "groups",
        alias = "group",
        alias = "data",
        deserialize_with = "flexible_list"
    )]
    pub groups: Vec<TldGroup>,
    /// Every field this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl TldGroupList {
    /// Number of groups.
    ///
    /// ```
    /// use inwx_client::TldGroupList;
    /// assert_eq!(TldGroupList::default().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Whether the answer carries no group.
    ///
    /// ```
    /// use inwx_client::TldGroupList;
    /// assert!(TldGroupList::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Whether more groups exist than were parsed.
    ///
    /// ```
    /// use inwx_client::TldGroupList;
    ///
    /// let list: TldGroupList =
    ///     serde_json::from_str(r#"{"count":9,"tldGroup":[{"tldGroup":"ccTLDs"}]}"#)?;
    /// assert!(list.has_more());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.count
            .is_some_and(|count| i64::try_from(self.groups.len()).unwrap_or(i64::MAX) < count)
    }

    /// The group named `name`, compared case-insensitively.
    ///
    /// ```
    /// use inwx_client::TldGroupList;
    ///
    /// let list: TldGroupList = serde_json::from_str(r#"{"tldGroup":[{"tldGroup":"ccTLDs"}]}"#)?;
    /// assert!(list.find("CCTLDS").is_some());
    /// assert!(list.find("gTLDs").is_none());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&TldGroup> {
        let wanted = name.trim().to_ascii_lowercase();
        self.groups.iter().find(|group| {
            group
                .name
                .as_deref()
                .is_some_and(|name| name.trim().to_ascii_lowercase() == wanted)
        })
    }
}

/// A `TLD` as it goes on the wire: trimmed, punycoded, lower-cased, no dot.
///
/// # Errors
///
/// [`Error::Validation`] when the input is empty, holds control characters,
/// spans more than one label, or is not a valid DNS label.
fn normalize_tld(input: &str) -> Result<String> {
    let trimmed = input.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        return Err(Error::validation("tld", "must not be empty"));
    }
    reject_control_chars("tld", trimmed)?;
    // UTS-46 mapping: lower-casing, punycode and the checks a bare label needs.
    let ascii = idna::domain_to_ascii(trimmed)
        .map_err(|_| Error::validation("tld", format!("{trimmed:?} is not a valid TLD")))?;
    if ascii.contains('.') {
        return Err(Error::validation(
            "tld",
            format!("{input:?} is a domain name, not a TLD; pass the last label alone"),
        ));
    }
    validate_dns_name("tld", &ascii, false)?;
    Ok(ascii)
}

/// A key as it is compared: trimmed, lower-cased, without a leading dot.
fn normalize_key(input: &str) -> String {
    input.trim().trim_start_matches('.').to_ascii_lowercase()
}

/// `1`/`true`/`yes`/`on` and `0`/`false`/`no`/`off`, case-insensitively.
fn parse_flag(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Whether every key of the object is a decimal index — the shape INWX uses
/// when it turns a one-entry result set into an object (`{"0": {...}}`).
fn is_indexed_map(map: &Map<String, Value>) -> bool {
    !map.is_empty() && map.keys().all(|key| key.parse::<u64>().is_ok())
}

/// Rewrites a `resData` object so the list under `list_key` is an array.
///
/// Handles the three shapes INWX uses for a list: an array under the key, an
/// object whose keys are indices, and the list spread over the top level.
fn res_data_object(data: Value, list_key: &'static str) -> Value {
    match data {
        Value::Object(map) => {
            if is_indexed_map(&map) {
                let entries = indexed_entries(&map);
                let mut out = Map::new();
                out.insert(list_key.to_owned(), Value::Array(entries));
                Value::Object(out)
            } else {
                Value::Object(map)
            }
        }
        Value::Array(entries) => {
            let mut out = Map::new();
            out.insert(list_key.to_owned(), Value::Array(entries));
            Value::Object(out)
        }
        _ => Value::Object(Map::new()),
    }
}

/// The values of an indexed object, ordered by their numeric key.
fn indexed_entries(map: &Map<String, Value>) -> Vec<Value> {
    let mut keyed = map
        .iter()
        .filter_map(|(key, value)| key.parse::<u64>().ok().map(|index| (index, value.clone())))
        .collect::<Vec<_>>();
    // `Map` iteration order is insertion order, and `"10"` sorts before `"9"`
    // lexicographically — sort by the number instead.
    keyed.sort_by_key(|(index, _)| *index);
    keyed.into_iter().map(|(_, value)| value).collect()
}

/// A list that may be an array, an indexed object, a bare object or absent.
///
/// Entries that do not fit the target type are dropped rather than failing the
/// whole answer: one unexpected field must not hide the rest of a log.
fn flexible_list<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    let entries = match value {
        Value::Array(entries) => entries,
        Value::Object(map) if is_indexed_map(&map) => indexed_entries(&map),
        Value::Object(map) if map.is_empty() => Vec::new(),
        Value::Object(map) => vec![Value::Object(map)],
        _ => Vec::new(),
    };
    Ok(entries
        .into_iter()
        .filter_map(|entry| serde_json::from_value(entry).ok())
        .collect())
}

/// A field of an unknown-name map, compared case-insensitively.
fn lookup_value<'a>(map: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a Value> {
    let wanted = normalize_key(key);
    map.iter()
        .find(|(name, _)| normalize_key(name) == wanted)
        .map(|(_, value)| value)
}

/// A counter of an unknown-name map, from a number or a numeric string.
fn lookup_i64(map: &BTreeMap<String, Value>, key: &str) -> Option<i64> {
    match lookup_value(map, key)? {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// An amount of an unknown-name map, from a number or a numeric string.
fn lookup_f64(map: &BTreeMap<String, Value>, key: &str) -> Option<f64> {
    match lookup_value(map, key)? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Text of an unknown-name map. Anything that is not a string has no `&str`
/// to hand out, and `text_for` is for labels, so numbers count as no text.
fn lookup_str<'a>(map: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    match lookup_value(map, key)? {
        Value::String(text) => Some(text),
        Value::Bool(_) | Value::Null | Value::Array(_) | Value::Object(_) | Value::Number(_) => {
            None
        }
    }
}

impl<T: Transport> InwxClient<T> {
    /// Reads a domain's action log (`domain.log`).
    ///
    /// This is the "why was this rejected" endpoint: the entries carry the
    /// action, the account that ran it and the API's own explanation.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainLogQuery, DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let query = DomainLogQuery::new(DomainName::parse("example.com")?).with_page(1, 50)?;
    /// for entry in client.domain_log(&query).await?.entries {
    ///     println!("{:?} {:?}", entry.action, entry.text);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn domain_log(&self, query: &DomainLogQuery) -> Result<DomainLog> {
        let data = self.call("domain.log", query.params()).await?;
        serde_json::from_value(res_data_object(data, "logs")).map_err(Error::from)
    }

    /// Reads the domain counters of the account, or of one domain
    /// (`domain.stats`).
    ///
    /// Pass `None` for the account-wide counters.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{DomainName, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let stats = client.domain_stats(Some(&DomainName::parse("example.com")?)).await?;
    /// println!("{:?} entries", stats.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn domain_stats(&self, domain: Option<&DomainName>) -> Result<DomainStats> {
        let params =
            domain.map_or_else(|| json!({}), |domain| json!({ "domain": domain.as_str() }));
        let data = self.call("domain.stats", params).await?;
        serde_json::from_value(res_data_object(data, "stats")).map_err(Error::from)
    }

    /// Reads what one `TLD` requires (`domain.getRules`).
    ///
    /// The `TLD` is normalised before it is sent: trimmed, lower-cased,
    /// punycoded, with a leading dot removed. A `TLD` of more than 63 bytes, an
    /// empty one, and a value containing a dot are refused locally.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let rules = client.tld_rules("MUCHEN.DE").await?;
    /// for rule in rules.rules.iter().filter(|rule| rule.flag() == Some(true)) {
    ///     println!("{:?} required: {:?}", rule.name, rule.description);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is not a single valid `TLD` label,
    /// plus the usual transport and API errors.
    pub async fn tld_rules(&self, tld: &str) -> Result<TldRules> {
        let tld = normalize_tld(tld)?;
        let data = self.call("domain.getRules", json!({ "tld": tld })).await?;
        serde_json::from_value(res_data_object(data, "rules")).map_err(Error::from)
    }

    /// Lists the `TLD` groups of the account (`domain.getTldGroups`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for group in client.tld_groups().await?.groups {
    ///     println!("{:?}: {} TLDs", group.name, group.tld_count());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn tld_groups(&self) -> Result<TldGroupList> {
        let data = self.call("domain.getTldGroups", json!({})).await?;
        serde_json::from_value(res_data_object(data, "tldGroup")).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_LABEL_LEN;

    fn query() -> DomainLogQuery {
        DomainLogQuery::new(DomainName::parse("example.com").unwrap())
    }

    #[test]
    fn page_bound_accepts_the_limit_and_refuses_one_more() {
        // Just inside, just outside, and the zero below the range.
        assert!(query().with_page(1, 1).is_ok());
        assert!(query().with_page(1, MAX_PAGE_LIMIT).is_ok());
        assert!(query().with_page(1, MAX_PAGE_LIMIT + 1).is_err());
        assert!(query().with_page(1, 0).is_err());
        // The page number itself starts at 1.
        assert!(query().with_page(1, 10).is_ok());
        assert!(query().with_page(0, 10).is_err());
    }

    #[test]
    fn range_needs_a_positive_span() {
        let start = Timestamp::parse("2026-01-01T00:00:00").unwrap();
        let one_second_on = Timestamp::parse("2026-01-01T00:00:01").unwrap();
        let a_day_on = Timestamp::parse("2026-01-02T00:00:00").unwrap();
        // The smallest legal span, then the value just outside it.
        assert!(query().with_range(start.clone(), one_second_on).is_ok());
        assert!(query().with_range(start.clone(), start.clone()).is_err());
        assert!(query().with_range(a_day_on, start).is_err());
    }

    #[test]
    fn params_only_carry_what_was_set() {
        assert_eq!(query().params(), json!({"domain": "example.com"}));
        let full = query()
            .with_page(3, 20)
            .unwrap()
            .with_range(
                Timestamp::parse("2026-01-01T00:00:00").unwrap(),
                Timestamp::parse("2026-02-01T00:00:00").unwrap(),
            )
            .unwrap();
        assert_eq!(
            full.params(),
            json!({
                "domain": "example.com",
                "page": 3,
                "pagelimit": 20,
                "dateFrom": "2026-01-01T00:00:00",
                "dateTo": "2026-02-01T00:00:00",
            })
        );
        assert_eq!(full.domain().as_str(), "example.com");
    }

    #[test]
    fn log_list_accepts_arrays_and_indexed_objects() {
        let array: DomainLog =
            serde_json::from_str(r#"{"count":2,"logs":[{"action":"create"},{"action":"renew"}]}"#)
                .unwrap();
        assert_eq!(array.len(), 2);
        assert_eq!(array.entries[1].action.as_deref(), Some("renew"));

        // `{"0":..,"10":..}` is ordered by the number, not by the string.
        let indexed: DomainLog = serde_json::from_value(json!({
            "logs": {"0": {"action": "oldest"}, "10": {"action": "tenth"}, "2": {"action": "second"}},
            "page": 2,
        }))
        .unwrap();
        let actions: Vec<&str> = indexed
            .entries
            .iter()
            .filter_map(|entry| entry.action.as_deref())
            .collect();
        assert_eq!(actions, ["oldest", "second", "tenth"]);
        assert_eq!(indexed.extra["page"], json!(2));
    }

    #[test]
    fn log_list_tolerates_single_empty_and_broken_shapes() {
        let single: DomainLog = serde_json::from_str(r#"{"logs":{"action":"create"}}"#).unwrap();
        assert_eq!(single.len(), 1);

        let empty: DomainLog = serde_json::from_str(r#"{"logs":{}}"#).unwrap();
        assert!(empty.is_empty());

        let null: DomainLog = serde_json::from_str(r#"{"logs":null,"count":null}"#).unwrap();
        assert!(null.is_empty());
        assert!(null.count.is_none());

        // A string where a list belongs must not lose the rest of the answer.
        let garbage: DomainLog = serde_json::from_str(r#"{"count":7,"logs":"n/a"}"#).unwrap();
        assert!(garbage.is_empty());
        assert_eq!(garbage.count, Some(7));
        assert!(garbage.has_more());

        // One unusable entry does not hide its neighbours.
        let mixed: DomainLog =
            serde_json::from_str(r#"{"logs":[{"action":"create"},42,{"action":"renew"}]}"#)
                .unwrap();
        assert_eq!(mixed.len(), 2);
    }

    #[test]
    fn res_data_root_shapes_are_rewritten_onto_the_list_key() {
        assert_eq!(
            res_data_object(json!([{"action": "create"}]), "logs"),
            json!({"logs": [{"action": "create"}]})
        );
        assert_eq!(
            res_data_object(json!({"0": {"action": "create"}}), "logs"),
            json!({"logs": [{"action": "create"}]})
        );
        let plain = json!({"count": 1, "logs": [{"action": "create"}]});
        assert_eq!(res_data_object(plain.clone(), "logs"), plain);
        assert_eq!(res_data_object(json!("nope"), "logs"), json!({}));
        assert_eq!(res_data_object(Value::Null, "logs"), json!({}));
    }

    #[test]
    fn tld_normalisation_accepts_up_to_one_label() {
        assert_eq!(normalize_tld("MUCHEN").unwrap(), "muchen");
        assert_eq!(normalize_tld("  DE  ").unwrap(), "de");
        assert_eq!(normalize_tld(".de").unwrap(), "de");
        assert_eq!(normalize_tld("münchen").unwrap(), "xn--mnchen-3ya");

        let just_inside = "a".repeat(MAX_LABEL_LEN);
        let just_outside = "a".repeat(MAX_LABEL_LEN + 1);
        assert_eq!(normalize_tld(&just_inside).unwrap(), just_inside);
        assert!(normalize_tld(&just_outside).is_err());
    }

    #[test]
    fn tld_normalisation_refuses_what_the_api_would_refuse() {
        assert!(normalize_tld("").is_err());
        assert!(normalize_tld("   ").is_err());
        assert!(normalize_tld(".").is_err());
        assert!(normalize_tld("example.com").is_err());
        assert!(normalize_tld("-de").is_err());
        assert!(normalize_tld("d e").is_err());
        assert!(normalize_tld("de\r\nX-Injected: 1").is_err());
    }

    #[test]
    fn log_entry_timestamps_and_aliases() {
        let spaced: DomainLogEntry =
            serde_json::from_str(r#"{"date":"2026-10-26 08:00:00"}"#).unwrap();
        assert_eq!(
            spaced
                .occurred_at()
                .map(|at| at.as_str().to_owned())
                .as_deref(),
            Some("2026-10-26T08:00:00")
        );

        let unclear: DomainLogEntry = serde_json::from_str(r#"{"date":"last tuesday"}"#).unwrap();
        assert!(unclear.occurred_at().is_none());
        assert!(DomainLogEntry::default().occurred_at().is_none());

        let snake: DomainLogEntry = serde_json::from_value(json!({
            "actionDate": "2026-10-26T08:00:00",
            "action_name": "create",
            "ip_address": "203.0.113.7",
            "message": "owner denied the transfer",
            "unexpected": {"a": 1},
        }))
        .unwrap();
        assert_eq!(snake.action.as_deref(), Some("create"));
        assert_eq!(snake.ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(snake.text.as_deref(), Some("owner denied the transfer"));
        assert_eq!(snake.extra["unexpected"], json!({"a": 1}));
        assert!(snake.occurred_at().is_some());
    }

    #[test]
    fn flags_accept_every_documented_spelling() {
        for yes in ["1", "true", "TRUE", " yes ", "on"] {
            assert_eq!(parse_flag(yes), Some(true), "{yes:?}");
        }
        for no in ["0", "false", "No", "OFF "] {
            assert_eq!(parse_flag(no), Some(false), "{no:?}");
        }
        for unclear in ["", " ", "2", "-1", "maybe"] {
            assert_eq!(parse_flag(unclear), None, "{unclear:?}");
        }
    }

    #[test]
    fn stats_read_the_list_and_the_flat_answer() {
        let list: DomainStats = serde_json::from_str(
            r#"{"count":3,"stats":[{"domain":"DE","count":"12","amount":"108.5","description":"registered"}]}"#,
        )
        .unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.has_more());
        assert_eq!(list.find(".de").unwrap().count, Some(12));
        assert_eq!(list.counter("de"), Some(12));
        assert_eq!(list.amount_for("DE"), Some(108.5));
        assert_eq!(list.text_for(".de"), Some("registered"));
        assert!(list.find("com").is_none());
        assert_eq!(list.counter("com"), None);

        let flat: DomainStats = serde_json::from_str(
            r#"{"totalDomains":"12","totalAmount":108.5,"state":"active","flags":7}"#,
        )
        .unwrap();
        assert!(flat.is_empty());
        assert_eq!(flat.counter("totaldomains"), Some(12));
        assert_eq!(flat.amount_for("totalamount"), Some(108.5));
        assert_eq!(flat.text_for("state"), Some("active"));
        // A number carries no label, and must not be turned into one.
        assert_eq!(flat.text_for("flags"), None);
        assert_eq!(flat.counter("nope"), None);
    }

    #[test]
    fn rules_expose_values_types_and_unknown_fields() {
        let rules: TldRules = serde_json::from_str(
            r#"{"tld":"de","count":5,"rules":[
                 {"name":"BIRTH-ADDRESS-CITY","value":true,"type":"boolean","description":"City of birth"},
                 {"name":" MIN-PERIOD ","value":" 12 ","ruleType":"int"},
                 {"name":"FEE","value":"10.5"},
                 {"name":"WEIRD","value":"maybe","surprise":true},
                 {"name":"EMPTY"}]}"#,
        )
        .unwrap();
        assert_eq!(rules.tld.as_deref(), Some("de"));
        assert_eq!(rules.len(), 5);
        // A count equal to what was parsed means the answer is complete.
        assert!(!rules.has_more());
        assert_eq!(rules.value_for("birth-address-city"), Some("true"));
        assert_eq!(rules.find("BIRTH-ADDRESS-CITY").unwrap().flag(), Some(true));
        assert_eq!(
            rules
                .find("BIRTH-ADDRESS-CITY")
                .unwrap()
                .rule_type
                .as_deref(),
            Some("boolean")
        );
        assert_eq!(rules.integer_for("min-period"), Some(12));
        assert_eq!(rules.find("FEE").unwrap().number(), Some(10.5));
        assert_eq!(rules.find("WEIRD").unwrap().flag(), None);
        assert_eq!(rules.find("weird").unwrap().extra["surprise"], json!(true));
        assert_eq!(rules.find("EMPTY").unwrap().integer(), None);
        assert!(rules.value_for("NOPE").is_none());
        // One more than the parsed entries means more is out there.
        let mut incomplete = rules.clone();
        incomplete.count = Some(6);
        assert!(incomplete.has_more());
        assert_eq!(TldRules::default().len(), 0);
        assert!(TldRules::default().is_empty());
    }

    #[test]
    fn groups_hold_their_tlds_and_both_key_spellings() {
        let list: TldGroupList = serde_json::from_str(
            r#"{"count":2,"tldGroup":[
                 {"roId":1,"tldGroup":"ccTLDs","description":"country codes","tld":["de","at"]},
                 {"ro_id":2,"tld_group":"new gTLDs","tlds":"berlin"}]}"#,
        )
        .unwrap();
        assert_eq!(list.len(), 2);
        assert!(!list.has_more());

        let first = list.find("CCTLDS").unwrap();
        assert_eq!(first.id, Some(1));
        assert_eq!(first.description.as_deref(), Some("country codes"));
        assert_eq!(first.tld_count(), 2);
        assert!(first.contains(".DE"));
        assert!(!first.contains("com"));

        let second = list.find("new gTLDs").unwrap();
        assert_eq!(second.id, Some(2));
        assert_eq!(second.tld_count(), 1);
        assert!(second.contains("berlin"));

        assert!(TldGroup::default().is_empty());
        assert_eq!(TldGroup::default().tld_count(), 0);
        assert!(!TldGroup::default().contains("de"));
        assert!(TldGroupList::default().is_empty());
        assert_eq!(TldGroupList::default().len(), 0);
    }

    #[test]
    fn indexed_root_and_sparse_lists_still_decode() {
        let indexed = res_data_object(
            json!({"0": {"name": "MIN-PERIOD", "value": "1"}, "5": {"name": "MAX-PERIOD", "value": "10"}}),
            "rules",
        );
        let rules: TldRules = serde_json::from_value(indexed).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules.integer_for("MAX-PERIOD"), Some(10));

        // A hole in the indices is not an error.
        let sparse: TldRules = serde_json::from_value(json!({
            "rules": {"0": {"name": "A"}, "7": {"name": "B"}}
        }))
        .unwrap();
        assert_eq!(sparse.len(), 2);
    }
}
