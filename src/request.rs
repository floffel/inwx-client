//! Domain push requests (`request.*`): list, inspect, accept, deny, cancel.
//!
//! Pushing a domain hands it to another account, where it arrives as a pending
//! request that the receiving account has to answer. [`crate::InwxClient::push_domain`]
//! starts that flow; this module finishes it: [`InwxClient::list_requests`] and
//! [`InwxClient::request_info`] show what is waiting, and
//! [`InwxClient::accept_request`] / [`InwxClient::deny_request`] /
//! [`InwxClient::cancel_request`] answer it.
//!
//! The three answers are irreversible in the sense that matters here: a replay
//! after a timeout would move the domain twice, so they are classified as
//! mutating — a 5xx or a transport failure after the request was written is
//! [`Error::Uncertain`], never a second attempt. A
//! success that names no readable request is
//! [`Error::Ambiguous`] instead of a plain parse
//! failure, because the request was answered by then and listing the requests is
//! how a caller confirms the outcome.
//!
//! # What stayed unverified
//!
//! The public INWX documentation does not settle the wire shape of the
//! `request.*` namespace, so the request keys and the answer keys are derived
//! from the rest of the API and marked *unverified* in `docs/contracts.md`.
//! Every read field is optional and unknown values are carried, so a wrong
//! answer key costs a `None` instead of a failed parse; the request keys must be
//! checked against the live pages before the mutations are used in production.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::pagination::{self, Listing, Page, Pages, Pagination};
use crate::transport::Transport;
use crate::types::{de, validate_id};

/// The state of a push request. Unknown values are carried verbatim.
///
/// ```
/// use inwx_client::RequestState;
///
/// assert_eq!("pending".parse::<RequestState>()?, RequestState::Pending);
/// assert_eq!(RequestState::Accepted.to_string(), "ACCEPTED");
///
/// // A state INWX adds later still survives a round trip.
/// let future: RequestState = "SOMETHING_NEW".parse()?;
/// assert_eq!(future, RequestState::Other("SOMETHING_NEW".into()));
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestState {
    /// Waiting for an answer.
    Pending,
    /// Accepted; the domain moved to the target account.
    Accepted,
    /// Denied; the domain stays with the sender.
    Denied,
    /// Cancelled by the account that pushed the domain.
    Canceled,
    /// A state this crate does not know; carried verbatim, upper-cased.
    Other(String),
}

impl RequestState {
    /// Parses a request state, upper-casing it; unknown values become
    /// [`RequestState::Other`].
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the input is empty.
    ///
    /// ```
    /// use inwx_client::RequestState;
    ///
    /// assert_eq!(RequestState::parse("DENIED")?, RequestState::Denied);
    /// assert!(RequestState::parse("   ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let upper = input.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::validation("request.state", "must not be empty"));
        }
        Ok(match upper.as_str() {
            "PENDING" => Self::Pending,
            "ACCEPTED" => Self::Accepted,
            "DENIED" => Self::Denied,
            "CANCELED" | "CANCELLED" => Self::Canceled,
            _ => Self::Other(upper),
        })
    }

    /// Wire representation.
    ///
    /// ```
    /// use inwx_client::RequestState;
    ///
    /// assert_eq!(RequestState::Pending.as_str(), "PENDING");
    /// assert_eq!(RequestState::Other("NEW".into()).as_str(), "NEW");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pending => "PENDING",
            Self::Accepted => "ACCEPTED",
            Self::Denied => "DENIED",
            Self::Canceled => "CANCELED",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for RequestState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RequestState {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

impl Serialize for RequestState {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RequestState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// One push request, as listed by `request.list` or read by `request.info`.
///
/// Every field is optional and unknown fields are ignored, because the wire
/// shape of `request.*` is not settled by the public documentation. The
/// camelCase and `snake_case` spellings of a renamed field are both accepted
/// (`createdAt`/`created_at`, `requestType`/`request_type`, `domainName`/`domain`),
/// so a spelling that differs from the one modelled here costs a `None` rather
/// than the whole row.
///
/// ```
/// use inwx_client::{RequestEntry, RequestState};
///
/// let request: RequestEntry = serde_json::from_str(
///     r#"{"id":7,"domain":"example.com","state":"PENDING","type":"TRANSFER"}"#,
/// )?;
/// assert_eq!(request.id, Some(7));
/// assert_eq!(request.domain.as_deref(), Some("example.com"));
/// assert_eq!(request.state, Some(RequestState::Pending));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct RequestEntry {
    /// Request id, used by the other four methods.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Domain the request is about.
    #[serde(
        default,
        alias = "domainName",
        alias = "domain_name",
        deserialize_with = "de::opt_string"
    )]
    pub domain: Option<String>,
    /// Current state of the request.
    #[serde(default, alias = "status", deserialize_with = "opt_state")]
    pub state: Option<RequestState>,
    /// Request kind (`type`), carried verbatim.
    #[serde(
        default,
        rename = "type",
        alias = "kind",
        alias = "requestType",
        alias = "request_type",
        deserialize_with = "de::opt_string"
    )]
    pub request_type: Option<String>,
    /// Creation timestamp, as text.
    #[serde(
        default,
        alias = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created: Option<String>,
    /// Last-change timestamp, as text.
    #[serde(
        default,
        alias = "updatedAt",
        alias = "updated_at",
        alias = "changed",
        deserialize_with = "de::opt_string"
    )]
    pub updated: Option<String>,
    /// Human readable note the sender or the API attached.
    #[serde(
        default,
        alias = "msg",
        alias = "reason",
        deserialize_with = "de::opt_string"
    )]
    pub message: Option<String>,
    /// Account or handle that sent the request.
    #[serde(
        default,
        alias = "from",
        alias = "sender",
        deserialize_with = "de::opt_string"
    )]
    pub requester: Option<String>,
    /// Account or handle the request is aimed at.
    #[serde(
        default,
        alias = "to",
        alias = "recipient",
        deserialize_with = "de::opt_string"
    )]
    pub target: Option<String>,
}

/// One page of `request.list`.
///
/// The answer is read permissively, like every other list in this crate: a
/// single request object where the array belongs is a page of one, a row that
/// does not fit [`RequestEntry`] is skipped rather than costing the whole page,
/// and a `count` that is not a number leaves [`RequestListPage::count`] `None`.
///
/// ```
/// use inwx_client::RequestListPage;
///
/// let page: RequestListPage = serde_json::from_str(
///     r#"{"count":1,"requests":[{"id":7,"state":"PENDING"}]}"#,
/// )?;
/// assert_eq!(page.len(), 1);
/// assert_eq!(page.requests[0].id, Some(7));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct RequestListPage {
    /// Total number of requests matching the filter.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The requests on this page.
    #[serde(default, rename = "requests", deserialize_with = "de::rows")]
    pub requests: Vec<RequestEntry>,
}

impl RequestListPage {
    /// Number of requests on this page.
    ///
    /// ```
    /// use inwx_client::RequestListPage;
    ///
    /// let page: RequestListPage = serde_json::from_str(r#"{"requests":[]}"#)?;
    /// assert_eq!(page.len(), 0);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Whether this page carries no requests.
    ///
    /// ```
    /// use inwx_client::RequestListPage;
    ///
    /// assert!(RequestListPage::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Whether the listing continues past this page, comparing the page length
    /// to the reported `count`.
    ///
    /// It is `false` when the answer carries no `count`: a missing total is not
    /// evidence of more requests.
    ///
    /// ```
    /// use inwx_client::RequestListPage;
    ///
    /// let page: RequestListPage = serde_json::from_str(
    ///     r#"{"count":2,"requests":[{"id":7}]}"#,
    /// )?;
    /// assert!(page.has_more());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.count
            .is_some_and(|count| i64::try_from(self.requests.len()).unwrap_or(i64::MAX) < count)
    }
}

/// The page rules [`Pages`] needs to walk `request.list`.
///
/// ```
/// use inwx_client::{Page, RequestListPage};
///
/// let page: RequestListPage = serde_json::from_str(r#"{"requests":[{"id":7}]}"#)?;
/// assert_eq!(page.total(), None);
/// assert_eq!(page.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
impl Page for RequestListPage {
    type Item = RequestEntry;

    fn total(&self) -> Option<i64> {
        self.count
    }

    fn len(&self) -> usize {
        self.requests.len()
    }

    fn truncate_to(&mut self, len: usize) {
        self.requests.truncate(len);
    }

    fn into_items(self) -> Vec<RequestEntry> {
        self.requests
    }
}

/// The `request.list` command, ready to be walked page by page with [`Pages`].
///
/// ```
/// use inwx_client::{Listing, RequestListing};
///
/// assert_eq!(<RequestListing as Listing>::METHOD, "request.list");
/// assert_eq!(
///     RequestListing::new().params(2, 25),
///     serde_json::json!({"page": 2, "pagelimit": 25})
/// );
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestListing;

impl RequestListing {
    /// Every request of the account.
    ///
    /// ```
    /// use inwx_client::RequestListing;
    ///
    /// assert_eq!(RequestListing::new(), RequestListing);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Listing for RequestListing {
    type Page = RequestListPage;

    const METHOD: &'static str = "request.list";

    fn params(&self, page: u32, page_size: u32) -> Value {
        pagination::with_paging(json!({}), page, page_size)
    }
}

/// An optional [`RequestState`] from a string, number or boolean; empty, `null`
/// and unusable values become `None`.
fn opt_state<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<RequestState>, D::Error> {
    let raw = de::opt_string(deserializer)?;
    Ok(raw.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            RequestState::parse(trimmed).ok()
        }
    }))
}

/// The request object of an answer: nested under `request` when the API wraps
/// it, otherwise the `resData` value itself.
fn request_object(mut data: Value) -> Value {
    match data.get_mut("request") {
        Some(nested) if !nested.is_null() => nested.take(),
        _ => data,
    }
}

/// Reads the `request.info` answer, refusing an answer that names no request.
fn info_entry(data: Value) -> Result<RequestEntry> {
    let entry: RequestEntry = serde_json::from_value(request_object(data)).map_err(Error::from)?;
    if entry.id.is_none() && entry.domain.is_none() && entry.state.is_none() {
        return Err(Error::MissingField {
            method: "request.info",
            field: "resData.id",
        });
    }
    Ok(entry)
}

/// Reads the answer of an accept/deny/cancel mutation.
///
/// The mutation already ran, so an answer that carries no readable request is
/// [`Error::Ambiguous`] rather than a plain parse failure: listing the requests
/// is how a caller confirms the outcome. An answer that carries no request data
/// at all is still a confirmed success, reported as the id that was sent.
fn mutation_entry(method: &'static str, id: i64, data: Value) -> Result<RequestEntry> {
    let value = request_object(data);
    if value.is_null() {
        return Ok(RequestEntry {
            id: Some(id),
            ..RequestEntry::default()
        });
    }
    let mut entry: RequestEntry = serde_json::from_value(value).map_err(|error| {
        Error::ambiguous(
            method,
            "the answer carries no readable request; list the requests to confirm \
             the outcome before acting again",
        )
        .with_source(error)
    })?;
    if entry.id.is_none() {
        entry.id = Some(id);
    }
    Ok(entry)
}

impl<T: Transport> InwxClient<T> {
    /// Lists the account's push requests (`request.list`), first page.
    ///
    /// That page holds at most [`DEFAULT_PAGE_SIZE`](crate::DEFAULT_PAGE_SIZE)
    /// requests. Check [`RequestListPage::has_more`] before treating the page as
    /// the whole listing, or walk every page with
    /// [`InwxClient::list_all_requests`].
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for request in client.list_requests().await?.requests {
    ///     println!("{:?} {:?}", request.id, request.state);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_requests(&self) -> Result<RequestListPage> {
        self.list_requests_page(1, crate::DEFAULT_PAGE_SIZE).await
    }

    /// Lists one page of push requests (`request.list`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let page = client.list_requests_page(2, 25).await?;
    /// println!("{} of {:?}", page.requests.len(), page.count);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the page size is zero, plus the usual
    /// transport and API errors.
    pub async fn list_requests_page(&self, page: u32, limit: u32) -> Result<RequestListPage> {
        if limit == 0 {
            return Err(Error::validation("pagelimit", "must be at least 1"));
        }
        let data = self
            .call(
                "request.list",
                json!({ "page": page.max(1), "pagelimit": limit }),
            )
            .await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Walks every page of the account's push requests (`request.list`).
    ///
    /// The bound in `pagination` decides how far the walk goes, and it is
    /// checked before the first request.
    ///
    /// ```
    /// # use inwx_client::{
    /// #     InwxClient, Pagination, RequestListing, Result,
    /// #     transport::{Request, Response, Transport},
    /// # };
    /// # use std::sync::{Arc, Mutex};
    /// #[derive(Clone)]
    /// struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    ///
    /// impl Transport for Scripted {
    ///     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    ///         let body = self.0.lock().unwrap().remove(0);
    ///         Response::new(200, std::iter::empty(), body.as_bytes().to_vec())
    ///     }
    /// }
    ///
    /// # async fn demo() -> Result<Vec<i64>> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"requests":[{"id":1},{"id":2}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"requests":[{"id":3}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let ids = client
    ///     .list_all_requests(&RequestListing::new(), &Pagination::new().with_page_size(2)?)
    ///     .collect_all()
    ///     .await?
    ///     .iter()
    ///     .filter_map(|request| request.id)
    ///     .collect();
    /// # Ok(ids)
    /// # }
    /// # assert_eq!(
    /// #     tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap(),
    /// #     [1, 2, 3]
    /// # );
    /// ```
    ///
    /// # Errors
    ///
    /// The bound is validated when it is built (see
    /// [`Pagination::with_page_size`]); the walk itself reports the usual
    /// transport and API errors.
    pub fn list_all_requests(
        &self,
        listing: &RequestListing,
        pagination: &Pagination,
    ) -> Pages<'_, T, RequestListing> {
        Pages::new(self, listing.clone(), *pagination)
    }

    /// Reads one push request (`request.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// println!("{:?}", client.request_info(7).await?.state);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, [`Error::MissingField`] when
    /// the answer names no request, plus the usual transport and API errors.
    pub async fn request_info(&self, id: i64) -> Result<RequestEntry> {
        let id = validate_id("request.id", id)?;
        let data = self.call("request.info", json!({ "id": id })).await?;
        info_entry(data)
    }

    /// Accepts a push request (`request.accept`).
    ///
    /// The command is non-idempotent: it moves the domain. A 5xx or a transport
    /// failure after the request was written is [`Error::Uncertain`], and a
    /// success whose answer carries no readable request is
    /// [`Error::Ambiguous`]; neither is replayed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.accept_request(7).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id,
    /// [`Error::Uncertain`] after a 5xx or a timeout,
    /// [`Error::Ambiguous`] when a success names no readable request, plus the
    /// usual API errors.
    pub async fn accept_request(&self, id: i64) -> Result<RequestEntry> {
        let id = validate_id("request.id", id)?;
        let data = self.call("request.accept", json!({ "id": id })).await?;
        mutation_entry("request.accept", id, data)
    }

    /// Denies a push request (`request.deny`).
    ///
    /// The command is non-idempotent and is never replayed; see
    /// [`InwxClient::accept_request`] for the certainty rules.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.deny_request(7).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id,
    /// [`Error::Uncertain`] after a 5xx or a timeout,
    /// [`Error::Ambiguous`] when a success names no readable request, plus the
    /// usual API errors.
    pub async fn deny_request(&self, id: i64) -> Result<RequestEntry> {
        let id = validate_id("request.id", id)?;
        let data = self.call("request.deny", json!({ "id": id })).await?;
        mutation_entry("request.deny", id, data)
    }

    /// Cancels a push request (`request.cancel`).
    ///
    /// The command is non-idempotent and is never replayed; see
    /// [`InwxClient::accept_request`] for the certainty rules.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.cancel_request(7).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id,
    /// [`Error::Uncertain`] after a 5xx or a timeout,
    /// [`Error::Ambiguous`] when a success names no readable request, plus the
    /// usual API errors.
    pub async fn cancel_request(&self, id: i64) -> Result<RequestEntry> {
        let id = validate_id("request.id", id)?;
        let data = self.call("request.cancel", json!({ "id": id })).await?;
        mutation_entry("request.cancel", id, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_round_trip_and_carry_unknown_values() {
        for (text, expected) in [
            ("pending", RequestState::Pending),
            ("ACCEPTED", RequestState::Accepted),
            (" denied ", RequestState::Denied),
            ("Cancelled", RequestState::Canceled),
            ("CANCELED", RequestState::Canceled),
        ] {
            assert_eq!(RequestState::parse(text).unwrap(), expected);
            assert_eq!(expected.to_string(), expected.as_str());
        }
        assert_eq!(
            RequestState::parse("FUTURE").unwrap(),
            RequestState::Other("FUTURE".into())
        );
        assert!(RequestState::parse("   ").is_err());
    }

    #[test]
    fn an_entry_tolerates_missing_fields_and_other_spellings() {
        let entry: RequestEntry = serde_json::from_str(
            r#"{"id":"7","domainName":"example.com","status":"FUTURE","kind":"PUSH"}"#,
        )
        .unwrap();
        assert_eq!(entry.id, Some(7));
        assert_eq!(entry.domain.as_deref(), Some("example.com"));
        assert_eq!(entry.state, Some(RequestState::Other("FUTURE".into())));
        assert_eq!(entry.request_type.as_deref(), Some("PUSH"));

        let empty: RequestEntry = serde_json::from_str(r#"{"unknown":1}"#).unwrap();
        assert_eq!(empty, RequestEntry::default());
    }

    #[test]
    fn a_list_page_tolerates_a_single_object_and_skips_bad_rows() {
        let single: RequestListPage =
            serde_json::from_str(r#"{"count":1,"requests":{"id":7}}"#).unwrap();
        assert_eq!(single.len(), 1);

        let mixed: RequestListPage =
            serde_json::from_str(r#"{"count":2,"requests":[{"id":1},null]}"#).unwrap();
        assert_eq!(mixed.len(), 1);

        let empty: RequestListPage = serde_json::from_str(r#"{"requests":null}"#).unwrap();
        assert!(empty.is_empty());
        assert!(!empty.has_more());
    }

    #[test]
    fn a_mutation_answer_without_data_names_the_id_it_acted_on() {
        let entry = mutation_entry("request.accept", 7, Value::Null).unwrap();
        assert_eq!(entry.id, Some(7));
        assert_eq!(entry.state, None);
    }

    #[test]
    fn a_mutation_answer_that_names_no_readable_request_is_ambiguous() {
        let error = mutation_entry("request.accept", 7, Value::String("nope".into())).unwrap_err();
        assert!(matches!(error, Error::Ambiguous { .. }), "{error:?}");
        assert!(error.is_uncertain());
        assert!(!error.is_retryable());
    }
}
