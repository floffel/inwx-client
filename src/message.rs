//! Account messages (`message.*`): the mailbox INWX keeps for a reseller.
//!
//! Two methods: poll the next message and acknowledge it. An acknowledged
//! message is gone from the queue; an unacknowledged one comes back on the next
//! poll, so a worker that processes a message must acknowledge it — and only
//! then.
//!
//! ```
//! use inwx_client::Message;
//!
//! let message: Message = serde_json::from_str(
//!     r#"{"id":12,"type":"DOMAIN","title":"Domain ready","message":"example.com is active"}"#,
//! )?;
//! assert_eq!(message.id, Some(12));
//! assert_eq!(message.title.as_deref(), Some("Domain ready"));
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, validate_id, validate_upper_token};

/// Longest state token this crate accepts for a message.
const MAX_STATE_LEN: usize = 64;

/// One message from the account mailbox.
///
/// ```
/// use inwx_client::Message;
///
/// let message: Message = serde_json::from_str(
///     r#"{"id":"12","type":"DOMAIN","date":"2026-03-01 10:00:00","title":"Ready",
///         "message":"example.com is active","objectId":98765}"#,
/// )?;
/// assert_eq!(message.id, Some(12));
/// assert_eq!(message.object_id, Some(98765));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Message {
    /// Message id, the handle `message.ack` needs.
    #[serde(
        default,
        rename = "messageId",
        alias = "id",
        deserialize_with = "de::opt_i64"
    )]
    pub id: Option<i64>,
    /// Message class, carried verbatim (`DOMAIN`, `CUSTOMER`, …).
    #[serde(default, rename = "type", deserialize_with = "de::opt_string")]
    pub message_type: Option<String>,
    /// Short subject line.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub title: Option<String>,
    /// Message body.
    #[serde(
        default,
        rename = "message",
        alias = "text",
        deserialize_with = "de::opt_string"
    )]
    pub body: Option<String>,
    /// Date, as text.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub date: Option<String>,
    /// Object the message is about (a domain id, a customer number, …).
    #[serde(
        default,
        rename = "objectId",
        alias = "object_id",
        deserialize_with = "de::opt_i64"
    )]
    pub object_id: Option<i64>,
    /// Domain the message is about, when it names one.
    #[serde(
        default,
        rename = "domainName",
        alias = "domain",
        deserialize_with = "de::opt_string"
    )]
    pub domain: Option<String>,
    /// Machine readable payload, when the API sends one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub xml: Option<String>,
}

impl Message {
    /// The id to acknowledge, when the answer carried one.
    ///
    /// ```
    /// use inwx_client::Message;
    ///
    /// let message: Message = serde_json::from_str(r#"{"id":7}"#)?;
    /// assert_eq!(message.message_id().ok(), Some(7));
    /// assert!(Message::default().message_id().is_err());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the API did not send an id.
    pub fn message_id(&self) -> Result<i64> {
        self.id.ok_or(Error::MissingField {
            method: "message.poll",
            field: "id",
        })
    }
}

/// The `message.ack` request: which message, and how it ended.
///
/// ```
/// use inwx_client::MessageAck;
///
/// let ack = MessageAck::new(12)?.with_state("processed")?;
/// let params = ack.params()?;
/// assert_eq!(params["messageId"], 12);
/// assert_eq!(params["state"], "PROCESSED");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAck {
    message_id: i64,
    state: Option<String>,
}

impl MessageAck {
    /// Acknowledges the message with `message_id`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive message id.
    ///
    /// ```
    /// use inwx_client::MessageAck;
    ///
    /// assert!(MessageAck::new(1).is_ok());
    /// assert!(MessageAck::new(0).is_err());
    /// ```
    pub fn new(message_id: i64) -> Result<Self> {
        Ok(Self {
            message_id: validate_id("message.id", message_id)?,
            state: None,
        })
    }

    /// Reports how processing ended (`state`, upper-cased and carried verbatim).
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oddly shaped state token.
    ///
    /// ```
    /// use inwx_client::MessageAck;
    ///
    /// let ack = MessageAck::new(1)?.with_state("processed")?;
    /// assert_eq!(ack.params()?["state"], "PROCESSED");
    /// assert!(MessageAck::new(1)?.with_state(" ").is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn with_state(mut self, state: impl Into<String>) -> Result<Self> {
        self.state = Some(validate_upper_token(
            "message.state",
            &state.into(),
            MAX_STATE_LEN,
        )?);
        Ok(self)
    }

    /// The `message.ack` parameters.
    ///
    /// # Errors
    ///
    /// Never fails today: every value is validated when it is set, so the
    /// parameters are always sendable. The `Result` keeps the shape of the
    /// builders that can refuse a value.
    ///
    /// ```
    /// use inwx_client::MessageAck;
    /// assert_eq!(MessageAck::new(3)?.params()?["messageId"], 3);
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn params(&self) -> Result<Value> {
        let mut params = serde_json::Map::new();
        params.insert("messageId".to_owned(), json!(self.message_id));
        if let Some(state) = &self.state {
            params.insert("state".to_owned(), json!(state));
        }
        Ok(Value::Object(params))
    }
}

/// One message from the mailbox, or `None` when it is empty.
///
/// A flat answer is read by the same keys [`Message`] decodes, so the
/// documented `messageId` spelling counts as well as `id`; an answer that
/// counts a message without carrying one is refused instead of being reported
/// as an empty mailbox.
///
/// ```
/// use inwx_client::PolledMessage;
///
/// let empty: PolledMessage = serde_json::from_str(r#"{"count":0}"#)?;
/// assert!(empty.message.is_none());
///
/// let one: PolledMessage = serde_json::from_str(r#"{"messageId":3,"title":"Ready"}"#)?;
/// assert_eq!(one.message.as_ref().and_then(|m| m.id), Some(3));
///
/// let lost: Result<PolledMessage, _> = serde_json::from_str(r#"{"count":2}"#);
/// assert!(lost.is_err());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolledMessage {
    /// Number of messages still waiting, when the API reports it.
    pub count: Option<i64>,
    /// The message itself; `None` for an empty mailbox.
    pub message: Option<Message>,
}

impl PolledMessage {
    /// The id to acknowledge, when a message was polled.
    ///
    /// ```
    /// use inwx_client::PolledMessage;
    ///
    /// let polled: PolledMessage = serde_json::from_str(r#"{"id":3}"#)?;
    /// assert_eq!(polled.message_id().ok(), Some(3));
    /// assert!(PolledMessage::default().message_id().is_err());
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the mailbox was empty.
    pub fn message_id(&self) -> Result<i64> {
        self.message
            .as_ref()
            .ok_or(Error::MissingField {
                method: "message.poll",
                field: "id",
            })?
            .message_id()
    }
}

/// Reads a `message.poll` answer.
///
/// INWX sends the message either flat in `resData` or nested under `message`,
/// and an empty mailbox as an empty object; all three shapes are accepted. A
/// message is recognised by the keys [`Message`] itself decodes — a nested
/// `message` object, or a flat `messageId`/`id` — so the spelling the struct
/// and the API documentation use is never missed.
///
/// A `count` that promises a message the answer does not carry is an
/// [`Error::UnexpectedAnswer`], not an empty mailbox: the message would stay
/// unacknowledged in the queue forever, because every caller skips a `None` and
/// only the discarded `count` remembered it. Two shapes that name different
/// messages are refused for the same reason — one of them would be dropped
/// silently.
fn poll_from(data: &Value) -> Result<PolledMessage> {
    let count = data.get("count").and_then(crate::types::opt_i64_value);
    let nested = data.get("message").filter(|node| node.is_object());
    let flat_id = data.get("messageId").or_else(|| data.get("id"));
    let raw = match (nested, flat_id) {
        (Some(nested), Some(flat_id)) => {
            // Both shapes in one answer: accepted only while they agree, so a
            // message id that disagrees can never be picked by accident.
            let nested_id = nested
                .get("messageId")
                .or_else(|| nested.get("id"))
                .and_then(crate::types::opt_i64_value);
            if nested_id != crate::types::opt_i64_value(flat_id) {
                return Err(Error::unexpected_answer(
                    "message.poll",
                    "message",
                    "the nested `message` and the flat `messageId`/`id` name different messages",
                ));
            }
            Some(nested.clone())
        }
        (Some(nested), None) => Some(nested.clone()),
        (None, Some(_)) => Some(data.clone()),
        (None, None) => {
            if matches!(count, Some(waiting) if waiting > 0) {
                return Err(Error::unexpected_answer(
                    "message.poll",
                    "message",
                    "the answer counts waiting messages but carries neither a `message` object \
                     nor a `messageId`/`id`",
                ));
            }
            None
        }
    };
    let message = raw
        .map(|body| serde_json::from_value::<Message>(body).map_err(Error::from))
        .transpose()?;
    Ok(PolledMessage { count, message })
}

/// Accepts every shape `message.poll` is documented to answer with.
impl<'de> Deserialize<'de> for PolledMessage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let data = Value::deserialize(deserializer)?;
        poll_from(&data).map_err(D::Error::custom)
    }
}

impl<T: Transport> InwxClient<T> {
    /// Reads the next message from the mailbox (`message.poll`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, MessageAck, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// if let Some(message) = client.poll_message().await?.message {
    ///     println!("{:?}", message.title);
    ///     client.ack_message(&MessageAck::new(message.message_id()?)?).await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the answer does not fit the model,
    /// [`Error::UnexpectedAnswer`] when it counts a waiting message but carries
    /// none, plus the usual transport and API errors.
    pub async fn poll_message(&self) -> Result<PolledMessage> {
        let data = self.call("message.poll", json!({})).await?;
        // Not through the `Deserialize` impl: that one can only report a serde
        // error, and a counted answer without a message has to surface as the
        // typed [`Error::UnexpectedAnswer`] a caller can match on.
        poll_from(&data)
    }

    /// Acknowledges a message and removes it from the queue (`message.ack`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, MessageAck, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.ack_message(&MessageAck::new(12)?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive message id, plus the usual
    /// transport and API errors.
    pub async fn ack_message(&self, ack: &MessageAck) -> Result<()> {
        let params = ack.params()?;
        self.call("message.ack", params).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_must_be_positive() {
        assert!(MessageAck::new(1).is_ok());
        assert!(MessageAck::new(0).is_err());
        assert!(MessageAck::new(-5).is_err());
    }

    #[test]
    fn a_state_token_of_64_characters_is_accepted_and_65_is_not() {
        let ok = "S".repeat(64);
        assert!(MessageAck::new(1).unwrap().with_state(&ok).is_ok());
        assert!(MessageAck::new(1)
            .unwrap()
            .with_state(format!("{ok}S"))
            .is_err());
    }

    #[test]
    fn an_empty_mailbox_is_not_an_error() {
        let polled: PolledMessage =
            serde_json::from_value(Value::Object(serde_json::Map::new())).unwrap();
        assert!(polled.message.is_none());
        assert!(polled.message_id().is_err());
    }

    #[test]
    fn both_message_shapes_are_accepted() {
        let flat: PolledMessage =
            serde_json::from_value(json!({"id": "4", "title": "Ready"})).unwrap();
        let nested: PolledMessage =
            serde_json::from_value(json!({"count": 2, "message": {"id": 4, "title": "Ready"}}))
                .unwrap();
        assert_eq!(flat.message, nested.message);
        assert_eq!(nested.count, Some(2));
        assert_eq!(flat.message_id().unwrap(), 4);
    }

    #[test]
    fn a_flat_answer_spelled_message_id_is_read() {
        let polled: PolledMessage =
            serde_json::from_value(json!({"messageId": 12, "title": "Ready"})).unwrap();
        assert_eq!(polled.message_id().unwrap(), 12);
        assert_eq!(
            polled.message.as_ref().and_then(|m| m.title.as_deref()),
            Some("Ready")
        );
        // The alias `id` is the just-inside neighbour of the same shape.
        let alias: PolledMessage = serde_json::from_value(json!({"id": 12})).unwrap();
        assert_eq!(alias.message_id().unwrap(), 12);
    }

    #[test]
    fn a_null_message_does_not_hide_a_flat_id() {
        let polled: PolledMessage = serde_json::from_value(json!({
            "count": 1,
            "message": Value::Null,
            "messageId": 7,
        }))
        .unwrap();
        assert_eq!(polled.count, Some(1));
        assert_eq!(polled.message_id().unwrap(), 7);
    }

    #[test]
    fn a_counted_answer_without_a_message_is_refused() {
        let err = serde_json::from_value::<PolledMessage>(json!({"count": 1})).unwrap_err();
        assert!(err.to_string().contains("unexpected `message`"), "{err}");
        // Just inside: a count of zero is an empty mailbox, not an error.
        let empty: PolledMessage = serde_json::from_value(json!({"count": 0})).unwrap();
        assert_eq!(empty.count, Some(0));
        assert!(empty.message.is_none());
    }

    #[test]
    fn two_shapes_may_repeat_one_id_but_not_disagree() {
        let agreeing: PolledMessage = serde_json::from_value(json!({
            "count": 1,
            "messageId": 4,
            "message": {"messageId": "4", "title": "Ready"},
        }))
        .unwrap();
        assert_eq!(agreeing.message_id().unwrap(), 4);

        let against = serde_json::from_value::<PolledMessage>(json!({
            "message": {"id": 4},
            "messageId": 5,
        }))
        .unwrap_err();
        assert!(
            against.to_string().contains("name different messages"),
            "{against}"
        );

        // A nested message without an id cannot be reconciled with a flat one.
        let half = serde_json::from_value::<PolledMessage>(json!({
            "message": {"title": "Ready"},
            "id": 5,
        }));
        assert!(half.is_err());
    }

    #[test]
    fn a_message_carries_unknown_types() {
        let message: Message = serde_json::from_str(r#"{"type":"SOMETHING_NEW"}"#).unwrap();
        assert_eq!(message.message_type.as_deref(), Some("SOMETHING_NEW"));
    }
}
