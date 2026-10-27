//! Messages (`message.*`): INWX's notification queue for a reseller account.
//!
//! INWX pushes events (a domain expired, a transfer needs an answer, an
//! order finished) into a queue. `message.poll` reads the queue, `message.ack`
//! confirms one entry so it is not delivered again.
//!
//! The object is described in the API documentation chapter 2 §2.14. The
//! payload of a message depends on its type, so it stays a [`Value`] in
//! [`Message::content`] and every unmodelled field survives in
//! [`Message::rest`].
//!
//! ```
//! use inwx_client::Message;
//!
//! let message: Message = serde_json::from_str(
//!     r#"{"id":912,"type":"DOMAIN","handler":"module.domain.expire","content":{"domain":"example.com"}}"#,
//! )?;
//! assert_eq!(message.id, Some(912));
//! assert_eq!(message.message_type.as_deref(), Some("DOMAIN"));
//! assert_eq!(message.content["domain"], "example.com");
//! # Ok::<(), serde_json::Error>(())
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::params;
use crate::transport::Transport;
use crate::types::de;

/// One entry of the notification queue.
///
/// ```
/// use inwx_client::Message;
///
/// let camel: Message =
///     serde_json::from_str(r#"{"id":"912","messageType":"EXPIRE","createdAt":"2026-10-01"}"#)?;
/// let snake: Message =
///     serde_json::from_str(r#"{"id":912,"message_type":"EXPIRE","created_at":"2026-10-01"}"#)?;
/// assert_eq!(camel, snake);
/// assert_eq!(camel.message_type.as_deref(), Some("EXPIRE"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Message {
    /// Message id, the argument of `message.ack`.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Message type, for example `DOMAIN` or `EXPIRE`.
    #[serde(
        default,
        rename = "messageType",
        alias = "message_type",
        alias = "type",
        deserialize_with = "de::opt_string"
    )]
    pub message_type: Option<String>,
    /// Code that would handle the message.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub handler: Option<String>,
    /// State of the entry, when the API reports one.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub state: Option<String>,
    /// Payload of the message, whose shape depends on the type.
    #[serde(default)]
    pub content: Value,
    /// Creation timestamp.
    #[serde(
        default,
        rename = "createdAt",
        alias = "created_at",
        deserialize_with = "de::opt_string"
    )]
    pub created_at: Option<String>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl Message {
    /// The id, or a validation error explaining what was missing.
    ///
    /// A queue entry without an id cannot be acknowledged, and reporting that
    /// here beats sending `message.ack` with a null id.
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the API sent no id.
    ///
    /// ```
    /// use inwx_client::Message;
    ///
    /// let message: Message = serde_json::from_str(r#"{"id":912}"#)?;
    /// assert_eq!(message.required_id()?, 912);
    ///
    /// let broken: Message = serde_json::from_str(r#"{"type":"DOMAIN"}"#)?;
    /// assert!(broken.required_id().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    pub fn required_id(&self) -> Result<i64> {
        self.id.ok_or(Error::MissingField {
            method: "message.poll",
            field: "id",
        })
    }
}

/// The answer to `message.poll`.
///
/// ```
/// use inwx_client::MessageQueue;
///
/// let queue: MessageQueue = serde_json::from_str(
///     r#"{"count":2,"message":[{"id":1,"type":"DOMAIN"},{"id":2,"type":"EXPIRE"}]}"#,
/// )?;
/// assert_eq!(queue.count, Some(2));
/// assert_eq!(queue.len(), 2);
/// assert_eq!(queue.ids(), vec![1, 2]);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct MessageQueue {
    /// Number of pending messages, as the API reported it.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The pending messages.
    #[serde(default, rename = "message", alias = "messages")]
    pub messages: Vec<Message>,
    /// Fields this crate does not model, kept verbatim.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

impl MessageQueue {
    /// Number of messages in this answer.
    ///
    /// ```
    /// use inwx_client::MessageQueue;
    /// let queue: MessageQueue = serde_json::from_str(r#"{"message":[{"id":1}]}"#)?;
    /// assert_eq!(queue.len(), 1);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the queue is empty.
    ///
    /// ```
    /// use inwx_client::MessageQueue;
    /// assert!(MessageQueue::default().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// The ids of the pending messages, skipping entries without one.
    ///
    /// ```
    /// use inwx_client::MessageQueue;
    /// let queue: MessageQueue = serde_json::from_str(r#"{"message":[{"id":1},{}]}"#)?;
    /// assert_eq!(queue.ids(), vec![1]);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn ids(&self) -> Vec<i64> {
        self.messages
            .iter()
            .filter_map(|message| message.id)
            .collect()
    }
}

impl<T: Transport> InwxClient<T> {
    /// Reads the notification queue (`message.poll`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let queue = client.poll_messages().await?;
    /// for message in &queue.messages {
    ///     println!("{:?} {:?}", message.message_type, message.content);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn poll_messages(&self) -> Result<MessageQueue> {
        let data = self.call("message.poll", json!({})).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Confirms one message so it is not delivered again (`message.ack`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.ack_message(912).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-positive id, plus the usual transport and
    /// API errors.
    pub async fn ack_message(&self, message_id: i64) -> Result<()> {
        let id = params::object_id("messageId", message_id)?;
        self.call("message.ack", json!({ "messageId": id })).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_stop_at_zero() {
        assert!(params::object_id("messageId", 1).is_ok());
        assert!(params::object_id("messageId", 0).is_err());
        assert!(params::object_id("messageId", -1).is_err());
    }

    #[test]
    fn a_missing_id_is_reported_not_guessed() {
        let message: Message = serde_json::from_str(r#"{"id":"912"}"#).unwrap();
        assert_eq!(message.required_id().unwrap(), 912);

        let message = Message::default();
        assert!(matches!(
            message.required_id(),
            Err(Error::MissingField { .. })
        ));
    }

    #[test]
    fn the_queue_accepts_both_spellings_and_keeps_the_payload() {
        let singular: MessageQueue =
            serde_json::from_str(r#"{"message":[{"id":1,"content":{"a":1}}]}"#).unwrap();
        let plural: MessageQueue =
            serde_json::from_str(r#"{"messages":[{"id":1,"content":{"a":1}}]}"#).unwrap();
        assert_eq!(singular, plural);
        assert_eq!(singular.messages[0].content["a"], 1);
        assert_eq!(singular.ids(), vec![1]);
        assert!(MessageQueue::default().is_empty());
    }
}
