//! Contact handles (`contact.*`): the people and organisations behind domains.
//!
//! INWX wants handles, not inline addresses: you create a handle once, then
//! attach it to a domain as registrant, admin, tech or billing. Validation here
//! mirrors the documented field types (`text64` street, `text10` postcode,
//! `email`, two-letter country) so a rejected handle is a local error: the
//! country is looked up in the `celes` ISO 3166-1 table and the address is
//! checked against `garde`'s RFC 5321 shape, never against a local guess.
//!
//! `contact.create` and `contact.update` write the same fields, so both check
//! the lengths against the one table in `TEXT_FIELDS`: a limit that holds on
//! the way in but not on the way of a change is not a limit.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::pagination::{self, Listing, Page, Pages, Pagination};
use crate::transport::Transport;
use crate::types::{
    de, pick_i64, reject_control_chars, validate_country_code, validate_email_field, ContactType,
};

/// A contact handle to create (`contact.create`).
///
/// The API requires type, name, street, city, postcode, country, voice and
/// email; the rest is optional. [`ContactRequest::params`] enforces exactly
/// that.
///
/// ```
/// use inwx_client::{ContactRequest, ContactType};
///
/// let request = ContactRequest::new(ContactType::Person, "Erika Mustermann", "erika@example.com")?
///     .with_street("Musterstraße 1")
///     .with_city("München")
///     .with_postcode("80331")
///     .with_country("DE")
///     .with_voice("+49.8912345678");
///
/// let params = request.params();
/// assert_eq!(params["type"], "PERSON");
/// assert_eq!(params["cc"], "DE");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRequest {
    contact_type: ContactType,
    name: String,
    org: Option<String>,
    street: Option<String>,
    city: Option<String>,
    postcode: Option<String>,
    state: Option<String>,
    country: Option<String>,
    voice: Option<String>,
    fax: Option<String>,
    email: String,
    remarks: Option<String>,
}

impl ContactRequest {
    /// A handle with the two fields that cannot be defaulted: the name and the
    /// email address.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is empty or longer than 255
    /// characters, or the email is not a plausible address.
    pub fn new(
        contact_type: ContactType,
        name: impl Into<String>,
        email: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        let email = email.into();
        check_name_not_blank(&name)?;
        check_len("contact.name", &name, 255)?;
        let email = validate_email_field("contact.email", &email)?;
        Ok(Self {
            contact_type,
            name,
            org: None,
            street: None,
            city: None,
            postcode: None,
            state: None,
            country: None,
            voice: None,
            fax: None,
            email,
            remarks: None,
        })
    }

    /// Sets the organisation (`ORG` handles need it).
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Org, "ACME", "ops@acme.test")?.with_org("ACME GmbH");
    /// assert_eq!(request.params()["org"], "ACME GmbH");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_org(mut self, org: impl Into<String>) -> Self {
        self.org = Some(org.into());
        self
    }

    /// Sets the street address.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_street("Weg 2");
    /// assert_eq!(request.params()["street"], "Weg 2");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_street(mut self, street: impl Into<String>) -> Self {
        self.street = Some(street.into());
        self
    }

    /// Sets the city.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_city("Berlin");
    /// assert_eq!(request.params()["city"], "Berlin");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_city(mut self, city: impl Into<String>) -> Self {
        self.city = Some(city.into());
        self
    }

    /// Sets the postal code (`text10`).
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_postcode("10115");
    /// assert_eq!(request.params()["pc"], "10115");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_postcode(mut self, postcode: impl Into<String>) -> Self {
        self.postcode = Some(postcode.into());
        self
    }

    /// Sets the state or province.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_state("BY");
    /// assert_eq!(request.params()["sp"], "BY");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Sets the two-letter ISO 3166-1 country code.
    ///
    /// The code is upper-cased here, so the value that is checked is the value
    /// that is sent; whether it is a country at all is decided by
    /// [`ContactRequest::validate`] against the ISO table, which knows that
    /// `ZZ` is not one.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_country("at");
    /// assert_eq!(request.params()["cc"], "AT");
    ///
    /// let unknown = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_country("ZZ");
    /// assert!(unknown.validate().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        let country = country.into();
        self.country = Some(country.trim().to_ascii_uppercase());
        self
    }

    /// Sets the phone number in international format (`+49.8912345678`).
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_voice("+49.891");
    /// assert_eq!(request.params()["voice"], "+49.891");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_voice(mut self, voice: impl Into<String>) -> Self {
        self.voice = Some(voice.into());
        self
    }

    /// Sets the fax number.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_fax("+49.892");
    /// assert_eq!(request.params()["fax"], "+49.892");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_fax(mut self, fax: impl Into<String>) -> Self {
        self.fax = Some(fax.into());
        self
    }

    /// Sets the remarks the registrar may show.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_remarks("night only");
    /// assert_eq!(request.params()["remarks"], "night only");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_remarks(mut self, remarks: impl Into<String>) -> Self {
        self.remarks = Some(remarks.into());
        self
    }

    /// The `contact.create` parameters, exactly as far as the request has been
    /// built.
    ///
    /// This is infallible; [`ContactRequest::validate`] is what enforces the
    /// fields the API requires.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Org, "ACME", "ops@acme.test")?.with_org("ACME GmbH");
    /// assert_eq!(request.params()["org"], "ACME GmbH");
    /// assert_eq!(request.params()["type"], "ORG");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        params.insert("type".to_owned(), json!(self.contact_type));
        params.insert("name".to_owned(), json!(self.name));
        params.insert("email".to_owned(), json!(self.email));
        if let Some(value) = &self.org {
            params.insert("org".to_owned(), json!(value));
        }
        for (key, value) in [
            ("street", &self.street),
            ("city", &self.city),
            ("pc", &self.postcode),
            ("sp", &self.state),
            ("voice", &self.voice),
            ("fax", &self.fax),
            ("remarks", &self.remarks),
        ] {
            if let Some(value) = value {
                params.insert(key.to_owned(), json!(value));
            }
        }
        if let Some(country) = &self.country {
            params.insert("cc".to_owned(), json!(country));
        }
        Value::Object(params)
    }

    /// Checks the fields `contact.create` requires and the documented lengths.
    ///
    /// The lengths are the ones `contact.update` enforces too: both paths walk
    /// the same table.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let incomplete = ContactRequest::new(ContactType::Person, "Erika", "erika@example.com")?;
    /// assert!(incomplete.validate().is_err());
    ///
    /// let complete = incomplete
    ///     .with_street("Weg 2")
    ///     .with_city("Berlin")
    ///     .with_postcode("10115")
    ///     .with_country("DE")
    ///     .with_voice("+49.891");
    /// assert!(complete.validate().is_ok());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] naming the first missing or malformed field.
    pub fn validate(&self) -> Result<()> {
        // The fields the API requires, in the documented order: the first one
        // missing is the error.
        for (param, field) in [
            ("street", "contact.street"),
            ("city", "contact.city"),
            ("pc", "contact.pc"),
            ("cc", "contact.cc"),
            ("voice", "contact.voice"),
        ] {
            if self.field(param).is_none() {
                return Err(Error::validation(field, "is required"));
            }
        }
        let country = self
            .field("cc")
            .ok_or_else(|| Error::validation("contact.cc", "is required"))?;
        validate_country_code("contact.cc", country)?;
        // Every string the request carries goes through the table the update
        // path uses, so the two paths cannot drift apart.
        for (param, field, max) in TEXT_FIELDS {
            if let Some(value) = self.field(param) {
                check_len(field, value, max)?;
            }
        }
        Ok(())
    }

    /// One of the request's string fields, by the API parameter that carries
    /// it — the lookup that makes `TEXT_FIELDS` apply to `contact.create`.
    fn field(&self, param: &str) -> Option<&str> {
        match param {
            "name" => Some(self.name.as_str()),
            "org" => self.org.as_deref(),
            "street" => self.street.as_deref(),
            "city" => self.city.as_deref(),
            "pc" => self.postcode.as_deref(),
            "sp" => self.state.as_deref(),
            "cc" => self.country.as_deref(),
            "voice" => self.voice.as_deref(),
            "fax" => self.fax.as_deref(),
            "remarks" => self.remarks.as_deref(),
            _ => None,
        }
    }
}

/// A change to an existing handle (`contact.update`).
///
/// The contact type is not updatable, and unset fields stay as they are.
///
/// The values are checked the way `contact.create` checks them: the same
/// length table, the same control-character guard, the same non-blank name. A
/// change cannot put a value on the wire that a create would have refused.
///
/// ```
/// use inwx_client::ContactUpdate;
///
/// let update = ContactUpdate::new(991)?.with_email("new@example.com");
/// let params = update.params()?;
/// assert_eq!(params["id"], 991);
/// assert_eq!(params["email"], "new@example.com");
/// # Ok::<(), inwx_client::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactUpdate {
    id: i64,
    changes: Map<String, Value>,
}

impl ContactUpdate {
    /// An empty update for handle `id`.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the handle is not a positive id.
    pub fn new(id: i64) -> Result<Self> {
        if id <= 0 {
            return Err(Error::validation(
                "contact.id",
                format!("must be a positive handle id, got {id}"),
            ));
        }
        Ok(Self {
            id,
            changes: Map::new(),
        })
    }

    /// Sets the name.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_name("Erika M.").params()?["name"], "Erika M.");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.changes.insert("name".to_owned(), json!(name.into()));
        self
    }

    /// Sets the organisation.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_org("ACME").params()?["org"], "ACME");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_org(mut self, org: impl Into<String>) -> Self {
        self.changes.insert("org".to_owned(), json!(org.into()));
        self
    }

    /// Sets the street.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_street("Weg 2").params()?["street"], "Weg 2");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_street(mut self, street: impl Into<String>) -> Self {
        self.changes
            .insert("street".to_owned(), json!(street.into()));
        self
    }

    /// Sets the city.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_city("Berlin").params()?["city"], "Berlin");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_city(mut self, city: impl Into<String>) -> Self {
        self.changes.insert("city".to_owned(), json!(city.into()));
        self
    }

    /// Sets the postal code.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_postcode("10115").params()?["pc"], "10115");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_postcode(mut self, postcode: impl Into<String>) -> Self {
        self.changes.insert("pc".to_owned(), json!(postcode.into()));
        self
    }

    /// Sets the state or province.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_state("BY").params()?["sp"], "BY");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.changes.insert("sp".to_owned(), json!(state.into()));
        self
    }

    /// Sets the country code (validated like [`ContactRequest::with_country`]).
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_country("de").params()?["cc"], "DE");
    /// assert!(ContactUpdate::new(1)?.with_country("ZZ").params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        let country = country.into();
        self.changes
            .insert("cc".to_owned(), json!(country.trim().to_ascii_uppercase()));
        self
    }

    /// Sets the phone number.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_voice("+49.891").params()?["voice"], "+49.891");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_voice(mut self, voice: impl Into<String>) -> Self {
        self.changes.insert("voice".to_owned(), json!(voice.into()));
        self
    }

    /// Sets the fax number.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_fax("+49.892").params()?["fax"], "+49.892");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_fax(mut self, fax: impl Into<String>) -> Self {
        self.changes.insert("fax".to_owned(), json!(fax.into()));
        self
    }

    /// Sets the email address (validated).
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_email("a@b.test").params()?["email"], "a@b.test");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.changes.insert("email".to_owned(), json!(email.into()));
        self
    }

    /// Sets the remarks.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    /// assert_eq!(ContactUpdate::new(1)?.with_remarks("x").params()?["remarks"], "x");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_remarks(mut self, remarks: impl Into<String>) -> Self {
        self.changes
            .insert("remarks".to_owned(), json!(remarks.into()));
        self
    }

    /// The `contact.update` parameters.
    ///
    /// The address and the country code are sent in the exact form they were
    /// validated in, trimmed and upper-cased respectively.
    ///
    /// ```
    /// use inwx_client::ContactUpdate;
    ///
    /// let params = ContactUpdate::new(991)?.with_country("de").params()?;
    /// assert_eq!(params["cc"], "DE");
    ///
    /// // The limits are the create path's limits: a `text64` street takes 64
    /// // characters and not 65, and a newline never goes on the wire.
    /// assert!(ContactUpdate::new(991)?.with_street("x".repeat(64)).params().is_ok());
    /// assert!(ContactUpdate::new(991)?.with_street("x".repeat(65)).params().is_err());
    /// assert!(ContactUpdate::new(991)?.with_name("a\r\nb").params().is_err());
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was changed, when a changed field is
    /// longer than its documented type allows (`text64` street, `text10`
    /// postcode, 255 characters for the rest), carries a control character, or
    /// when a changed name is blank, email or country code is invalid.
    pub fn params(&self) -> Result<Value> {
        if self.changes.is_empty() {
            return Err(Error::validation(
                "contact",
                "an update needs at least one changed field",
            ));
        }
        if let Some(Value::String(name)) = self.changes.get("name") {
            check_name_not_blank(name)?;
        }
        let mut params = self.changes.clone();
        // The same table `contact.create` validates with: `contact.update`
        // writes the same fields, so it holds the same limits.
        for (param, field, max) in TEXT_FIELDS {
            if let Some(Value::String(value)) = self.changes.get(param) {
                check_len(field, value, max)?;
            }
        }
        if let Some(Value::String(email)) = self.changes.get("email") {
            let email = validate_email_field("contact.email", email)?;
            params.insert("email".to_owned(), json!(email));
        }
        if let Some(Value::String(country)) = self.changes.get("cc") {
            let country = validate_country_code("contact.cc", country)?;
            params.insert("cc".to_owned(), json!(country));
        }
        params.insert("id".to_owned(), json!(self.id));
        Ok(Value::Object(params))
    }
}

/// A contact handle as returned by `contact.info`.
///
/// ```
/// use inwx_client::{Contact, ContactType};
///
/// let contact: Contact = serde_json::from_str(
///     r#"{"roId":991,"id":991,"type":"PERSON","name":"Erika Mustermann",
///         "street":"Musterstraße 1","city":"München","pc":"80331","cc":"DE",
///         "voice":"+49.891","email":"erika@example.com","usedCount":2}"#,
/// )?;
/// assert_eq!(contact.contact_type, Some(ContactType::Person));
/// assert_eq!(contact.name.as_deref(), Some("Erika Mustermann"));
/// assert_eq!(contact.used_count, Some(2));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Contact {
    /// Handle id (`roId`).
    #[serde(default, rename = "roId", deserialize_with = "de::opt_i64")]
    pub ro_id: Option<i64>,
    /// Handle id as the rest of the API reports it.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub id: Option<i64>,
    /// Kind of handle.
    #[serde(default, rename = "type", deserialize_with = "opt_contact_type")]
    pub contact_type: Option<ContactType>,
    /// Name.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub name: Option<String>,
    /// Organisation.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub org: Option<String>,
    /// Street.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub street: Option<String>,
    /// City.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub city: Option<String>,
    /// Postal code.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub postcode: Option<String>,
    /// State or province.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub state: Option<String>,
    /// Country code.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub country: Option<String>,
    /// Phone number.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub voice: Option<String>,
    /// Fax number.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub fax: Option<String>,
    /// Email address.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub email: Option<String>,
    /// Remarks.
    #[serde(default, deserialize_with = "de::opt_string")]
    pub remarks: Option<String>,
    /// How many domains and zones use this handle.
    #[serde(default, rename = "usedCount", deserialize_with = "de::opt_i64")]
    pub used_count: Option<i64>,
}

impl Contact {
    /// The handle id, preferring `roId` over `id`.
    ///
    /// ```
    /// use inwx_client::Contact;
    ///
    /// let contact: Contact = serde_json::from_str(r#"{"id":991}"#)?;
    /// assert_eq!(contact.handle(), Some(991));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[must_use]
    pub fn handle(&self) -> Option<i64> {
        self.ro_id.or(self.id)
    }
}

/// One page of `contact.list`.
///
/// The `contact` rows are read the way every other list answer in this crate is
/// read: an array, or a single object where the array belongs (one handle), and
/// a row that does not fit [`Contact`] is skipped instead of failing the page.
/// `count` is `None` when the answer does not carry a usable total.
///
/// ```
/// use inwx_client::ContactListPage;
///
/// let page: ContactListPage = serde_json::from_str(
///     r#"{"count":1,"contact":[{"roId":991,"name":"Erika"}]}"#,
/// )?;
/// assert_eq!(page.contacts.len(), 1);
///
/// // A single handle in the place of the array is a page of one, and one row
/// // that does not fit the handle costs that row rather than the page.
/// let single: ContactListPage =
///     serde_json::from_str(r#"{"count":2,"contact":{"roId":991}}"#)?;
/// assert_eq!(single.contacts.len(), 1);
/// let mixed: ContactListPage = serde_json::from_str(
///     r#"{"count":2,"contact":[{"roId":991},null]}"#,
/// )?;
/// assert_eq!(mixed.contacts.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ContactListPage {
    /// Total number of handles matching the search.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The handles on this page.
    #[serde(default, rename = "contact", deserialize_with = "de::rows")]
    pub contacts: Vec<Contact>,
}

/// The page rules [`Pages`] needs to walk `contact.list`.
///
/// ```
/// use inwx_client::{ContactListPage, Page};
///
/// let page: ContactListPage = serde_json::from_str(
///     r#"{"count":4,"contact":[{"roId":991},{"roId":992}]}"#,
/// )?;
/// assert_eq!(page.total(), Some(4));
/// assert_eq!(page.len(), 2);
/// # Ok::<(), serde_json::Error>(())
/// ```
impl Page for ContactListPage {
    type Item = Contact;

    fn total(&self) -> Option<i64> {
        self.count
    }

    fn len(&self) -> usize {
        self.contacts.len()
    }

    fn truncate_to(&mut self, len: usize) {
        self.contacts.truncate(len);
    }

    fn into_items(self) -> Vec<Contact> {
        self.contacts
    }
}

/// A search + paging for `contact.list`.
///
/// ```
/// use inwx_client::ContactQuery;
///
/// let params = ContactQuery::new().with_search("Erika").with_page(1, 20).params();
/// assert_eq!(params["search"], "Erika");
/// assert_eq!(params["pagelimit"], 20);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactQuery {
    search: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

impl ContactQuery {
    /// An unfiltered query.
    ///
    /// ```
    /// use inwx_client::ContactQuery;
    /// assert_eq!(ContactQuery::new().params(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Searches name, organisation and email.
    ///
    /// ```
    /// use inwx_client::ContactQuery;
    /// assert_eq!(ContactQuery::new().with_search("acme").params()["search"], "acme");
    /// ```
    #[must_use]
    pub fn with_search(mut self, search: impl Into<String>) -> Self {
        self.search = Some(search.into());
        self
    }

    /// Sets the page (1-based) and page size.
    ///
    /// ```
    /// use inwx_client::ContactQuery;
    /// assert_eq!(ContactQuery::new().with_page(2, 5).params()["page"], 2);
    /// ```
    #[must_use]
    pub fn with_page(mut self, page: u32, limit: u32) -> Self {
        self.page = Some(page);
        self.limit = Some(limit);
        self
    }

    /// The `contact.list` parameters.
    ///
    /// ```
    /// use inwx_client::ContactQuery;
    /// assert!(ContactQuery::new().params().is_object());
    /// ```
    #[must_use]
    pub fn params(&self) -> Value {
        let mut params = Map::new();
        if let Some(search) = &self.search {
            params.insert("search".to_owned(), json!(search));
        }
        if let Some(page) = self.page {
            params.insert("page".to_owned(), json!(page));
        }
        if let Some(limit) = self.limit {
            params.insert("pagelimit".to_owned(), json!(limit));
        }
        Value::Object(params)
    }
}

/// The `contact.list` command, ready to be walked page by page with
/// [`Pages`].
///
/// The query's own `page`/`pagelimit` are overridden by the walker — a walk
/// owns its cursor.
///
/// ```
/// use inwx_client::{ContactListing, ContactQuery, Listing};
///
/// let listing = ContactListing::new(ContactQuery::new().with_search("Mustermann"));
/// assert_eq!(<ContactListing as Listing>::METHOD, "contact.list");
/// let params = listing.params(2, 25);
/// assert_eq!(params["search"], "Mustermann");
/// assert_eq!(params["page"], 2);
/// assert_eq!(params["pagelimit"], 25);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactListing {
    query: ContactQuery,
}

impl ContactListing {
    /// The listing for one search.
    ///
    /// ```
    /// use inwx_client::{ContactListing, ContactQuery};
    ///
    /// let query = ContactQuery::new().with_search("acme");
    /// assert_eq!(ContactListing::new(query.clone()).query(), &query);
    /// ```
    #[must_use]
    pub fn new(query: ContactQuery) -> Self {
        Self { query }
    }

    /// The search the walk is using.
    ///
    /// ```
    /// use inwx_client::{ContactListing, ContactQuery};
    ///
    /// assert_eq!(ContactListing::default().query(), &ContactQuery::new());
    /// ```
    #[must_use]
    pub fn query(&self) -> &ContactQuery {
        &self.query
    }
}

impl Listing for ContactListing {
    type Page = ContactListPage;

    const METHOD: &'static str = "contact.list";

    fn params(&self, page: u32, page_size: u32) -> Value {
        pagination::with_paging(self.query.params(), page, page_size)
    }
}

/// Parses a contact type leniently: an empty or absent value means `None`, and
/// an unknown type is carried rather than failing the whole handle.
fn opt_contact_type<'de, D>(deserializer: D) -> std::result::Result<Option<ContactType>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    raw.filter(|raw| !raw.trim().is_empty())
        .map(|raw| ContactType::parse(&raw))
        .transpose()
        .map_err(serde::de::Error::custom)
}

/// The documented limits of the string fields `contact.create` and
/// `contact.update` share, as `(API parameter, error field, characters)`.
///
/// One table for both directions: `contact.create` writes these fields and
/// `contact.update` changes them, and a `text64` that is refused on the way in
/// must not pass on the way of a change. `name` is `text255` plus the
/// non-blank rule [`check_name_not_blank`] enforces.
const TEXT_FIELDS: [(&str, &str, usize); 9] = [
    ("name", "contact.name", 255),
    ("org", "contact.org", 255),
    ("street", "contact.street", 64),
    ("city", "contact.city", 64),
    ("pc", "contact.pc", 10),
    ("sp", "contact.sp", 64),
    ("voice", "contact.voice", 64),
    ("fax", "contact.fax", 64),
    ("remarks", "contact.remarks", 255),
];

/// Enforces a documented maximum length.
fn check_len(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.chars().count() > max {
        return Err(Error::validation(
            field,
            format!("must be at most {max} characters"),
        ));
    }
    reject_control_chars(field, value)
}

/// Rejects a blank name: the API requires one on create and an update that
/// blanked it would leave a handle the registrar refuses.
fn check_name_not_blank(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(Error::validation("contact.name", "must not be empty"));
    }
    Ok(())
}

impl<T: Transport> InwxClient<T> {
    /// Creates a contact handle (`contact.create`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ContactRequest, ContactType, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let request = ContactRequest::new(ContactType::Person, "Erika Mustermann", "erika@example.com")?
    ///     .with_street("Musterstraße 1")
    ///     .with_city("München")
    ///     .with_postcode("80331")
    ///     .with_country("DE")
    ///     .with_voice("+49.8912345678");
    /// let id = client.create_contact(&request).await?;
    /// println!("handle {id}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`ContactRequest::params`], the usual
    /// transport and API errors, and [`Error::Ambiguous`] when the call was
    /// answered without a readable id: the handle exists by then, so the answer
    /// names no result rather than failing — listing the contacts beats
    /// creating the handle a second time.
    pub async fn create_contact(&self, request: &ContactRequest) -> Result<i64> {
        request.validate()?;
        let data = self.call("contact.create", request.params()).await?;
        // The registrar has created the handle as soon as this call returned.
        // An id that cannot be read therefore says nothing about the remote
        // state, so it must not surface as the terminal `MissingField`: a
        // caller that retried on that would leave a duplicate handle behind.
        // `pick_i64` accepts a number or a numeric string and falls back to the
        // `roId` spelling, which INWX sends next to `id`.
        let empty = Map::new();
        let fields = data.as_object().unwrap_or(&empty);
        pick_i64(fields, &["id", "roId"]).ok_or_else(|| {
            Error::ambiguous(
                "contact.create",
                "the answer carries no usable handle id, so the contact was most \
                 likely created; list the contacts before creating it again",
            )
        })
    }

    /// Reads a handle (`contact.info`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// let contact = client.contact_info(991).await?;
    /// println!("{:?}", contact.email);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// An answer that names no handle is an error, not an empty handle: every
    /// field of [`Contact`] is optional, so reading a shape the answer does not
    /// have would hand back a record with no id, no name and no email and still
    /// report success.
    ///
    /// ```
    /// # use inwx_client::{Error, InwxClient, Result, transport::{Request, Response, Transport}};
    /// # use std::sync::{Arc, Mutex};
    /// # #[derive(Clone)]
    /// # struct Scripted(Arc<Mutex<Vec<&'static str>>>);
    /// # impl Transport for Scripted {
    /// #     async fn execute(&self, _request: Request<'_>) -> Result<Response> {
    /// #         let body = self.0.lock().unwrap().remove(0);
    /// #         Response::new(200, std::iter::empty(), body.as_bytes().to_vec())
    /// #     }
    /// # }
    /// # async fn demo() -> Result<()> {
    /// let transport = Scripted(Arc::new(Mutex::new(vec![
    ///     r#"{"code":1000,"msg":"ok","resData":{"contact":{"roId":991,"name":"Erika"}}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// assert_eq!(client.contact_info(991).await?.handle(), Some(991));
    /// assert!(matches!(
    ///     client.contact_info(991).await,
    ///     Err(Error::MissingField { field: "resData.contact", .. })
    /// ));
    /// # Ok(())
    /// # }
    /// # tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingField`] when the answer names no handle — no `contact`
    /// object and nothing usable in `resData` itself, or a handle that carries
    /// neither `roId` nor `id` — plus the usual transport and API errors.
    pub async fn contact_info(&self, id: i64) -> Result<Contact> {
        let data = self
            .call("contact.info", json!({ "id": id, "wide": 0 }))
            .await?;
        // INWX nests the handle under `contact`, and an answer that carries it
        // flat in `resData` is read the same way. The fallback therefore applies
        // only when `contact` is absent or null, and either branch has to end in
        // a handle with an id: `Contact` has no required field, so an empty or
        // reshaped answer would otherwise deserialise into an all-`None` handle
        // and the shape mismatch would be reported as success.
        let (field, value) = match data.get("contact") {
            Some(nested) if !nested.is_null() => ("resData.contact.id", nested.clone()),
            _ => ("resData.contact", data),
        };
        let contact: Contact = serde_json::from_value(value).map_err(Error::from)?;
        if contact.handle().is_none() {
            return Err(Error::MissingField {
                method: "contact.info",
                field,
            });
        }
        Ok(contact)
    }

    /// Lists one page of handles (`contact.list`).
    ///
    /// The answer is read permissively, like every other list in this crate: a
    /// single `contact` object instead of the array is a page of one handle, a
    /// row that does not fit [`Contact`] is skipped rather than costing the
    /// whole page, and a `count` that is not a number leaves [`ContactListPage::count`]
    /// `None`. Only transport and API errors fail the call.
    ///
    /// For more than one page use
    /// [`InwxClient::list_all_contacts`], which walks them.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ContactQuery, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// for contact in client.list_contacts(&ContactQuery::new().with_search("ACME")).await?.contacts {
    ///     println!("{:?}", contact.handle());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn list_contacts(&self, query: &ContactQuery) -> Result<ContactListPage> {
        let data = self.call("contact.list", query.params()).await?;
        serde_json::from_value(data).map_err(Error::from)
    }

    /// Walks every page of the account's handles (`contact.list`).
    ///
    /// [`InwxClient::list_contacts`] answers one page; this is the cursor for
    /// accounts with more handles than fit into one request. The bound in
    /// `pagination` decides how far the walk goes, and it is checked before the
    /// first request.
    ///
    /// ```
    /// # use inwx_client::{
    /// #     ContactQuery, InwxClient, Pagination, Result,
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
    ///     r#"{"code":1000,"msg":"ok","resData":{"count":3,"contact":[{"roId":991},{"roId":992}]}}"#,
    ///     r#"{"code":1000,"msg":"ok","resData":{"contact":[{"roId":993}]}}"#,
    /// ])));
    /// let client = InwxClient::new(transport).with_session("domrobot=test")?;
    /// let handles = client
    ///     .list_all_contacts(
    ///         &ContactQuery::new().with_search("ACME"),
    ///         &Pagination::new().with_page_size(2)?,
    ///     )
    ///     .collect_all()
    ///     .await?
    ///     .iter()
    ///     .filter_map(inwx_client::Contact::handle)
    ///     .collect();
    /// # Ok(handles)
    /// # }
    /// # assert_eq!(
    /// #     tokio::runtime::Runtime::new().unwrap().block_on(demo()).unwrap(),
    /// #     [991, 992, 993]
    /// # );
    /// ```
    ///
    /// # Errors
    ///
    /// The bound is validated when it is built (see
    /// [`Pagination::with_page_size`]); the walk itself reports the usual
    /// transport and API errors.
    pub fn list_all_contacts(
        &self,
        query: &ContactQuery,
        pagination: &Pagination,
    ) -> Pages<'_, T, ContactListing> {
        Pages::new(self, ContactListing::new(query.clone()), *pagination)
    }

    /// Updates a handle (`contact.update`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{ContactUpdate, InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.update_contact(&ContactUpdate::new(991)?.with_email("neu@example.com")).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] from [`ContactUpdate::params`], plus the usual
    /// transport and API errors.
    pub async fn update_contact(&self, update: &ContactUpdate) -> Result<()> {
        self.call("contact.update", update.params()?).await?;
        Ok(())
    }

    /// Deletes a handle (`contact.delete`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use inwx_client::{InwxClient, ReqwestTransport};
    ///
    /// let client = InwxClient::new(ReqwestTransport::new())
    ///     .with_credentials("user", std::env::var("INWX_PASSWORD")?)?;
    /// client.delete_contact(991).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The usual transport and API errors — `2305` when the handle is still
    /// attached to a domain.
    pub async fn delete_contact(&self, id: i64) -> Result<()> {
        self.call("contact.delete", json!({ "id": id })).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> ContactRequest {
        ContactRequest::new(ContactType::Person, "Erika", "erika@example.com")
            .unwrap()
            .with_street("Weg 2")
            .with_city("Berlin")
            .with_postcode("10115")
            .with_country("de")
            .with_voice("+49.891")
    }

    #[test]
    fn required_fields_are_enforced_one_by_one() {
        let base = ContactRequest::new(ContactType::Person, "A", "a@b.test").unwrap();
        assert!(base.clone().with_street("s").validate().is_err());
        assert!(base
            .clone()
            .with_street("s")
            .with_city("c")
            .with_postcode("1")
            .with_country("DE")
            .validate()
            .is_err());
        assert!(complete().validate().is_ok());
    }

    #[test]
    fn an_unknown_country_code_is_not_a_country() {
        // Two ASCII letters are not enough: `ZZ` and `QQ` have the shape and are
        // not countries, so the ISO table decides.
        for bad in ["ZZ", "QQ", "zz", "DEU", "D1", "", "  "] {
            assert!(complete().with_country(bad).validate().is_err(), "{bad:?}");
        }
        // Just inside the boundary, in either case and with padding: the code is
        // normalised, checked against the table and sent in that one form.
        for good in ["DE", "de", " DE "] {
            let request = complete().with_country(good);
            assert!(request.validate().is_ok(), "{good:?}");
            assert_eq!(request.params()["cc"], "DE", "{good:?}");
        }
    }

    #[test]
    fn email_validation() {
        let check = |email: &str| validate_email_field("contact.email", email);
        assert!(check("a@b.test").is_ok());
        assert!(check("a@b").is_err());
        assert!(check("@b.test").is_err());
        assert!(check("a@").is_err());
        assert!(check("a b@c.test").is_err());
        assert!(check("a@@b.test").is_err());
        assert!(check("ab").is_err());
        assert!(check(&format!("{}@b.test", "x".repeat(300))).is_err());
        // A 64-character local part is accepted and 65 is rejected: the total
        // address stays far below the length limit, so only the local-part
        // boundary can decide these two.
        let local = |len: usize| format!("{}@b.test", "x".repeat(len));
        assert!(check(&local(64)).is_ok());
        assert!(check(&local(65)).is_err());
        // 255 bytes are the last accepted length, 256 are rejected.
        let total = |last: usize| {
            format!(
                "{}@{}.{}.{}",
                "a".repeat(64),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(last)
            )
        };
        assert_eq!(total(61).len(), 254);
        assert_eq!(total(62).len(), 255);
        assert_eq!(total(63).len(), 256);
        assert!(check(&total(61)).is_ok());
        assert!(check(&total(62)).is_ok());
        assert!(check(&total(63)).is_err());
    }

    #[test]
    fn the_address_that_is_checked_is_the_address_that_is_sent() {
        // #112: the trimmed value was validated while the untrimmed one went out.
        assert_eq!(
            validate_email_field("contact.email", "  a@b.test  ").unwrap(),
            "a@b.test"
        );
        let request = ContactRequest::new(ContactType::Person, "A", "  a@b.test  ").unwrap();
        assert_eq!(request.params()["email"], "a@b.test");
        let update = ContactUpdate::new(1).unwrap().with_email(" a@b.test ");
        assert_eq!(update.params().unwrap()["email"], "a@b.test");
    }

    #[test]
    fn lengths_are_enforced() {
        // `text10` postcode: 10 characters are the last valid value, 11 are rejected.
        let max_postcode = complete().with_postcode("1".repeat(10));
        assert!(max_postcode.validate().is_ok());
        let long_postcode = complete().with_postcode("1".repeat(11));
        assert!(long_postcode.validate().is_err());
        // `text64` street: 64 characters are the last valid value, 65 are rejected.
        let max_street = complete().with_street("x".repeat(64));
        assert!(max_street.validate().is_ok());
        let long_street = complete().with_street("x".repeat(65));
        assert!(long_street.validate().is_err());
    }

    #[test]
    fn update_requires_a_change_and_a_positive_id() {
        assert!(ContactUpdate::new(0).is_err());
        assert!(ContactUpdate::new(-5).is_err());
        assert!(ContactUpdate::new(1).unwrap().params().is_err());
    }

    #[test]
    fn update_uppercases_and_validates_country() {
        assert_eq!(
            ContactUpdate::new(1)
                .unwrap()
                .with_country("at")
                .params()
                .unwrap()["cc"],
            "AT"
        );
        assert!(ContactUpdate::new(1)
            .unwrap()
            .with_country("AUT")
            .params()
            .is_err());
    }

    #[test]
    fn optional_fields_are_omitted_when_unset() {
        let params = complete().params();
        assert!(params.get("org").is_none());
        assert!(params.get("fax").is_none());
        assert!(params.get("remarks").is_none());
        assert_eq!(params["cc"], "DE");
    }

    /// A request with every string field set, so the completeness checks below
    /// see the whole surface `contact.create` can send.
    fn all_fields() -> ContactRequest {
        complete()
            .with_org("ACME GmbH")
            .with_state("BY")
            .with_fax("+49.892")
            .with_remarks("night only")
    }

    /// An update that sets exactly one field, named by its API parameter.
    fn update_with(param: &str, value: &str) -> Result<Value> {
        let update = ContactUpdate::new(1).unwrap();
        let update = match param {
            "name" => update.with_name(value),
            "org" => update.with_org(value),
            "street" => update.with_street(value),
            "city" => update.with_city(value),
            "pc" => update.with_postcode(value),
            "sp" => update.with_state(value),
            "voice" => update.with_voice(value),
            "fax" => update.with_fax(value),
            "remarks" => update.with_remarks(value),
            other => panic!("{other} is not a limited field"),
        };
        update.params()
    }

    #[test]
    fn update_enforces_every_documented_length() {
        // #110: `contact.update` sent these fields without the create path's
        // limits, so a 100_000-character street went out unchanged.
        for (param, field, max) in TEXT_FIELDS {
            assert!(
                update_with(param, &"x".repeat(max)).is_ok(),
                "{param} at its limit of {max}"
            );
            match update_with(param, &"x".repeat(max + 1)) {
                Err(Error::Validation { field: named, .. }) => assert_eq!(named, field),
                other => panic!("{param} one past its limit of {max}: {other:?}"),
            }
        }
    }

    #[test]
    fn update_counts_characters_not_bytes() {
        // Like the create path: `ü` is two bytes and one character.
        for (param, _, max) in TEXT_FIELDS {
            assert!(update_with(param, &"ü".repeat(max)).is_ok(), "{param}");
            assert!(update_with(param, &"ü".repeat(max + 1)).is_err(), "{param}");
        }
    }

    #[test]
    fn update_rejects_control_characters_in_every_field() {
        for (param, field, _) in TEXT_FIELDS {
            for value in ["a\r\nb", "a\nb", "a\u{0}b", "a\u{7f}b"] {
                match update_with(param, value) {
                    Err(Error::Validation { field: named, .. }) => {
                        assert_eq!(named, field, "{param} took {value:?}");
                    }
                    other => panic!("{param} accepted {value:?}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn update_rejects_a_blank_name_like_create_does() {
        assert!(ContactRequest::new(ContactType::Person, "  ", "a@b.test").is_err());
        assert!(update_with("name", " ").is_err());
        assert!(update_with("name", "Erika").is_ok());
    }

    #[test]
    fn the_limit_table_covers_exactly_the_string_fields_both_paths_send() {
        let params = all_fields().params();
        let object = params.as_object().unwrap();

        // Every row of the table names a field the create path really sends, and
        // the error field it reports is derived from the parameter.
        for (param, field, _) in TEXT_FIELDS {
            assert!(
                object.contains_key(param),
                "{param} is limited but never sent"
            );
            assert_eq!(
                field,
                format!("contact.{param}").as_str(),
                "error field for {param}"
            );
            // ... and one the update path can change.
            assert!(update_with(param, "x").is_ok(), "{param} is not updatable");
        }

        // And the other direction: no string field goes out unchecked. `type`,
        // `email` and `cc` are the three with their own validators.
        for (param, value) in object {
            if matches!(value, Value::String(_))
                && !matches!(param.as_str(), "type" | "email" | "cc")
            {
                assert!(
                    TEXT_FIELDS.iter().any(|(key, ..)| key == param),
                    "{param} is sent without a documented limit"
                );
            }
        }
    }
}
