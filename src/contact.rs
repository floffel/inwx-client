//! Contact handles (`contact.*`): the people and organisations behind domains.
//!
//! INWX wants handles, not inline addresses: you create a handle once, then
//! attach it to a domain as registrant, admin, tech or billing. Validation here
//! mirrors the documented field types (`text64` street, `text10` postcode,
//! two-letter country) so a rejected handle is a local error.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::InwxClient;
use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::types::{de, reject_control_chars, ContactType};

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
        if name.trim().is_empty() {
            return Err(Error::validation("contact.name", "must not be empty"));
        }
        if name.chars().count() > 255 {
            return Err(Error::validation(
                "contact.name",
                "must be at most 255 characters",
            ));
        }
        reject_control_chars("contact.name", &name)?;
        validate_email(&email)?;
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

    /// Sets the two-letter ISO country code.
    ///
    /// ```
    /// use inwx_client::{ContactRequest, ContactType};
    ///
    /// let request = ContactRequest::new(ContactType::Person, "A", "a@b.test")?.with_country("at");
    /// assert_eq!(request.params()["cc"], "AT");
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
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
            params.insert("cc".to_owned(), json!(country.to_ascii_uppercase()));
        }
        Value::Object(params)
    }

    /// Checks the fields `contact.create` requires and the documented lengths.
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
        let street = self
            .street
            .as_deref()
            .ok_or_else(|| Error::validation("contact.street", "is required"))?;
        let city = self
            .city
            .as_deref()
            .ok_or_else(|| Error::validation("contact.city", "is required"))?;
        let postcode = self
            .postcode
            .as_deref()
            .ok_or_else(|| Error::validation("contact.pc", "is required"))?;
        let country = self
            .country
            .as_deref()
            .ok_or_else(|| Error::validation("contact.cc", "is required"))?;
        let voice = self
            .voice
            .as_deref()
            .ok_or_else(|| Error::validation("contact.voice", "is required"))?;

        check_country(country)?;
        check_len("contact.street", street, 64)?;
        check_len("contact.city", city, 64)?;
        check_len("contact.pc", postcode, 10)?;
        check_len("contact.voice", voice, 64)?;
        if let Some(org) = &self.org {
            check_len("contact.org", org, 255)?;
        }
        if let Some(state) = &self.state {
            check_len("contact.sp", state, 64)?;
        }
        if let Some(fax) = &self.fax {
            check_len("contact.fax", fax, 64)?;
        }
        if let Some(remarks) = &self.remarks {
            check_len("contact.remarks", remarks, 255)?;
        }
        Ok(())
    }
}

/// A change to an existing handle (`contact.update`).
///
/// The contact type is not updatable, and unset fields stay as they are.
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
    /// # Ok::<(), inwx_client::Error>(())
    /// ```
    #[must_use]
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.changes.insert("cc".to_owned(), json!(country.into()));
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
    /// # Errors
    ///
    /// [`Error::Validation`] when nothing was changed, or when a changed email
    /// or country code is invalid.
    pub fn params(&self) -> Result<Value> {
        if self.changes.is_empty() {
            return Err(Error::validation(
                "contact",
                "an update needs at least one changed field",
            ));
        }
        if let Some(Value::String(email)) = self.changes.get("email") {
            validate_email(email)?;
        }
        if let Some(Value::String(country)) = self.changes.get("cc") {
            check_country(country)?;
        }
        let mut params = self.changes.clone();
        params.insert("id".to_owned(), json!(self.id));
        if let Some(Value::String(country)) = params.get_mut("cc") {
            *country = country.to_ascii_uppercase();
        }
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
/// ```
/// use inwx_client::ContactListPage;
///
/// let page: ContactListPage = serde_json::from_str(
///     r#"{"count":1,"contact":[{"roId":991,"name":"Erika"}]}"#,
/// )?;
/// assert_eq!(page.contacts.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ContactListPage {
    /// Total number of handles matching the search.
    #[serde(default, deserialize_with = "de::opt_i64")]
    pub count: Option<i64>,
    /// The handles on this page.
    #[serde(default, rename = "contact")]
    pub contacts: Vec<Contact>,
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

/// Validates the two-letter country code the API expects.
fn check_country(country: &str) -> Result<()> {
    let trimmed = country.trim();
    if trimmed.len() != 2 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(Error::validation(
            "contact.cc",
            format!("{country:?} is not a two-letter ISO country code"),
        ));
    }
    Ok(())
}

/// Rejects empty, whitespace-carrying or `@`-less addresses; the registrar's
/// own check is authoritative.
fn validate_email(email: &str) -> Result<()> {
    let trimmed = email.trim();
    if trimmed.len() < 3 || trimmed.len() > 255 {
        return Err(Error::validation(
            "contact.email",
            "must be 3 to 255 characters",
        ));
    }
    let Some((local, domain)) = trimmed.split_once('@') else {
        return Err(Error::validation(
            "contact.email",
            format!("{email:?} is missing `@`"),
        ));
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(Error::validation(
            "contact.email",
            format!("{email:?} is not a valid email address"),
        ));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(Error::validation(
            "contact.email",
            "must not contain whitespace",
        ));
    }
    reject_control_chars("contact.email", trimmed)?;
    if !domain.contains('.') {
        return Err(Error::validation(
            "contact.email",
            format!("{email:?} has no top level domain"),
        ));
    }
    Ok(())
}

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
    /// [`Error::Validation`] from [`ContactRequest::params`],
    /// [`Error::MissingField`] when the answer carries no `id`, plus the usual
    /// transport and API errors.
    pub async fn create_contact(&self, request: &ContactRequest) -> Result<i64> {
        request.validate()?;
        let data = self.call("contact.create", request.params()).await?;
        data.get("id")
            .and_then(Value::as_i64)
            .ok_or(Error::MissingField {
                method: "contact.create",
                field: "resData.id",
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
    /// # Errors
    ///
    /// The usual transport and API errors.
    pub async fn contact_info(&self, id: i64) -> Result<Contact> {
        let data = self
            .call("contact.info", json!({ "id": id, "wide": 0 }))
            .await?;
        let contact = data.get("contact").cloned().unwrap_or(data);
        serde_json::from_value(contact).map_err(Error::from)
    }

    /// Lists handles (`contact.list`).
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
    fn country_code_must_be_two_letters() {
        let bad = complete().with_country("DEU");
        assert!(bad.validate().is_err());
        let bad = complete().with_country("D1");
        assert!(bad.validate().is_err());
    }

    #[test]
    fn email_validation() {
        assert!(validate_email("a@b.test").is_ok());
        assert!(validate_email("a@b").is_err());
        assert!(validate_email("@b.test").is_err());
        assert!(validate_email("a@").is_err());
        assert!(validate_email("a b@c.test").is_err());
        assert!(validate_email("a@@b.test").is_err());
        assert!(validate_email("ab").is_err());
        assert!(validate_email(&format!("{}@b.test", "x".repeat(300))).is_err());
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
}
