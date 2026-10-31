//! Fuzz target: the JSON-RPC response parser, and every typed decode that runs
//! on top of it, must never panic — whatever bytes arrive from the endpoint.
//!
//! Run with `cargo +nightly fuzz run parse_response` (see the README for the
//! corpus and how to reproduce a crash).

#![no_main]

use libfuzzer_sys::fuzz_target;
use inwx_client::{
    Application, ApplicationCheckResult, ApplicationType, AuthInfo2Order, AuthInfo2OrderResult,
    AuthInfo2PriceQuote, Contact, ContactVerificationSettings, Customer, CustomerDownload,
    DataExport, DnsRecord, DomainCheck, DomainInfo, DocumentEntry, DownloadedDocument,
    HostCheckResult, HostRecord, Message, NewsItem, NicHandle, PdfFile, PdfHandle, PolledMessage,
    RecordType, RpcResponse, ZoneInfo,
    AccountRole, AccountRoleEntry, Application, ApplicationCheckResult, ApplicationType, AuthInfo2,
    AuthInfo2Record, Contact, ContactVerificationSettings, Customer, CustomerDownload, DataExport,
    DnsRecord, DomainCheck, DomainInfo, DocumentEntry, DownloadedDocument, HostCheckResult,
    HostRecord, Message, NewsItem, NicHandle, PdfFile, PdfHandle, PolledMessage, RecordType,
    RpcResponse, ZoneInfo,
};

fuzz_target!(|data: &[u8]| {
    // The framing layer: any byte string either parses or returns a Json error.
    let Ok(response) = RpcResponse::parse(data) else {
        return;
    };

    // Classification and rendering are pure and must not panic.
    let _ = response.is_success();
    let _ = response.is_authentication();
    let _ = response.error_message();

    // Every typed decoder this crate runs on `resData` gets the same payload.
    if let Some(payload) = response.res_data.clone() {
        let _ = serde_json::from_value::<DnsRecord>(payload.clone());
        let _ = serde_json::from_value::<ZoneInfo>(payload.clone());
        let _ = serde_json::from_value::<DomainInfo>(payload.clone());
        let _ = serde_json::from_value::<DomainCheck>(payload.clone());
        let _ = serde_json::from_value::<Contact>(payload.clone());
        let _ = serde_json::from_value::<Vec<DnsRecord>>(payload.clone());

        // The reseller/partner objects (issue #22) decode the same way, and the
        // ones with a base64 body run their decoder too.
        let _ = serde_json::from_value::<Application>(payload.clone());
        let _ = serde_json::from_value::<Vec<Application>>(payload.clone());
        let _ = serde_json::from_value::<ApplicationCheckResult>(payload.clone());
        let _ = serde_json::from_value::<AuthInfo2OrderResult>(payload.clone());
        let _ = serde_json::from_value::<AuthInfo2PriceQuote>(payload.clone());
        let _ = serde_json::from_value::<ContactVerificationSettings>(payload.clone());
        let _ = serde_json::from_value::<Customer>(payload.clone());
        let _ = serde_json::from_value::<Vec<Customer>>(payload.clone());
        let _ = serde_json::from_value::<CustomerDownload>(payload.clone());
        let _ = serde_json::from_value::<DataExport>(payload.clone());
        let _ = serde_json::from_value::<DocumentEntry>(payload.clone());
        let _ = serde_json::from_value::<DownloadedDocument>(payload.clone())
            .map(|document| document.bytes());
        let _ = serde_json::from_value::<HostCheckResult>(payload.clone());
        let _ = serde_json::from_value::<HostRecord>(payload.clone());
        let _ = serde_json::from_value::<Message>(payload.clone());
        let _ = serde_json::from_value::<PolledMessage>(payload.clone());
        let _ = serde_json::from_value::<NewsItem>(payload.clone());
        let _ = serde_json::from_value::<NicHandle>(payload.clone());
        let _ = serde_json::from_value::<PdfHandle>(payload.clone());
        let _ = serde_json::from_value::<PdfFile>(payload.clone()).map(|file| file.bytes());
        // Account roles (#74): the row model and the role vocabulary inside it.
        let _ = serde_json::from_value::<AccountRoleEntry>(payload.clone());
        let _ = serde_json::from_value::<Vec<AccountRoleEntry>>(payload.clone());

        // A `domain.check` answer may be a single object or an array.
        if let Some(entries) = payload.get("domain").and_then(|value| value.as_array()) {
            for entry in entries {
                let _ = serde_json::from_value::<DomainCheck>(entry.clone());
            }
        }
    }

    // Error conversion must not panic either, and success codes must agree with
    // `is_success`.
    let code = response.code;
    let result = response.into_result();
    debug_assert_eq!(result.is_ok(), inwx_client::rpc::is_success_code(code));

    // Record types are parsed from user input, so feed them the same bytes.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = RecordType::parse(text);
        // The reseller value parsers take user input as well: a product type,
        // the domain of an AuthInfo2 order and a document file name.
        let _ = ApplicationType::parse(text);
        if let Ok(order_domain) = text.parse::<inwx_client::DomainName>() {
            let _ = AuthInfo2Order::new(order_domain, true).params();
        }
        let _ = inwx_client::DocumentUpload::new(text, b"x");
        let _ = AccountRole::parse(text);
    }
});
