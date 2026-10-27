//! Fuzz target: the JSON-RPC response parser, and every typed decode that runs
//! on top of it, must never panic — whatever bytes arrive from the endpoint.
//!
//! Run with `cargo +nightly fuzz run parse_response` (see the README for the
//! corpus and how to reproduce a crash).

#![no_main]

use libfuzzer_sys::fuzz_target;
use inwx_client::{
    Application, ApplicationListPage, AuthInfo2, AuthInfo2Price, CheckOutcome, Contact,
    ContactVerificationSettings, Customer, CustomerDownloadPage, DataExport, DnsRecord,
    DocumentDownload, DocumentListPage, DomainCheck, DomainInfo, Host, HostListPage, Message,
    MessageQueue, NewsListPage, NicHandleListPage, PdfDocument, RecordType, RpcResponse, ZoneInfo,
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
        // The reseller/partner objects, including the ones that decode base64
        // and read settings by name afterwards.
        let _ = serde_json::from_value::<Application>(payload.clone());
        let _ = serde_json::from_value::<ApplicationListPage>(payload.clone());
        let _ = serde_json::from_value::<AuthInfo2>(payload.clone());
        let _ = serde_json::from_value::<AuthInfo2Price>(payload.clone());
        let _ = serde_json::from_value::<CheckOutcome>(payload.clone());
        let _ = serde_json::from_value::<ContactVerificationSettings>(payload.clone());
        let _ = serde_json::from_value::<Customer>(payload.clone());
        let _ = serde_json::from_value::<CustomerDownloadPage>(payload.clone());
        let _ = serde_json::from_value::<DataExport>(payload.clone());
        let _ = serde_json::from_value::<DocumentListPage>(payload.clone());
        let _ = serde_json::from_value::<Host>(payload.clone());
        let _ = serde_json::from_value::<HostListPage>(payload.clone());
        let _ = serde_json::from_value::<Message>(payload.clone());
        let _ = serde_json::from_value::<MessageQueue>(payload.clone());
        let _ = serde_json::from_value::<NewsListPage>(payload.clone());
        let _ = serde_json::from_value::<NicHandleListPage>(payload.clone());
        if let Ok(settings) = serde_json::from_value::<ContactVerificationSettings>(payload.clone()) {
            for key in ["verifyEmail", "interval", "state"] {
                let _ = settings.value(key);
                let _ = settings.bool_value(key);
                let _ = settings.string_value(key);
            }
        }
        if let Ok(queue) = serde_json::from_value::<MessageQueue>(payload.clone()) {
            let _ = queue.ids();
            for message in &queue.messages {
                let _ = message.required_id();
            }
        }
        // Base64 bodies must fail cleanly, never panic.
        if let Ok(document) = serde_json::from_value::<DocumentDownload>(payload.clone()) {
            let _ = document.bytes();
        }
        if let Ok(document) = serde_json::from_value::<PdfDocument>(payload.clone()) {
            let _ = document.bytes();
            let _ = document.required_hash();
        }
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
        // Reseller string inputs: hash, AuthInfo2 code, document name and body.
        let _ = inwx_client::PdfHash::new(text);
        let _ = inwx_client::AuthInfo2Code::new(text);
        let _ = inwx_client::DocumentUpload::from_base64(text, "aGk=");
        let _ = inwx_client::DocumentUpload::from_base64("blob.bin", text);
        let _ = inwx_client::DocumentUpload::new(text, b"x");
        let _ = inwx_client::ApplicationCheck::new().and_then(|c| c.with_type(text));
        let _ = inwx_client::AuthInfo2Order::new().and_then(|o| o.with_field(text, 1));
    }
});
