//! Fuzz target: the price decoders of `domain.getPrices`,
//! `domain.getalldomainprices`, `domain.getdomainprice`,
//! `domain.getextradatarules`, `domain.getpromos` and `domain.pricechanges`.
//!
//! INWX is inconsistent about the shape of a price answer — an amount is a
//! number or a decimal string, a list is an array or a bare object, a row lives
//! under `price`, `promo`, `pricechange` or their plurals — so every spelling
//! gets fed arbitrary bytes here. Nothing may panic, and a row that cannot be
//! read must cost at most that row.
//!
//! Run with `cargo +nightly fuzz run parse_price_rows` (see the README for the
//! corpus and how to reproduce a crash).

#![no_main]

use libfuzzer_sys::fuzz_target;
use inwx_client::{
    DomainPriceQuote, ExtraDataRule, PriceChange, PriceList, PromoCode, RpcResponse, TldPrice,
};

fuzz_target!(|data: &[u8]| {
    // Framing first: any byte string either parses or returns an error.
    let Ok(response) = RpcResponse::parse(data) else {
        return;
    };
    let Some(payload) = response.res_data.clone() else {
        return;
    };

    // The paged table, including the row-walking helpers on top of it.
    if let Ok(list) = serde_json::from_value::<PriceList>(payload.clone()) {
        let _ = list.len();
        let _ = list.is_empty();
        let _ = list.has_more();
        let _ = list.find("de");
    }
    let _ = serde_json::from_value::<TldPrice>(payload.clone());
    let _ = serde_json::from_value::<Vec<TldPrice>>(payload.clone());
    let _ = serde_json::from_value::<DomainPriceQuote>(payload.clone());

    // The three list answers whose key is not settled by the documentation.
    for key in ["extradata", "extradataRules", "rules"] {
        if let Some(rows) = payload.get(key) {
            let _ = serde_json::from_value::<Vec<ExtraDataRule>>(rows.clone());
        }
    }
    if let Ok(rules) = serde_json::from_value::<Vec<ExtraDataRule>>(payload.clone()) {
        for rule in rules {
            let _ = rule.price_type();
            let _ = rule.is_text();
        }
    }
    for key in ["promo", "promos", "pricechange", "pricechanges"] {
        if let Some(rows) = payload.get(key) {
            let _ = serde_json::from_value::<Vec<PromoCode>>(rows.clone());
            let _ = serde_json::from_value::<Vec<PriceChange>>(rows.clone());
        }
    }
    if let Ok(promos) = serde_json::from_value::<Vec<PromoCode>>(payload.clone()) {
        for promo in promos {
            let _ = promo.price_type();
        }
    }
    if let Ok(changes) = serde_json::from_value::<Vec<PriceChange>>(payload.clone()) {
        for change in changes {
            let _ = change.price_type();
            let _ = change.is_increase();
        }
    }
});
