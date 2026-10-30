//! Keeps the crate-level "What it covers" table honest (issue #50).
//!
//! The table in `src/lib.rs` promises concrete commands and per-namespace
//! counts. Reading it should tell a user exactly what the crate sends, so this
//! test parses the table *and* the sources and fails when the two disagree in
//! either direction: a command that is tabled but never dispatched, a count that
//! no longer matches the code, or a namespace that gained commands (or a whole
//! module) without a row.
//!
//! Dispatch sites are found by looking for the method string as the first
//! argument of a call, which deliberately ignores the many `namespace.field`
//! labels the validators use. `certificate.order` and `certificate.update`, for
//! example, only ever appear as `Error::validation` field names — they are not
//! RPC commands, and counting them would overstate coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Callees whose first argument is the RPC method that gets sent.
///
/// `dyndns_subscriptions` is the private helper that receives the method as a
/// parameter and dispatches it; `subscription_list_commands_travel_through_the_helper`
/// pins the exact set that may be passed to it, so widening that helper later
/// cannot silently hide a command from the table.
const DISPATCH_CALLEES: &[&str] = &["call", "send", "dyndns_subscriptions"];

/// Commands a table row promises for one namespace.
#[derive(Debug, Default)]
struct Claim {
    /// Table areas that mention this namespace.
    areas: BTreeSet<String>,
    /// Commands spelled out in the table.
    explicit: BTreeSet<String>,
    /// `namespace.* (N methods)` shorthand, with its promised count.
    shorthand: Option<usize>,
    /// Commands marked `(implicit)`: documented, reachable through `call`, but
    /// not wrapped in their own method.
    implicit: BTreeSet<String>,
}

/// What the sources actually do.
struct Scan {
    /// Dispatched commands, grouped by namespace.
    dispatched: BTreeMap<String, BTreeSet<String>>,
    /// Namespaces dispatched inside one source file, keyed by file name.
    files: BTreeMap<String, BTreeSet<String>>,
    /// Every `namespace.command` shaped literal anywhere in `src/`.
    literals: BTreeSet<String>,
}

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_utf8(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn lib_source() -> String {
    read_utf8(&manifest_dir().join("src").join("lib.rs"))
}

/// Every `.rs` file below `src/`, keyed by file name.
fn source_files() -> BTreeMap<String, String> {
    let mut paths: Vec<PathBuf> = fs::read_dir(manifest_dir().join("src"))
        .unwrap_or_else(|error| panic!("read src directory: {error}"))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_else(|| panic!("{} has a non-UTF-8 name", path.display()))
                .to_owned();
            (name, read_utf8(path))
        })
        .collect()
}

/// Split `certificate.renew` into its namespace and command.
///
/// Rejects anything that is not shaped like a command, so field labels such as
/// `record.ttl` still parse but `example.com` and `a.de` are only ever picked up
/// if they turn out to sit in a dispatch position.
fn split_method(literal: &str) -> Option<(&str, &str)> {
    let (namespace, command) = literal.split_once('.')?;
    let namespace_ok = !namespace.is_empty()
        && namespace
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && namespace
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase());
    let command_ok = !command.is_empty()
        && command.chars().all(|c| c.is_ascii_alphanumeric())
        && command
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase());
    if namespace_ok && command_ok {
        Some((namespace, command))
    } else {
        None
    }
}

/// String literals in `source`, as `(offset of the opening quote, contents)`.
///
/// Comments and raw strings are skipped, which matters because doctests quote
/// plenty of method names without dispatching them.
fn string_literals(source: &[char]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < source.len() {
        let c = source[i];
        if c == '/' && source.get(i + 1) == Some(&'/') {
            while i < source.len() && source[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && source.get(i + 1) == Some(&'*') {
            let mut depth = 1;
            i += 2;
            while i < source.len() && depth > 0 {
                if source[i] == '/' && source.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if source[i] == '*' && source.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else if c == '\'' {
            i = char_literal_end(source, i);
        } else if c == 'r' {
            // Raw strings never hold a dispatch target; skip over them whole.
            let mut hashes = 0;
            let mut j = i + 1;
            while source.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if source.get(j) == Some(&'"') && hashes > 0 {
                i = j + 1;
                loop {
                    match source.get(i) {
                        None => break,
                        Some('"') => {
                            let closed = (0..hashes).all(|k| source.get(i + 1 + k) == Some(&'#'));
                            if closed {
                                i += 1 + hashes;
                                break;
                            }
                            i += 1;
                        }
                        Some(_) => i += 1,
                    }
                }
            } else {
                i += 1;
            }
        } else if c == '"' {
            let start = i;
            let mut j = i + 1;
            let mut text = String::new();
            while j < source.len() {
                match source[j] {
                    '\\' => {
                        j += 2;
                    }
                    '"' => break,
                    other => {
                        text.push(other);
                        j += 1;
                    }
                }
            }
            out.push((start, text));
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Index just past the closing quote of the char literal starting at `start`.
fn char_literal_end(source: &[char], start: usize) -> usize {
    if source.get(start + 1) == Some(&'\\') {
        let mut j = start + 2;
        while j < source.len() && source[j] != '\'' {
            j += 1;
        }
        return j + 1;
    }
    if source.get(start + 2) == Some(&'\'') {
        return start + 3;
    }
    start + 1
}

/// Callee of the call a literal is the first argument of, if it is one.
fn callee_before(source: &[char], quote: usize) -> Option<String> {
    let mut i = quote;
    loop {
        if i == 0 {
            return None;
        }
        i -= 1;
        if !source[i].is_whitespace() {
            break;
        }
    }
    if source[i] != '(' {
        return None;
    }
    let mut start = i;
    while start > 0 {
        let c = source[start - 1];
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '!' {
            start -= 1;
        } else {
            break;
        }
    }
    let path: String = source[start..i].iter().collect();
    let last = path.rsplit('.').next()?;
    if last.is_empty() {
        None
    } else {
        Some(last.to_owned())
    }
}

fn scan_sources() -> Scan {
    let mut dispatched: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut files: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut literals = BTreeSet::new();
    for (file, text) in source_files() {
        let chars: Vec<char> = text.chars().collect();
        for (offset, literal) in string_literals(&chars) {
            let Some((namespace, _)) = split_method(&literal) else {
                continue;
            };
            literals.insert(literal.clone());
            let dispatched_here = callee_before(&chars, offset)
                .is_some_and(|callee| DISPATCH_CALLEES.contains(&callee.as_str()));
            if dispatched_here {
                dispatched
                    .entry(namespace.to_owned())
                    .or_default()
                    .insert(literal.clone());
                files
                    .entry(file.clone())
                    .or_default()
                    .insert(namespace.to_owned());
            }
        }
    }
    Scan {
        dispatched,
        files,
        literals,
    }
}

/// Backticked tokens in a table cell, each with the text that follows it.
fn cell_tokens(cell: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = cell.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '`' {
            i += 1;
            continue;
        }
        let Some(token_len) = chars[i + 1..].iter().position(|c| *c == '`') else {
            break;
        };
        let token: String = chars[i + 1..i + 1 + token_len].iter().collect();
        let note_start = i + token_len + 2;
        let note_len = chars
            .get(note_start..)
            .and_then(|rest| rest.iter().position(|c| *c == '`'))
            .unwrap_or(chars.len() - note_start);
        let note: String = chars[note_start..note_start + note_len].iter().collect();
        out.push((token.trim().to_owned(), note.trim().to_owned()));
        i = note_start;
    }
    out
}

/// First number in an annotation such as `(13 methods)`.
fn leading_number(note: &str) -> Option<usize> {
    let start = note.char_indices().find(|(_, c)| c.is_ascii_digit())?.0;
    let rest = &note[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn is_implicit(note: &str) -> bool {
    note.to_ascii_lowercase().contains("implicit")
}

/// Parse the `What it covers` table out of a crate doc comment.
fn coverage_table(lib: &str) -> Result<BTreeMap<String, Claim>, Vec<String>> {
    let mut problems = Vec::new();
    let mut claims: BTreeMap<String, Claim> = BTreeMap::new();
    let mut rows = 0;
    let mut inside = false;
    for raw in lib.lines() {
        let line = raw.trim_start_matches("//!").trim();
        if !inside {
            inside = line == "# What it covers";
            continue;
        }
        if !line.starts_with('|') {
            if rows > 0 {
                break;
            }
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 3 {
            problems.push(format!("malformed table row: {line}"));
            continue;
        }
        if cells[1].eq_ignore_ascii_case("area")
            || cells[1]
                .chars()
                .all(|c| c == '-' || c == ':' || c.is_whitespace())
        {
            continue;
        }
        rows += 1;
        if let Err(errors) = record_row(cells[1], cells[2], &mut claims) {
            problems.extend(errors);
        }
    }
    if rows == 0 {
        problems.push("no `What it covers` table found in src/lib.rs".to_owned());
    }
    if problems.is_empty() {
        Ok(claims)
    } else {
        Err(problems)
    }
}

fn record_row(
    area: &str,
    cell: &str,
    claims: &mut BTreeMap<String, Claim>,
) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let mut last_namespace: Option<String> = None;
    for (token, note) in cell_tokens(cell) {
        if let Some(short) = token.strip_suffix(".*") {
            let Some(count) = leading_number(&note) else {
                problems.push(format!(
                    "{area}: `{token}` needs a method count, as in `{short}.* (13 methods)`"
                ));
                continue;
            };
            let claim = claims.entry(short.to_owned()).or_default();
            claim.areas.insert(area.to_owned());
            claim.shorthand = Some(count);
            last_namespace = Some(short.to_owned());
            continue;
        }
        let (namespace, method) = if let Some((namespace, method)) = split_method(&token) {
            (namespace.to_owned(), method.to_owned())
        } else if let Some(current) = last_namespace.clone() {
            (current, token.clone())
        } else {
            problems.push(format!(
                "{area}: `{token}` carries no namespace and follows nothing that names one"
            ));
            continue;
        };
        let command = format!("{namespace}.{method}");
        let claim = claims.entry(namespace.clone()).or_default();
        claim.areas.insert(area.to_owned());
        last_namespace = Some(namespace);
        if is_implicit(&note) {
            claim.implicit.insert(command);
        } else {
            claim.explicit.insert(command);
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Everything wrong with the table, compared against `scan`.
fn mismatches(claims: &BTreeMap<String, Claim>, scan: &Scan) -> Vec<String> {
    let mut problems = Vec::new();
    for (namespace, claim) in claims {
        let areas = claim.areas.iter().cloned().collect::<Vec<_>>().join("+");
        match scan.dispatched.get(namespace) {
            None => {
                if !claim.explicit.is_empty() {
                    problems.push(format!(
                        "{areas}: `{namespace}.*` is tabled, but src/ dispatches no {namespace} command"
                    ));
                }
            }
            Some(real) => {
                if let Some(count) = claim.shorthand {
                    if count != real.len() {
                        problems.push(format!(
                            "{areas}: `{namespace}.* ({count} methods)`, but src/ dispatches {}: {}",
                            real.len(),
                            real.iter().cloned().collect::<Vec<_>>().join(", ")
                        ));
                    }
                }
                for claimed in &claim.explicit {
                    if !real.contains(claimed) {
                        problems.push(format!("{areas}: {claimed} is tabled but never dispatched"));
                    }
                }
                if claim.shorthand.is_none() {
                    for actual in real {
                        if !claim.explicit.contains(actual) {
                            problems
                                .push(format!("{areas}: {actual} is dispatched but not tabled"));
                        }
                    }
                }
            }
        }
        for claimed in &claim.implicit {
            if !scan.literals.contains(claimed) {
                problems.push(format!(
                    "{areas}: {claimed} is tabled as implicit but appears nowhere in src/"
                ));
            }
        }
    }
    for namespace in scan.dispatched.keys() {
        if !claims.contains_key(namespace) {
            problems.push(format!(
                "src/ dispatches {namespace}.* but the table has no row for that namespace"
            ));
        }
    }
    problems
}

/// Every problem with the table as it appears in `lib`.
fn table_problems(lib: &str) -> Vec<String> {
    let scan = scan_sources();
    match coverage_table(lib) {
        Ok(claims) => mismatches(&claims, &scan),
        Err(problems) => problems,
    }
}

/// Replace the first occurrence of `needle`, panicking if it is absent.
fn replace_once(lib: &str, needle: &str, replacement: &str) -> String {
    lib.split_once(needle).map_or_else(
        || panic!("the table has no {needle:?}"),
        |(head, tail)| format!("{head}{replacement}{tail}"),
    )
}

/// The table with every line mentioning `needle` removed.
fn without_line(lib: &str, needle: &str) -> String {
    lib.lines()
        .filter(|line| !line.contains(needle))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn coverage_table_matches_the_dispatched_commands() {
    let problems = table_problems(&lib_source());
    assert_eq!(problems.join("\n"), String::new());
}

#[test]
fn certificate_count_is_right_at_the_boundary() {
    let lib = lib_source();
    // Just inside: the count the sources really dispatch.
    assert_eq!(table_problems(&lib).join("\n"), String::new());
    // One off in either direction is a lie about coverage.
    for wrong in ["(12 methods)", "(14 methods)"] {
        let mutated = replace_once(
            &lib,
            "`certificate.*` (13 methods)",
            &format!("`certificate.*` {wrong}"),
        );
        let problems = table_problems(&mutated);
        assert_eq!(
            problems.len(),
            1,
            "expected one problem for {wrong}: {problems:?}"
        );
        assert!(problems[0].contains("certificate"), "{problems:?}");
    }
}

#[test]
fn dyndns_subscription_row_covers_exactly_four_commands() {
    let lib = lib_source();
    assert_eq!(table_problems(&lib).join("\n"), String::new());
    // Just outside on the small side: dropping a dispatched command.
    let dropped = replace_once(&lib, "`dyndnssubscription.list`, ", "");
    let problems = table_problems(&dropped);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("dyndnssubscription.list"),
        "{problems:?}"
    );
    // Just outside on the large side: promising a command that does not exist.
    let added = replace_once(
        &lib,
        "`dyndnssubscription.listProducts`",
        "`dyndnssubscription.listProducts`, `dyndnssubscription.renew`",
    );
    let problems = table_problems(&added);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("dyndnssubscription.renew is tabled but never dispatched")
            || problems[0].contains("never dispatched"),
        "{problems:?}"
    );
}

#[test]
fn a_tabled_command_must_be_dispatched() {
    let mutated = replace_once(
        &lib_source(),
        "`domain.whois`",
        "`domain.whois`, `domain.order`",
    );
    let problems = table_problems(&mutated);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("domain.order is tabled but never dispatched"),
        "{problems:?}"
    );
}

#[test]
fn dropping_a_namespace_row_is_reported() {
    // The exact regression from issue #50: a module with real RPC calls and no
    // row in the table.
    let mutated = without_line(&lib_source(), "DynDNS subscriptions");
    let problems = table_problems(&mutated);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("dyndnssubscription"),
        "the missing row must be named: {problems:?}"
    );
}

#[test]
fn an_implicit_claim_must_still_appear_in_the_sources() {
    let lib = lib_source();
    assert_eq!(table_problems(&lib).join("\n"), String::new());
    let bogus = replace_once(
        &lib,
        "`account.check` (implicit)",
        "`account.checkmate` (implicit)",
    );
    let problems = table_problems(&bogus);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("account.checkmate"), "{problems:?}");
}

#[test]
fn validation_labels_are_not_counted_as_commands() {
    // `certificate.order` and `certificate.update` are `Error::validation`
    // field names, not RPC commands; counting them would inflate the row.
    let scan = scan_sources();
    let certificate = scan
        .dispatched
        .get("certificate")
        .unwrap_or_else(|| panic!("certificate commands were not found at all"));
    assert_eq!(certificate.len(), 13);
    assert!(!certificate.contains("certificate.order"));
    assert!(!certificate.contains("certificate.update"));
    assert!(certificate.contains("certificate.updateOrder"));
}

#[test]
fn subscription_list_commands_travel_through_the_helper() {
    let path = manifest_dir().join("src").join("dyndnssubscription.rs");
    let chars: Vec<char> = read_utf8(&path).chars().collect();
    let mut through_helper = BTreeSet::new();
    for (offset, literal) in string_literals(&chars) {
        if split_method(&literal).is_some()
            && callee_before(&chars, offset).is_some_and(|callee| callee == "dyndns_subscriptions")
        {
            through_helper.insert(literal);
        }
    }
    let expected: BTreeSet<String> = ["dyndnssubscription.list", "dyndnssubscription.listProducts"]
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    assert_eq!(through_helper, expected);
}

#[test]
fn every_module_that_dispatches_is_tabled() {
    let scan = scan_sources();
    let claims = coverage_table(&lib_source()).unwrap_or_else(|problems| {
        panic!("the table does not parse: {}", problems.join("\n"));
    });
    let mut missing = Vec::new();
    for line in lib_source().lines() {
        let Some(rest) = line.trim().strip_prefix("pub mod ") else {
            continue;
        };
        let module = rest.trim_end().trim_end_matches(';').trim();
        let Some(namespaces) = scan.files.get(&format!("{module}.rs")) else {
            continue;
        };
        for namespace in namespaces {
            if !claims.contains_key(namespace) {
                missing.push(format!(
                    "{module}.rs dispatches {namespace}.* with no table row"
                ));
            }
        }
    }
    assert_eq!(missing.join(", "), String::new());
    // Guard against a scan so broken that every assertion above is vacuous.
    assert!(scan.dispatched.len() >= 10);
    let total: usize = scan.dispatched.values().map(BTreeSet::len).sum();
    assert!(total >= 90, "only {total} commands were scanned");
}
