//! The documented first run must not write to a production zone (issue #134).
//!
//! The crate-level docs and the README are the copy-paste path a new user
//! follows: build a client, call a method. When that example builds the client
//! with `InwxClient::new`, the first thing a reader does after `cargo add` is
//! create — and delete — a record in a live zone. Both snippets are `no_run`,
//! so nothing in the suite would ever notice; the reader notices, after the
//! record was already gone.
//!
//! These tests read the docs as text and fail when a fenced block that reaches
//! for a real HTTP transport and calls a mutating method does not name the
//! sandbox. The scope is the documented first-run path — `src/lib.rs` and
//! `README.md`. Per-method docs (`create_record`'s own page, for instance)
//! describe exactly one command and are deliberately not scanned here.

use std::fs;
use std::path::PathBuf;

/// Methods whose call changes state at the endpoint.
const MUTATING: &[&str] = &[
    "create_record",
    "delete_record",
    "update_record",
    "create_domain",
    "update_domain",
    "delete_domain",
    "renew_domain",
    "transfer",
    "create_zone",
    "update_zone",
    "delete_zone",
    "create_contact",
    "update_contact",
    "delete_contact",
];

/// Markers that mean "this block is not aimed at production".
const SANDBOX_MARKERS: &[&str] = &["InwxClient::sandbox", "SANDBOX_BASE_URL", "with_base_url"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = manifest_dir().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()))
}

/// Every fenced code block with the line number of its opening fence.
fn fenced_blocks(markdown: &str) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut opening: Option<(usize, String)> = None;
    for (index, line) in markdown.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            match opening.take() {
                None => opening = Some((index + 1, String::new())),
                Some(block) => blocks.push(block),
            }
            continue;
        }
        if let Some((_, ref mut body)) = opening {
            body.push_str(line);
            body.push('\n');
        }
    }
    // An unterminated fence is a doc bug of its own; treating it as a block is
    // the safe direction, because it can only add findings, never hide one.
    if let Some(block) = opening {
        blocks.push(block);
    }
    blocks
}

/// Opening lines of the blocks that would write to production on copy-paste.
///
/// A block qualifies when it mentions a real HTTP transport
/// (`ReqwestTransport`), calls a mutating method, and names neither the sandbox
/// constructor nor a sandbox base URL.
fn production_mutators(markdown: &str) -> Vec<usize> {
    fenced_blocks(markdown)
        .into_iter()
        .filter(|(_, body)| {
            body.contains("ReqwestTransport")
                && MUTATING
                    .iter()
                    .any(|method| body.contains(&format!(".{method}(")))
                && !SANDBOX_MARKERS.iter().any(|marker| body.contains(marker))
        })
        .map(|(line, _)| line)
        .collect()
}

/// Just outside: a production block that creates a record is reported.
#[test]
fn flags_a_production_block_that_writes() {
    let doc = "\
# Example

```no_run
let client = InwxClient::new(ReqwestTransport::new());
client.create_record(&domain, &record).await?;
```
";
    assert_eq!(production_mutators(doc), vec![3]);
}

/// Just outside, the quiet variant: `delete_record` alone is enough.
#[test]
fn flags_a_production_block_that_only_deletes() {
    let doc = "\
```no_run
let transport = ReqwestTransport::new();
let client = InwxClient::new(transport);
client.delete_record(&id).await?;
```
";
    assert_eq!(production_mutators(doc), vec![1]);
}

/// Just inside: the same block spelled against the sandbox is accepted.
#[test]
fn accepts_the_sandbox_constructor() {
    let doc = "\
```no_run
let client = InwxClient::sandbox(ReqwestTransport::new());
client.create_record(&domain, &record).await?;
client.delete_record(&id).await?;
```
";
    assert!(production_mutators(doc).is_empty());
}

/// Just inside, the other spelling: a client that was pointed at
/// `SANDBOX_BASE_URL` by hand.
#[test]
fn accepts_an_explicit_sandbox_base_url() {
    let doc = "\
```no_run
let client = InwxClient::new(ReqwestTransport::new()).with_base_url(SANDBOX_BASE_URL);
client.delete_record(&id).await?;
```
";
    assert!(production_mutators(doc).is_empty());
}

/// Just inside: a read-only production block is fine — reading a live zone is
/// exactly what a first run against production may do.
#[test]
fn accepts_a_read_only_production_block() {
    let doc = "\
```no_run
let client = InwxClient::new(ReqwestTransport::new());
for record in client.list_records(&domain).await? { println!(\"{record:?}\"); }
```
";
    assert!(production_mutators(doc).is_empty());
}

/// Just inside: a scripted transport touches nothing, so it needs no marker.
#[test]
fn accepts_a_scripted_transport() {
    let doc = "\
```
let client = InwxClient::new(Scripted);
client.create_record(&domain, &record).await?;
```
";
    assert!(production_mutators(doc).is_empty());
}

/// The crate-level docs are the first thing rustdoc shows.
#[test]
fn crate_docs_start_in_the_sandbox() {
    let source = read("src/lib.rs");
    assert_eq!(
        production_mutators(&source),
        Vec::<usize>::new(),
        "a fenced block in src/lib.rs writes to production; use `InwxClient::sandbox`"
    );
}

/// And the same rule holds for the README, which is what the crate page shows.
#[test]
fn readme_starts_in_the_sandbox() {
    let readme = read("README.md");
    assert_eq!(
        production_mutators(&readme),
        Vec::<usize>::new(),
        "a fenced block in README.md writes to production; use `InwxClient::sandbox`"
    );
}

/// Neither document may leave the sandbox unnamed: the constant is the thing a
/// reader needs in order to find the endpoint they are actually talking to.
#[test]
fn both_documents_name_the_sandbox_endpoint() {
    for relative in ["src/lib.rs", "README.md"] {
        let text = read(relative);
        assert!(
            text.contains("SANDBOX_BASE_URL"),
            "{relative} never mentions SANDBOX_BASE_URL"
        );
        assert!(
            text.contains("api.ote.domrobot.com"),
            "{relative} never spells out the sandbox host"
        );
    }
}
