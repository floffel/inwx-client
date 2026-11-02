//! Keeps the panic-freedom lint gate intact (issue #136).
//!
//! The crate root denies `clippy::unwrap_used`, `clippy::expect_used`,
//! `clippy::panic`, `clippy::todo`, `clippy::unimplemented` and
//! `clippy::indexing_slicing`. All six live in the `restriction` group, which
//! neither `clippy::all` nor `clippy::pedantic` turns on — so if the attribute
//! is deleted, moved behind a feature or overridden by a module-level
//! `#[allow]`, the compiler stays green and the next `unwrap()` on an
//! API-controlled value ships. Nothing in `cargo test` notices that today;
//! these tests do.
//!
//! The allow for test code is the one exception, and it has to stay scoped to
//! `cfg(test)`: an unconditional allow would silence the library as well.

use std::fs;
use std::path::{Path, PathBuf};

/// Lints the crate root must deny for library code.
const DENIED: &[&str] = &[
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::panic",
    "clippy::todo",
    "clippy::unimplemented",
    "clippy::indexing_slicing",
];

/// Text fragments that mean "this can panic", checked in library code.
const PANIC_FRAGMENTS: &[&str] = &[
    ".unwrap()",
    ".expect(",
    "panic!(",
    "todo!(",
    "unimplemented!(",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()))
}

fn lib_source() -> String {
    read(&manifest_dir().join("src").join("lib.rs"))
}

/// Every `src/*.rs` file, sorted by name.
fn source_files() -> Vec<PathBuf> {
    let dir = manifest_dir().join("src");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("src/ is readable")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("rs"))
        .collect();
    files.sort();
    files
}

/// The `#![...]` attribute starting at `start`, as `(end, text)` byte offsets
/// into `source`; `end` is just past the closing `]`.
fn attribute_at(source: &str, start: usize, prefix: &str) -> Option<(usize, String)> {
    let open = start + prefix.len() - 1;
    let tail = source.get(open..)?;
    let mut depth = 0_usize;
    for (offset, character) in tail.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let close = open + offset + 1;
                    let end = close + source.get(close..)?.find(']')? + 1;
                    return Some((end, source.get(start..end)?.to_owned()));
                }
            }
            _ => {}
        }
    }
    None
}

/// Every crate-level attribute that starts with `prefix`, as `(start, end, text)`.
fn attributes(source: &str, prefix: &str) -> Vec<(usize, usize, String)> {
    let mut found = Vec::new();
    let mut cursor = 0_usize;
    while let Some(offset) = source.get(cursor..).and_then(|tail| tail.find(prefix)) {
        let start = cursor + offset;
        let Some((end, text)) = attribute_at(source, start, prefix) else {
            break;
        };
        found.push((start, end, text));
        cursor = end;
    }
    found
}

/// `source` with the comment lines removed: a doc comment may name a lint, an
/// attribute is what actually sets one.
fn code_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `source` with the sorted, non-overlapping `ranges` removed.
fn without_ranges(source: &str, ranges: &[(usize, usize)]) -> String {
    let mut sorted = ranges.to_vec();
    sorted.sort_unstable();
    let mut out = String::with_capacity(source.len());
    let mut cursor = 0_usize;
    for (start, end) in sorted {
        if let Some(head) = source.get(cursor..start) {
            out.push_str(head);
        }
        cursor = end;
    }
    if let Some(tail) = source.get(cursor..) {
        out.push_str(tail);
    }
    out
}

#[test]
fn crate_root_denies_every_panic_lint() {
    let source = lib_source();
    let blocks = attributes(&source, "#![deny(");
    let gated = blocks
        .iter()
        .any(|(_, _, text)| DENIED.iter().all(|lint| text.contains(lint)));
    assert!(
        gated,
        "no crate-level #![deny(..)] lists all of {DENIED:?}; found: {:?}",
        blocks
            .iter()
            .map(|(_, _, text)| text.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_panic_lints_are_allowed_only_under_cfg_test() {
    let source = lib_source();
    let allow_blocks = attributes(&source, "#![cfg_attr(");
    let scoped: Vec<&(usize, usize, String)> = allow_blocks
        .iter()
        .filter(|(_, _, text)| text.contains("test,"))
        .collect();
    assert_eq!(
        scoped.len(),
        1,
        "expected exactly one #![cfg_attr(test, ..)] at the crate root"
    );
    let allow = &scoped[0].2;
    for lint in DENIED {
        assert!(
            allow.contains(lint),
            "the cfg(test) allow does not cover {lint}, so test code cannot compile"
        );
    }

    // Anything left over names a denied lint outside a crate-level attribute —
    // a module-level `#[allow(clippy::unwrap_used)]` or a second deny that a
    // later review would have to find by hand.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for (start, end, _) in attributes(&source, "#![deny(") {
        ranges.push((start, end));
    }
    for (start, end, _) in &allow_blocks {
        ranges.push((*start, *end));
    }
    let stripped = code_lines(&without_ranges(&source, &ranges));
    for lint in DENIED {
        assert!(
            !stripped.contains(lint),
            "lib.rs names {lint} outside a crate-level attribute"
        );
    }
    for path in source_files() {
        if path.file_name().and_then(|name| name.to_str()) == Some("lib.rs") {
            continue;
        }
        let text = code_lines(&read(&path));
        for lint in DENIED {
            assert!(
                !text.contains(lint),
                "{} allows or denies {lint} locally",
                path.display()
            );
        }
    }
}

#[test]
fn library_code_carries_no_panic_path() {
    for path in source_files() {
        let source = read(&path);
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source.as_str(), |(before, _)| before);
        for (index, line) in production.lines().enumerate() {
            // Doc comments hold the examples, and those are allowed to unwrap.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for fragment in PANIC_FRAGMENTS {
                assert!(
                    !line.contains(fragment),
                    "{}:{}: `{fragment}` in library code",
                    path.display(),
                    index + 1
                );
            }
        }
    }
}

#[test]
fn the_lint_runs_in_ci() {
    let workflow = read(
        &manifest_dir()
            .join(".github")
            .join("workflows")
            .join("ci.yml"),
    );
    assert!(
        workflow.contains("cargo clippy --all-targets --all-features -- -D warnings"),
        "CI no longer runs clippy over all targets with -D warnings"
    );
}
