//! Guard test for the append-only invariant.
//!
//! The audit chain is only sound if events are never updated or deleted. We enforce this in
//! two complementary ways at deploy time (the audit DB user is granted INSERT/SELECT only) and
//! here in the code itself: NO source file may contain an SQL `UPDATE`/`DELETE` mutation verb.
//! All SQL in this crate is uppercase inside string literals (SELECT/INSERT/CREATE), while the
//! prose that *describes* this invariant uses lowercase "update"/"delete" — so scanning for the
//! uppercase SQL tokens cleanly distinguishes a real mutation statement from a comment.

use std::path::Path;

fn collect_rs(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

#[test]
fn no_update_or_delete_sql_in_source() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src, &mut files);
    assert!(!files.is_empty(), "expected to scan src/*.rs");

    for file in files {
        let body = std::fs::read_to_string(&file).expect("read source file");
        for token in ["UPDATE", "DELETE"] {
            // Match the uppercase SQL verb as a standalone word.
            let found = body
                .match_indices(token)
                .any(|(i, _)| is_word_boundary(&body, i, token.len()));
            assert!(
                !found,
                "source mutation verb `{token}` found in {} — the audit log must be append-only \
                 (no update/delete code path)",
                file.display()
            );
        }
    }
}

fn is_word_boundary(s: &str, start: usize, len: usize) -> bool {
    let before_ok = start == 0
        || !s.as_bytes()[start - 1].is_ascii_alphanumeric() && s.as_bytes()[start - 1] != b'_';
    let end = start + len;
    let after_ok =
        end >= s.len() || !s.as_bytes()[end].is_ascii_alphanumeric() && s.as_bytes()[end] != b'_';
    before_ok && after_ok
}
