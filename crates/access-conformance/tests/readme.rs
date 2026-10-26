//! The README holds the table of keys of the code, and the example profiles of the README exist.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

fn readme() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap()
}

#[test]
fn the_readme_holds_the_table_of_keys_of_the_code() {
    let table = access_conformance::reference_table();
    assert!(
        readme().contains(&table),
        "The README must hold this table. Copy it from `access_conformance::reference_table()`:\n{table}"
    );
}

#[test]
fn each_example_file_that_the_readme_names_exists() {
    let text = readme();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut count = 0;
    for word in text.split(|c: char| c.is_whitespace() || c == '`' || c == ',') {
        if let Some(name) = word.strip_prefix("examples/") {
            let name = name.trim_end_matches(['.', ')', ':']);
            assert!(
                dir.join("examples").join(name).is_file(),
                "examples/{name} is missing"
            );
            count += 1;
        }
    }
    assert!(count >= 4, "the README names {count} example files");
}
