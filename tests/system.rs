//! Generic end-to-end system test.
//!
//! Decrypts a VeraCrypt container, mounts whatever filesystem it holds — exFAT
//! or NTFS, the assertions don't care which — and verifies the known directory
//! tree produced by `resources/make_test_tree.sh`:
//!
//! ```text
//! root_file.txt              (file, > 32 bytes)
//! empty_file.txt             (empty file)
//! empty_dir/                 (empty directory)
//! dir_a/
//!   inside_a.txt             (file, > 32 bytes)
//!   empty_inside.txt         (empty file)
//!   dir_b/
//!     deep.txt               (file, > 32 bytes — file within a dir within a dir)
//! ```
//!
//! To cover an additional container (e.g. an exFAT one), populate it with
//! `make_test_tree.sh` and add a `#[test]` that calls [`check_container`] with
//! its path and password.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::ErrorKind;

use vc_reader::fs::{self, Entry, Filesystem};
use vc_reader::veracrypt::Volume;

/// The content `make_test_tree.sh` writes into each non-empty file (the script
/// adds a trailing newline). Comfortably larger than the 32-byte threshold.
const BIG: &str = "The quick brown fox jumps over the lazy dog 0123456789.";

/// Expected bytes of a non-empty file: `BIG` plus the script's trailing newline.
fn big_contents() -> Vec<u8> {
    format!("{BIG}\n").into_bytes()
}

#[test]
fn ntfs_container() {
    check_container(
        concat!(env!("CARGO_MANIFEST_DIR"), "/resources/test_ntfs.vc"),
        b"1",
    );
}

// Future exFAT coverage is just another fixture + one line:
//
// #[test]
// fn exfat_container() {
//     check_container(
//         concat!(env!("CARGO_MANIFEST_DIR"), "/resources/test_exfat.vc"),
//         b"1",
//     );
// }

/// Decrypt and mount `path`, then run every structure and extraction check
/// against it. Filesystem-agnostic: it works for any backend [`fs::open`]
/// supports.
fn check_container(path: &str, password: &[u8]) {
    let mut volume = mount(path, password);
    check_tree(volume.as_mut());
    check_content_extraction(volume.as_mut());
    check_empty_extraction(volume.as_mut());
    check_nested_extraction(volume.as_mut());
    check_missing_file(volume.as_mut());
}

/// Decrypt the container and mount whatever filesystem it contains.
fn mount(path: &str, password: &[u8]) -> Box<dyn Filesystem> {
    let file = File::open(path).expect("test fixture missing");
    let mut vol = Volume::open(file, password).expect("container should decrypt");
    let kind = fs::detect(&mut vol).expect("filesystem detection should succeed");
    assert!(kind.is_supported(), "unsupported filesystem: {}", kind.name());
    fs::open(vol, kind).expect("filesystem should mount")
}

/// The directory tree is listed with the right files, directories, and sizes.
fn check_tree(volume: &mut dyn Filesystem) {
    let tree: BTreeMap<String, Entry> = volume
        .list()
        .expect("listing should succeed")
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();

    let big_size = big_contents().len() as u64;
    assert!(big_size > 32, "test content must exceed the AES block size");

    let dir = |path: &str| {
        let e = tree.get(path).unwrap_or_else(|| panic!("missing directory {path}"));
        assert!(e.is_dir, "{path} should be a directory");
    };
    let file = |path: &str, size: u64| {
        let e = tree.get(path).unwrap_or_else(|| panic!("missing file {path}"));
        assert!(!e.is_dir, "{path} should be a file");
        assert_eq!(e.size, size, "size of {path}");
    };

    // A file on the root, and an empty file on the root.
    file("root_file.txt", big_size);
    file("empty_file.txt", 0);

    // An empty directory.
    dir("empty_dir");

    // A directory with a file in it and an empty file in it.
    dir("dir_a");
    file("dir_a/inside_a.txt", big_size);
    file("dir_a/empty_inside.txt", 0);

    // A file within a directory within a directory.
    dir("dir_a/dir_b");
    file("dir_a/dir_b/deep.txt", big_size);
}

/// Files with content extract to exactly the bytes that were written.
fn check_content_extraction(volume: &mut dyn Filesystem) {
    for path in ["root_file.txt", "dir_a/inside_a.txt", "dir_a/dir_b/deep.txt"] {
        let mut buf = Vec::new();
        volume.extract(path, &mut buf).expect("extraction should succeed");
        assert_eq!(buf, big_contents(), "contents of {path}");
    }
}

/// Empty files extract to nothing.
fn check_empty_extraction(volume: &mut dyn Filesystem) {
    for path in ["empty_file.txt", "dir_a/empty_inside.txt"] {
        let mut buf = Vec::new();
        volume.extract(path, &mut buf).expect("extraction should succeed");
        assert!(buf.is_empty(), "{path} should extract to nothing");
    }
}

/// Extracting through two directory levels resolves the path correctly.
fn check_nested_extraction(volume: &mut dyn Filesystem) {
    let mut buf = Vec::new();
    volume
        .extract("dir_a/dir_b/deep.txt", &mut buf)
        .expect("nested extraction should succeed");
    assert_eq!(buf, big_contents());
}

/// Extracting a path that does not exist is reported as `NotFound`.
fn check_missing_file(volume: &mut dyn Filesystem) {
    let mut buf = Vec::new();
    let err = volume
        .extract("dir_a/nope.txt", &mut buf)
        .expect_err("missing file should error");
    assert_eq!(err.kind(), ErrorKind::NotFound);
}
