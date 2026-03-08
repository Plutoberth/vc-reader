#!/usr/bin/env bash
#
# Populate a mounted VeraCrypt volume with the known directory tree that the
# system test (tests/system_ntfs.rs) expects.
#
# Run it with the volume's mount point as the first argument (defaults to the
# current directory). IMPORTANT: use forward slashes — running these commands
# with backslashes in bash escapes the separators and produces flat, mangled
# names instead of a real tree.
#
#     ./make_test_tree.sh /mnt/veracrypt1
#
# Afterwards, unmount and copy the container over resources/test_ntfs.vc so the
# system test runs against this tree.
set -euo pipefail

root="${1:-.}"
cd "$root"

# Content larger than the 32-byte threshold, reused for the non-empty files.
big='The quick brown fox jumps over the lazy dog 0123456789.'

# 1. A file at the volume root (with content > 32 bytes).
printf '%s\n' "$big" > root_file.txt

# 2. An empty file at the root.
: > empty_file.txt

# 3. An empty directory.
mkdir -p empty_dir

# 4. A file inside a directory, plus an empty file inside that same directory.
mkdir -p dir_a
printf '%s\n' "$big" > dir_a/inside_a.txt
: > dir_a/empty_inside.txt

# 5. A file inside a directory inside a directory.
mkdir -p dir_a/dir_b
printf '%s\n' "$big" > dir_a/dir_b/deep.txt

sync
echo "Created test tree under: $(pwd)"
