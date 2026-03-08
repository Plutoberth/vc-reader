//! NTFS backend, built on the `ntfs` crate.

use std::io::{self, Write};

use ntfs::structured_values::NtfsFileNamespace;
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};

use super::{Entry, Filesystem};
use crate::veracrypt::Volume;

/// An NTFS filesystem mounted on a decrypted volume.
///
/// `Ntfs` owns the parsed boot-sector metadata and only borrows the reader for
/// the duration of each call, so it can live alongside the [`Volume`] here.
pub struct NtfsFs {
    vol: Volume,
    ntfs: Ntfs,
}

impl NtfsFs {
    pub fn open(mut vol: Volume) -> io::Result<Self> {
        let ntfs = Ntfs::new(&mut vol).map_err(to_io)?;
        Ok(Self { vol, ntfs })
    }
}

impl Filesystem for NtfsFs {
    fn label(&mut self) -> Option<String> {
        let name = self.ntfs.volume_name(&mut self.vol)?.ok()?;
        name.name().to_string().ok()
    }

    fn list(&mut self) -> io::Result<Vec<Entry>> {
        let root = self.ntfs.root_directory(&mut self.vol).map_err(to_io)?;
        let mut out = Vec::new();
        walk(&self.ntfs, &mut self.vol, &root, "", &mut out)?;
        Ok(out)
    }

    fn extract(&mut self, path: &str, out: &mut dyn Write) -> io::Result<()> {
        let mut current = self.ntfs.root_directory(&mut self.vol).map_err(to_io)?;
        let mut components = path.split('/').peekable();

        while let Some(component) = components.next() {
            let child = find_child(&self.ntfs, &mut self.vol, &current, component)?
                .ok_or_else(|| not_found(path))?;

            if components.peek().is_none() {
                return read_data(&mut self.vol, &child, out);
            }
            if !child.is_directory() {
                return Err(not_found(path));
            }
            current = child;
        }

        Err(not_found(path))
    }
}

/// Recursively collect every user-visible file and directory under `dir`.
fn walk(
    ntfs: &Ntfs,
    fs: &mut Volume,
    dir: &NtfsFile<'_>,
    prefix: &str,
    out: &mut Vec<Entry>,
) -> io::Result<()> {
    let index = dir.directory_index(fs).map_err(to_io)?;
    let mut entries = index.entries();

    while let Some(entry) = entries.next(fs) {
        let entry = entry.map_err(to_io)?;
        let name = match entry.key() {
            Some(key) => key.map_err(to_io)?,
            None => continue,
        };

        // Each file is indexed once per name namespace; skip the 8.3 DOS alias
        // so we don't list it twice.
        if name.namespace() == NtfsFileNamespace::Dos {
            continue;
        }
        let filename = name.name().to_string().map_err(to_io)?;
        // Skip the "." self-reference and the NTFS metafiles ($MFT, $Bitmap, …).
        if filename == "." || filename.starts_with('$') {
            continue;
        }

        let file = entry.to_file(ntfs, fs).map_err(to_io)?;
        let is_dir = file.is_directory();
        let path = format!("{prefix}{filename}");
        let size = if is_dir { 0 } else { data_len(fs, &file)? };

        out.push(Entry { path: path.clone(), size, is_dir });
        if is_dir {
            walk(ntfs, fs, &file, &format!("{path}/"), out)?;
        }
    }

    Ok(())
}

/// Find the immediate child of `dir` whose name equals `name`.
fn find_child<'n>(
    ntfs: &'n Ntfs,
    fs: &mut Volume,
    dir: &NtfsFile<'n>,
    name: &str,
) -> io::Result<Option<NtfsFile<'n>>> {
    let index = dir.directory_index(fs).map_err(to_io)?;
    let mut entries = index.entries();

    while let Some(entry) = entries.next(fs) {
        let entry = entry.map_err(to_io)?;
        let key = match entry.key() {
            Some(key) => key.map_err(to_io)?,
            None => continue,
        };
        if key.namespace() == NtfsFileNamespace::Dos {
            continue;
        }
        if key.name().to_string().map_err(to_io)? == name {
            return Ok(Some(entry.to_file(ntfs, fs).map_err(to_io)?));
        }
    }

    Ok(None)
}

/// Length of a file's unnamed `$DATA` stream (`0` if it has none).
fn data_len(fs: &mut Volume, file: &NtfsFile<'_>) -> io::Result<u64> {
    match file.data(fs, "") {
        Some(item) => {
            let item = item.map_err(to_io)?;
            let attribute = item.to_attribute().map_err(to_io)?;
            Ok(attribute.value_length())
        }
        None => Ok(0),
    }
}

/// Stream a file's unnamed `$DATA` stream into `out`.
fn read_data(fs: &mut Volume, file: &NtfsFile<'_>, out: &mut dyn Write) -> io::Result<()> {
    let item = match file.data(fs, "") {
        Some(item) => item.map_err(to_io)?,
        None => return Ok(()), // no unnamed data stream → empty file
    };
    let attribute = item.to_attribute().map_err(to_io)?;
    let mut value = attribute.value(fs).map_err(to_io)?;

    let mut buf = [0u8; 8192];
    loop {
        let read = value.read(fs, &mut buf).map_err(to_io)?;
        if read == 0 {
            break;
        }
        out.write_all(&buf[..read])?;
    }
    Ok(())
}

fn not_found(path: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("path not found in volume: {path}"))
}

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}
