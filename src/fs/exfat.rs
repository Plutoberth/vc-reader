//! exFAT backend, built on the `exfat-fs` crate.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Mutex;

use exfat_fs::dir::Root;
use exfat_fs::dir::entry::fs::FsElement;
use exfat_fs::disk::ReadOffset;

use super::{Entry, Filesystem};
use crate::veracrypt::Volume;

/// Adapts a [`Volume`] to the random-access [`ReadOffset`] trait that
/// `exfat-fs` reads through. The [`Mutex`] gives the interior mutability that
/// `read_at(&self, …)` requires.
#[derive(Debug)]
struct VolumeDisk(Mutex<Volume>);

impl ReadOffset for VolumeDisk {
    type Err = io::Error;

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, Self::Err> {
        let mut vol = self.0.lock().unwrap();
        vol.seek(SeekFrom::Start(offset))?;
        vol.read(buffer)
    }
}

/// An exFAT filesystem mounted on a decrypted volume.
pub struct ExfatFs {
    root: Root<VolumeDisk>,
}

impl ExfatFs {
    pub fn open(vol: Volume) -> io::Result<Self> {
        let disk = VolumeDisk(Mutex::new(vol));
        let root = Root::open(disk).map_err(to_io)?;
        Ok(Self { root })
    }
}

impl Filesystem for ExfatFs {
    fn label(&mut self) -> Option<String> {
        self.root.label().map(|l| format!("{l}"))
    }

    fn list(&mut self) -> io::Result<Vec<Entry>> {
        let mut out = Vec::new();
        collect(self.root.items(), "", &mut out);
        Ok(out)
    }

    fn extract(&mut self, path: &str, out: &mut dyn Write) -> io::Result<()> {
        extract_from(self.root.items(), path, out)
    }
}

/// Recursively collect every file and directory under `items`.
fn collect(items: &mut [FsElement<VolumeDisk>], prefix: &str, out: &mut Vec<Entry>) {
    for item in items.iter_mut() {
        match item {
            FsElement::F(f) => out.push(Entry {
                path: format!("{prefix}{}", f.name()),
                size: f.len(),
                is_dir: false,
            }),
            FsElement::D(d) => {
                let path = format!("{prefix}{}", d.name());
                out.push(Entry { path: path.clone(), size: 0, is_dir: true });
                if let Ok(mut children) = d.open() {
                    collect(&mut children, &format!("{path}/"), out);
                }
            }
        }
    }
}

/// Walk `items` along `target` (a slash-separated path) and stream the file.
fn extract_from(
    items: &mut [FsElement<VolumeDisk>],
    target: &str,
    out: &mut dyn Write,
) -> io::Result<()> {
    let (head, tail) = match target.split_once('/') {
        Some((h, t)) => (h, t),
        None => (target, ""),
    };

    for item in items.iter_mut() {
        match item {
            FsElement::F(f) if tail.is_empty() && f.name() == head => {
                io::copy(f, out)?;
                return Ok(());
            }
            FsElement::D(d) if !tail.is_empty() && d.name() == head => {
                let mut children = d.open().map_err(to_io)?;
                return extract_from(&mut children, tail, out);
            }
            _ => {}
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "file not found in volume"))
}

/// `exfat-fs` errors are `Debug`-only, so render them into an `io::Error`.
fn to_io<E: std::fmt::Debug>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{e:?}"))
}
