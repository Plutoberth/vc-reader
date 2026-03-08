//! Reader-agnostic filesystem layer.
//!
//! A decrypted [`Volume`] is just a block device; this module turns it into a
//! browsable filesystem. Each concrete filesystem lives in its own backend
//! module ([`exfat`], [`ntfs`]) and implements the [`Filesystem`] trait, so the
//! rest of the program never needs to know which one it is talking to.
//!
//! [`detect`] sniffs the boot sector to identify the filesystem and [`open`]
//! constructs the matching backend.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::veracrypt::Volume;

mod exfat;
mod ntfs;

/// A single file or directory discovered while listing a filesystem.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Slash-separated path from the volume root (no leading slash).
    pub path: String,
    /// Size in bytes; `0` for directories.
    pub size: u64,
    /// Whether this entry is a directory.
    pub is_dir: bool,
}

/// A browsable filesystem backed by a decrypted [`Volume`].
pub trait Filesystem {
    /// The volume label, if the filesystem records one.
    fn label(&mut self) -> Option<String>;

    /// Every file and directory in the volume, in depth-first order.
    fn list(&mut self) -> io::Result<Vec<Entry>>;

    /// Stream the contents of the file at `path` into `out`.
    fn extract(&mut self, path: &str, out: &mut dyn Write) -> io::Result<()>;
}

/// A filesystem we can recognise from the boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Exfat,
    Ntfs,
    Fat32,
    Fat16,
    Fat12,
    Unknown,
}

impl FsKind {
    /// Human-readable name, as printed to the user.
    pub fn name(self) -> &'static str {
        match self {
            FsKind::Exfat => "exFAT",
            FsKind::Ntfs => "NTFS",
            FsKind::Fat32 => "FAT32",
            FsKind::Fat16 => "FAT16",
            FsKind::Fat12 => "FAT12",
            FsKind::Unknown => "unknown",
        }
    }

    /// Whether [`open`] can produce a backend for this filesystem.
    pub fn is_supported(self) -> bool {
        matches!(self, FsKind::Exfat | FsKind::Ntfs)
    }
}

/// Identify the filesystem by inspecting the volume's first sector.
pub fn detect(vol: &mut Volume) -> io::Result<FsKind> {
    let mut sector = [0u8; 512];
    vol.seek(SeekFrom::Start(0))?;
    vol.read_exact(&mut sector)?;
    vol.seek(SeekFrom::Start(0))?;

    // exFAT and NTFS carry their name in the OEM field at offset 3.
    let kind = if &sector[3..11] == b"EXFAT   " {
        FsKind::Exfat
    } else if &sector[3..11] == b"NTFS    " {
        FsKind::Ntfs
    // FAT variants carry a filesystem-type string at a fixed offset.
    } else if &sector[82..90] == b"FAT32   " {
        FsKind::Fat32
    } else if &sector[54..62] == b"FAT16   " {
        FsKind::Fat16
    } else if &sector[54..62] == b"FAT12   " {
        FsKind::Fat12
    } else {
        FsKind::Unknown
    };
    Ok(kind)
}

/// Construct the filesystem backend for an already-[`detect`]ed `kind`,
/// taking ownership of the decrypted volume.
pub fn open(vol: Volume, kind: FsKind) -> io::Result<Box<dyn Filesystem>> {
    match kind {
        FsKind::Exfat => Ok(Box::new(exfat::ExfatFs::open(vol)?)),
        FsKind::Ntfs => Ok(Box::new(ntfs::NtfsFs::open(vol)?)),
        unsupported => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported filesystem: {}", unsupported.name()),
        )),
    }
}
