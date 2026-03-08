//! VeraCrypt container reader.
//!
//! [`veracrypt::Volume`] decrypts a container header and exposes the decrypted
//! data area as a seekable block device. The [`fs`] module sits on top of that
//! block device and browses the filesystem it contains (exFAT or NTFS).

pub mod fs;
pub mod veracrypt;
