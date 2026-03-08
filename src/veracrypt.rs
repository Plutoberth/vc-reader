use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::Aes256;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use ripemd::Ripemd160;
use sha2::{Sha256, Sha512};
use streebog::Streebog512;
use whirlpool::Whirlpool;

// ─── Constants ───────────────────────────────────────────────────────────────

const HEADER_SALT_SIZE: usize = 64;
const HEADER_SIZE: usize = 512;
const HEADER_ENC_OFFSET: usize = 64;
const HEADER_ENC_SIZE: usize = 448;
const DERIVED_KEY_SIZE: usize = 64;
const VERACRYPT_MAGIC: &[u8; 4] = b"VERA";

/// XTS data unit size (always 512 bytes in VeraCrypt).
pub const BLOCK_SIZE: usize = 512;

// PBKDF2 iteration counts (non-system volumes)
const ITER_SHA512: u32 = 500_000;
const ITER_SHA256: u32 = 500_000;
const ITER_RIPEMD160: u32 = 655_331;
const ITER_WHIRLPOOL: u32 = 500_000;
const ITER_STREEBOG: u32 = 500_000;

// ─── KDF (internal) ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Kdf {
    Sha512,
    Sha256,
    Ripemd160,
    Whirlpool,
    Streebog512,
}

impl std::fmt::Display for Kdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kdf::Sha512      => write!(f, "PBKDF2-HMAC-SHA-512"),
            Kdf::Sha256      => write!(f, "PBKDF2-HMAC-SHA-256"),
            Kdf::Ripemd160   => write!(f, "PBKDF2-HMAC-RIPEMD-160"),
            Kdf::Whirlpool   => write!(f, "PBKDF2-HMAC-Whirlpool"),
            Kdf::Streebog512 => write!(f, "PBKDF2-HMAC-Streebog-512"),
        }
    }
}

const ALL_KDFS: &[Kdf] = &[
    Kdf::Sha512,
    Kdf::Sha256,
    Kdf::Ripemd160,
    Kdf::Whirlpool,
    Kdf::Streebog512,
];

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum VolumeError {
    Io(io::Error),
    DecryptionFailed,
}

impl From<io::Error> for VolumeError {
    fn from(e: io::Error) -> Self { VolumeError::Io(e) }
}

impl std::fmt::Display for VolumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeError::Io(e) => write!(f, "I/O error: {e}"),
            VolumeError::DecryptionFailed => {
                write!(f, "header decryption failed with all KDFs (AES-256 only)")
            }
        }
    }
}

// ─── Volume (public API) ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Volume {
    file: File,
    kdf_name: String,
    format_version: u16,
    volume_size: u64,
    encrypted_area_offset: u64,
    encrypted_area_size: u64,
    sector_size: u32,
    master_keys: [u8; 64],
    cursor: u64,
}

impl Volume {
    /// Open a VeraCrypt container, trying all supported KDFs.
    pub fn open(mut file: File, password: &[u8]) -> Result<Volume, VolumeError> {
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)?;

        let salt = &header[..HEADER_SALT_SIZE];

        for &kdf in ALL_KDFS {
            let key = derive_key(password, salt, kdf);
            let key1: &[u8; 32] = key[..32].try_into().unwrap();
            let key2: &[u8; 32] = key[32..].try_into().unwrap();

            let mut plain = [0u8; HEADER_ENC_SIZE];
            plain.copy_from_slice(&header[HEADER_ENC_OFFSET..HEADER_ENC_OFFSET + HEADER_ENC_SIZE]);
            aes256_xts_decrypt(key1, key2, 0, &mut plain);

            if &plain[..4] != VERACRYPT_MAGIC { continue; }

            let stored_crc   = u32::from_be_bytes(plain[188..192].try_into().unwrap());
            let computed_crc = crc32fast::hash(&plain[..188]);
            if stored_crc != computed_crc { continue; }

            let format_version        = u16::from_be_bytes(plain[4..6].try_into().unwrap());
            let volume_size           = u64::from_be_bytes(plain[36..44].try_into().unwrap());
            let encrypted_area_offset = u64::from_be_bytes(plain[44..52].try_into().unwrap());
            let encrypted_area_size   = u64::from_be_bytes(plain[52..60].try_into().unwrap());
            let sector_size           = u32::from_be_bytes(plain[64..68].try_into().unwrap());

            let mut master_keys = [0u8; 64];
            master_keys.copy_from_slice(&plain[192..256]);

            return Ok(Volume {
                file, kdf_name: kdf.to_string(),
                format_version, volume_size,
                encrypted_area_offset, encrypted_area_size,
                sector_size, master_keys, cursor: 0,
            });
        }

        Err(VolumeError::DecryptionFailed)
    }

    pub fn kdf_name(&self) -> &str              { &self.kdf_name }
    pub fn format_version(&self) -> u16         { self.format_version }
    pub fn volume_size(&self) -> u64            { self.volume_size }
    pub fn encrypted_area_offset(&self) -> u64  { self.encrypted_area_offset }
    pub fn encrypted_area_size(&self) -> u64    { self.encrypted_area_size }
    pub fn sector_size(&self) -> u32            { self.sector_size }
    pub fn master_key(&self) -> &[u8; 64]       { &self.master_keys }
    pub fn num_blocks(&self) -> u64             { self.encrypted_area_size / BLOCK_SIZE as u64 }

    /// Read and decrypt a single 512-byte block by index (0-based within the encrypted area).
    pub fn read_block(&mut self, index: u64, buf: &mut [u8; BLOCK_SIZE]) -> io::Result<()> {
        let offset = self.encrypted_area_offset + index * BLOCK_SIZE as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)?;

        let unit_no = self.encrypted_area_offset / BLOCK_SIZE as u64 + index;
        let mk_data:  &[u8; 32] = self.master_keys[..32].try_into().unwrap();
        let mk_tweak: &[u8; 32] = self.master_keys[32..64].try_into().unwrap();
        aes256_xts_decrypt(mk_data, mk_tweak, unit_no, buf);
        Ok(())
    }
}

// ─── Read + Seek (block-device interface) ────────────────────────────────────

impl io::Read for Volume {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cursor >= self.encrypted_area_size {
            return Ok(0);
        }

        let remaining = (self.encrypted_area_size - self.cursor) as usize;
        let to_read = buf.len().min(remaining);
        let mut done = 0;

        while done < to_read {
            let pos = self.cursor + done as u64;
            let block_idx = pos / BLOCK_SIZE as u64;
            let off = (pos % BLOCK_SIZE as u64) as usize;
            let n = (BLOCK_SIZE - off).min(to_read - done);

            let mut block = [0u8; BLOCK_SIZE];
            self.read_block(block_idx, &mut block)?;
            buf[done..done + n].copy_from_slice(&block[off..off + n]);
            done += n;
        }

        self.cursor += done as u64;
        Ok(done)
    }
}

impl io::Seek for Volume {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => self.encrypted_area_size as i64 + n,
            SeekFrom::Current(n) => self.cursor as i64 + n,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.cursor = new as u64;
        Ok(self.cursor)
    }
}

// ─── Crypto internals ────────────────────────────────────────────────────────

fn derive_key(password: &[u8], salt: &[u8], kdf: Kdf) -> [u8; DERIVED_KEY_SIZE] {
    let mut key = [0u8; DERIVED_KEY_SIZE];
    match kdf {
        Kdf::Sha512 =>
            pbkdf2::<Hmac<Sha512>>(password, salt, ITER_SHA512, &mut key)
                .expect("PBKDF2-SHA512 failed"),
        Kdf::Sha256 =>
            pbkdf2::<Hmac<Sha256>>(password, salt, ITER_SHA256, &mut key)
                .expect("PBKDF2-SHA256 failed"),
        Kdf::Ripemd160 =>
            pbkdf2::<Hmac<Ripemd160>>(password, salt, ITER_RIPEMD160, &mut key)
                .expect("PBKDF2-RIPEMD160 failed"),
        Kdf::Whirlpool =>
            pbkdf2::<Hmac<Whirlpool>>(password, salt, ITER_WHIRLPOOL, &mut key)
                .expect("PBKDF2-Whirlpool failed"),
        Kdf::Streebog512 =>
            pbkdf2::<Hmac<Streebog512>>(password, salt, ITER_STREEBOG, &mut key)
                .expect("PBKDF2-Streebog512 failed"),
    }
    key
}

fn gf128_mul_x(t: &mut [u8; 16]) {
    let carry = (t[15] >> 7) & 1;
    for i in (1..16).rev() {
        t[i] = (t[i] << 1) | (t[i - 1] >> 7);
    }
    t[0] <<= 1;
    if carry != 0 {
        t[0] ^= 0x87;
    }
}

fn aes256_xts_decrypt(key1: &[u8; 32], key2: &[u8; 32], sector: u64, data: &mut [u8]) {
    debug_assert_eq!(data.len() % 16, 0, "XTS requires whole AES blocks");

    let enc = Aes256::new(GenericArray::from_slice(key2));
    let dec = Aes256::new(GenericArray::from_slice(key1));

    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector.to_le_bytes());
    enc.encrypt_block(GenericArray::from_mut_slice(&mut tweak));

    for block in data.chunks_mut(16) {
        let b: &mut [u8; 16] = block.try_into().unwrap();
        for (byte, t) in b.iter_mut().zip(tweak.iter()) { *byte ^= t; }
        dec.decrypt_block(GenericArray::from_mut_slice(b));
        for (byte, t) in b.iter_mut().zip(tweak.iter()) { *byte ^= t; }
        gf128_mul_x(&mut tweak);
    }
}
