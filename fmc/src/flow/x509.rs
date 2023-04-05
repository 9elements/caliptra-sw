/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains X509 Certificate & CSR related utility functions

--*/
use crate::flow::crypto::Crypto;
use crate::fmc_env::FmcEnv;
use caliptra_drivers::*;

/// Wrapper to hold certificate buffer and length
pub struct Certificate<'a, const LEN: usize> {
    buf: &'a [u8; LEN],
    len: usize,
}

impl<'a, const LEN: usize> Certificate<'a, LEN> {
    /// Create an instance of `Certificate`
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer
    /// * `len` - Buffer length  
    pub fn new(buf: &'a [u8; LEN], len: usize) -> Self {
        Self { buf, len }
    }

    /// Get the buffer
    pub fn get(&self) -> Option<&[u8]> {
        self.buf.get(..self.len)
    }
}

/// X509 API
pub enum X509 {}

impl X509 {
    /// Get X509 Subject Serial Number
    ///
    /// # Arguments
    ///
    /// * `env`     - ROM Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 64]` - X509 Subject Identifier serial number
    pub fn subj_sn(env: &FmcEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 64]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(env, &data)?;
        Ok(Self::hex(&digest.into()))
    }

    /// Get Cert Subject Key Identifier
    ///
    /// # Arguments
    ///
    /// * `env`     - ROM Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Subject Key Identifier
    pub fn subj_key_id(env: &FmcEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();
        let digest: [u8; 32] = Crypto::sha256_digest(env, &data)?.into();

        Ok(digest[..20].try_into().unwrap())
    }

    /// Get Cert Serial Number
    ///
    /// # Arguments
    ///
    /// * `env`     - ROM Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Serial Number
    pub fn cert_sn(env: &FmcEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();
        let mut digest: [u8; 32] = Crypto::sha256_digest(env, &data)?.into();
        digest[0] &= !0x80;
        Ok(digest[..20].try_into().unwrap())
    }

    /// Return the hex representation of the input `buf`
    ///
    /// # Arguments
    ///
    /// `buf` - Buffer
    ///
    /// # Returns
    ///
    /// `[u8; 64]` - Hex representation of the buffer
    fn hex(buf: &[u8; 32]) -> [u8; 64] {
        fn ch(byte: u8) -> u8 {
            match byte & 0x0F {
                b @ 0..=9 => 48 + b,
                b @ 10..=15 => 55 + b,
                _ => unreachable!(),
            }
        }

        let mut hex = [0u8; 64];

        for (index, byte) in buf.iter().enumerate() {
            hex[index << 1] = ch((byte & 0xF0) >> 4);
            hex[(index << 1) + 1] = ch(byte & 0x0F);
        }

        hex
    }
}
