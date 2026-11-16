use std::fs;
use std::path::Path;
use base64::prelude::*;
use byteorder::{ByteOrder, LittleEndian};
use getrandom::SysRng;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::{PrivateKey, PublicKey};
use sha1::Sha1;

use crate::error::{Error, Result};

pub(crate) const ANDROID_PUBKEY_MODULUS_SIZE: usize = 256; // 2048 bits
pub(crate) const ANDROID_PUBKEY_MODULUS_WORDS: usize = 64;  // 64 * 32 bits
pub(crate) const ANDROID_PUBKEY_ENCODED_SIZE: usize = 524; // 3 * 4 + 2 * 256

/// Computes modular inverse mod 2^32 for an odd 32-bit integer.
fn mod_inverse_u32(a: u32) -> u32 {
    let mut x = 1u32;
    for _ in 0..5 {
        x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    }
    x
}

/// RSA key pair for ADB authentication.
#[derive(Clone)]
pub struct KeyPair {
    private_key: PrivateKey,
}

impl KeyPair {
    /// Generates a new 2048-bit RSA key pair.
    pub fn generate() -> Result<Self> {
        let private_key = PrivateKey::new(&mut SysRng, 2048)
            .map_err(|e| Error::key(format!("Failed to generate RSA key: {}", e)))?;
        Ok(Self { private_key })
    }

    /// Creates an `KeyPair` from an existing `PrivateKey`.
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        Self { private_key }
    }

    /// Access the underlying `PrivateKey`.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Access the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.private_key)
    }

    /// Loads a private key from a PEM-encoded string (PKCS#8 or PKCS#1).
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        // Try PKCS#8 first, then fallback to PKCS#1
        if let Ok(key) = PrivateKey::from_pkcs8_pem(pem_str) {
            return Ok(Self { private_key: key });
        }
        if let Ok(key) = PrivateKey::from_pkcs1_pem(pem_str) {
            return Ok(Self { private_key: key });
        }
        Err(Error::key("Failed to parse private key PEM (neither PKCS#8 nor PKCS#1)"))
    }

    /// Loads a private key from a file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| Error::key(format!("cannot read {}: {}", path.as_ref().display(), e)))?;
        Self::from_pem(&content)
    }

    /// Exports the private key as a PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        self.private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| Error::key(format!("Failed to export PKCS#8 PEM: {}", e)))
            .map(|zeroizing| zeroizing.as_str().to_string())
    }

    /// Saves the private key to a file with restricted permissions (0600 on Unix).
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let pem = self.to_pkcs8_pem()?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Write-then-rename so a crash never leaves a truncated key.
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, path)?;

        Ok(())
    }

    /// Encodes the RSA public key into Android's 524-byte `RSAPublicKey` binary structure:
    ///
    /// ```c
    /// struct RSAPublicKey {
    ///     uint32_t modulus_size_words; // 64
    ///     uint32_t n0inv;              // -1 / n[0] mod 2^32
    ///     uint8_t modulus[256];        // little-endian
    ///     uint8_t rr[256];             // R^2 mod n, little-endian
    ///     uint32_t exponent;           // public exponent (e.g. 65537)
    /// };
    /// ```
    pub fn android_pubkey_bytes(&self) -> Result<Vec<u8>> {
        let n_bytes_le = self.private_key.n().as_ref().to_le_bytes();
        if n_bytes_le.len() > ANDROID_PUBKEY_MODULUS_SIZE {
            return Err(Error::key("Modulus exceeds 2048 bits"));
        }
        let n_biguint = BigUint::from_bytes_le(&n_bytes_le);

        let e_bytes_le = self.private_key.e().to_le_bytes();
        let e_biguint = BigUint::from_bytes_le(&e_bytes_le);

        // n0 = n % 2^32
        let mod_32: BigUint = BigUint::one() << 32;
        let n0_rem = &n_biguint % mod_32;
        let n0 = n0_rem.to_u32().unwrap_or(0);

        if n0.is_multiple_of(2) {
            return Err(Error::key("Modulus is even, invalid RSA key"));
        }

        // n0inv = -1 / n[0] mod 2^32 = 0 - inv(n0)
        let n0inv = (0u32).wrapping_sub(mod_inverse_u32(n0));

        // R = 2^2048, R^2 = 2^4096
        // rr = R^2 mod n
        let r = BigUint::one() << (ANDROID_PUBKEY_MODULUS_WORDS * 32);
        let rr = (&r * &r) % &n_biguint;
        let rr_bytes_le = rr.to_bytes_le();
        if rr_bytes_le.len() > ANDROID_PUBKEY_MODULUS_SIZE {
            return Err(Error::key("R^2 mod n exceeds 2048 bits"));
        }

        let exponent = e_biguint.to_u32().unwrap_or(65537);

        let mut out = vec![0u8; ANDROID_PUBKEY_ENCODED_SIZE];

        // 1. modulus_size_words: uint32
        LittleEndian::write_u32(&mut out[0..4], ANDROID_PUBKEY_MODULUS_WORDS as u32);

        // 2. n0inv: uint32
        LittleEndian::write_u32(&mut out[4..8], n0inv);

        // 3. modulus: 256 bytes little-endian
        out[8..8 + n_bytes_le.len()].copy_from_slice(&n_bytes_le);

        // 4. rr: 256 bytes little-endian
        out[264..264 + rr_bytes_le.len()].copy_from_slice(&rr_bytes_le);

        // 5. exponent: uint32
        LittleEndian::write_u32(&mut out[520..524], exponent);

        Ok(out)
    }

    /// Returns the public key string in Android's format:
    /// `<base64(RSAPublicKey)> <banner>\0`
    pub fn android_pubkey_string(&self, banner: &str) -> Result<String> {
        let binary_pubkey = self.android_pubkey_bytes()?;
        let b64 = BASE64_STANDARD.encode(&binary_pubkey);
        Ok(format!("{} {}\0", b64, banner))
    }

    /// Signs an authentication challenge token from adbd (typically 20 bytes).
    ///
    /// Android's adbd expects an RSA PKCS#1 v1.5 signature over the SHA-1 DigestInfo
    /// wrapped token.
    pub fn sign_token(&self, token: &[u8]) -> Result<Vec<u8>> {
        self.private_key
            .pkcs1v15_sign_prehash::<Sha1>(token)
            .map_err(|e| Error::key(format!("Failed to sign token: {}", e)))
    }

    /// Verifies a signature against the public key.
    pub fn verify_signature(&self, token: &[u8], signature: &[u8]) -> bool {
        let pub_key = self.public_key();
        pub_key.pkcs1v15_verify_prehash::<Sha1>(token, signature).is_ok()
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyPair(..)")
    }
}

impl KeyPair {
    /// Load the key at `path` (PKCS#8 or PKCS#1 PEM), or create one there
    /// (plus `<path>.pub` in adb's format) if the file does not exist.
    ///
    /// If `path` is a directory, `<dir>/adbkey` is used. An existing file
    /// that cannot be parsed is an error, never silently replaced: a new key
    /// would make every device ask for authorization again.
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let file = if path.is_dir() { path.join("adbkey") } else { path.to_path_buf() };
        match fs::read_to_string(&file) {
            Ok(pem) => Self::from_pem(&pem)
                .map_err(|e| Error::key(format!("{} is not a usable key: {}", file.display(), e.message()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                key.save_to_file(&file)
                    .map_err(|e| Error::key(format!("cannot save key to {}: {}", file.display(), e.message())))?;
                let public = key.android_pubkey_string("airadb@client")?;
                fs::write(file.with_extension("pub"), public.trim_end_matches('\0'))
                    .map_err(|e| Error::key(format!("cannot save public key next to {}: {e}", file.display())))?;
                Ok(key)
            }
            Err(e) => Err(Error::key(format!("cannot read {}: {e}", file.display()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PrivateKeyParts;

    #[test]
    fn test_mod_inverse_u32() {
        for val in [3u32, 5, 7, 17, 65537, 2147483647, 4294967295] {
            let inv = mod_inverse_u32(val);
            assert_eq!(val.wrapping_mul(inv), 1, "Failed for {}", val);
        }
    }

    #[test]
    fn test_keygen_and_sign_verify() {
        let key = KeyPair::generate().unwrap();
        let token = b"12345678901234567890"; // 20 bytes token
        let sig = key.sign_token(token).unwrap();
        assert_eq!(sig.len(), 256); // 2048-bit RSA signature length is 256 bytes

        assert!(key.verify_signature(token, &sig));

        // Corrupted token
        let bad_token = b"12345678901234567891";
        assert!(!key.verify_signature(bad_token, &sig));
    }

    #[test]
    fn test_android_pubkey_format() {
        let key = KeyPair::generate().unwrap();
        let pub_bytes = key.android_pubkey_bytes().unwrap();
        assert_eq!(pub_bytes.len(), ANDROID_PUBKEY_ENCODED_SIZE);

        let words = LittleEndian::read_u32(&pub_bytes[0..4]);
        assert_eq!(words, 64);

        let exponent = LittleEndian::read_u32(&pub_bytes[520..524]);
        assert_eq!(exponent, 65537);

        let pub_str = key.android_pubkey_string("test@host").unwrap();
        assert!(pub_str.ends_with(" test@host\0"));
    }

    #[test]
    fn load_or_create_persists_and_refuses_garbage() {
        let dir = std::env::temp_dir().join(format!("airadb-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let first = KeyPair::load_or_create(&dir).unwrap();
        assert!(dir.join("adbkey").exists() && dir.join("adbkey.pub").exists());
        let again = KeyPair::load_or_create(dir.join("adbkey")).unwrap();
        assert_eq!(first.private_key().n(), again.private_key().n());

        fs::write(dir.join("adbkey"), "garbage").unwrap();
        assert_eq!(KeyPair::load_or_create(&dir).unwrap_err().kind(), crate::ErrorKind::Key);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pem_roundtrip() {
        let key = KeyPair::generate().unwrap();
        let pem = key.to_pkcs8_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));

        let loaded = KeyPair::from_pem(&pem).unwrap();
        assert_eq!(key.private_key().n(), loaded.private_key().n());
        assert_eq!(key.private_key().d(), loaded.private_key().d());
    }
}
