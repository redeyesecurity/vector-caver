//! HMAC-SHA256 helpers using RustCrypto crates.
//!
//! Public API:
//!   `sha256(data)` → `[u8; 32]`
//!   `hmac_sha256(key, data)` → `[u8; 32]`
//!   `hmac_sha256_hex(key, data)` → `String` (64 lowercase hex chars)
//!   `hmac_token(key, value)` → `String` (16-char hex pseudonym)

use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

/// Compute SHA-256 of `data`. Returns the 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Compute HMAC-SHA256 of `data` with `key`. Returns the 32-byte MAC.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Compute HMAC-SHA256 and return as a 64-character lowercase hex string.
pub fn hmac_sha256_hex(key: &str, data: &str) -> String {
    hex::encode(hmac_sha256(key.as_bytes(), data.as_bytes()))
}

/// Pseudonymize `value` with `key` using HMAC-SHA256.
/// Returns a 16-character hex string (64-bit prefix) for correlation without reversal.
pub fn hmac_token(key: &str, value: &str) -> String {
    let mac = hmac_sha256(key.as_bytes(), value.as_bytes());
    hex::encode(&mac[..8])
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 / NIST CAVP test vectors
    #[test]
    fn sha256_empty() {
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_nist_448bit() {
        let h = hex::encode(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert_eq!(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    // RFC 4231 HMAC-SHA256 test vectors
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let mac = hex::encode(hmac_sha256(&key, b"Hi There"));
        assert_eq!(mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let mac = hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?"));
        assert_eq!(mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn hmac_sha256_hex_length() {
        assert_eq!(hmac_sha256_hex("k", "v").len(), 64);
    }

    #[test]
    fn hmac_token_length_and_hex() {
        let t = hmac_token("secret", "alice@example.com");
        assert_eq!(t.len(), 16);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hmac_token_stable_and_sensitive() {
        assert_eq!(hmac_token("k", "v"), hmac_token("k", "v"));
        assert_ne!(hmac_token("k1", "v"), hmac_token("k2", "v"));
        assert_ne!(hmac_token("k", "v1"), hmac_token("k", "v2"));
    }
}
