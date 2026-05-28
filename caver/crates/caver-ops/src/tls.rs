//! mTLS enforcement for caver sink/source URLs.
//!
//! Any caver sink that carries sensitive event data must use TLS when
//! `TlsPolicy::Required` is in effect.  Call `TlsPolicy::check(url)` before
//! opening a connection; the check is cheap (string prefix test, no I/O).
//!
//! # Example
//!
//! ```rust
//! use caver_ops::tls::{TlsPolicy, TlsError};
//!
//! let policy = TlsPolicy::Required;
//! assert!(policy.check("https://caver.internal:8088").is_ok());
//! assert!(policy.check("http://caver.internal:8088").is_err());
//!
//! let permissive = TlsPolicy::Permissive;
//! assert!(permissive.check("http://localhost:8088").is_ok());
//! ```

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsPolicy {
    /// Reject any URL that is not `https://` or `grpcs://`.
    Required,
    /// Allow plaintext connections (development/testing only).
    #[default]
    Permissive,
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("plaintext URL '{url}' rejected by TLS policy; use https:// or grpcs://")]
    PlaintextRejected { url: String },
}

impl TlsPolicy {
    /// Return `Ok(())` when `url` satisfies this policy, or `Err` otherwise.
    pub fn check(&self, url: &str) -> Result<(), TlsError> {
        match self {
            TlsPolicy::Permissive => Ok(()),
            TlsPolicy::Required => {
                if is_encrypted(url) {
                    Ok(())
                } else {
                    Err(TlsError::PlaintextRejected { url: url.to_string() })
                }
            }
        }
    }
}

fn is_encrypted(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("https://")
        || lower.starts_with("grpcs://")
        || lower.starts_with("tls://")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_accepts_https() {
        let p = TlsPolicy::Required;
        assert!(p.check("https://caver.internal:8088").is_ok());
        assert!(p.check("HTTPS://CAVER.INTERNAL:8088").is_ok());
    }

    #[test]
    fn required_accepts_grpcs() {
        assert!(TlsPolicy::Required.check("grpcs://fleet.internal:4317").is_ok());
    }

    #[test]
    fn required_rejects_http() {
        let err = TlsPolicy::Required.check("http://caver:8088").unwrap_err();
        assert!(err.to_string().contains("http://caver:8088"));
        assert!(err.to_string().contains("rejected"));
    }

    #[test]
    fn required_rejects_grpc_plaintext() {
        assert!(TlsPolicy::Required.check("grpc://caver:4317").is_err());
    }

    #[test]
    fn permissive_allows_http() {
        assert!(TlsPolicy::Permissive.check("http://localhost:8088").is_ok());
    }

    #[test]
    fn permissive_allows_https() {
        assert!(TlsPolicy::Permissive.check("https://caver:8088").is_ok());
    }

    #[test]
    fn default_is_permissive() {
        assert_eq!(TlsPolicy::default(), TlsPolicy::Permissive);
    }
}
