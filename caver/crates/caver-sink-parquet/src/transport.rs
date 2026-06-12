//! Built-in S3/MinIO transport for the parquet sink (caver-collector#895).
//!
//! Sync (`ureq`) like the rest of the caver workspace — no async runtime.
//! Credentials are resolved from environment variables whose *names* come
//! from config (never literal values), matching the search-peer `token_env`
//! convention. Retries 5xx/transport errors with exponential backoff; 4xx
//! fail immediately (auth/config problems don't heal by retrying).

use crate::sigv4::{sha256_hex, sign_request, uri_encode, Credentials};
use crate::sink::PutFn;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("credentials: env var {0} is unset or empty")]
    MissingCredentials(String),
    #[error("s3 put failed after {attempts} attempt(s): {last}")]
    PutFailed { attempts: u32, last: String },
}

pub struct S3Config {
    /// Custom endpoint for MinIO / S3-compatible stores, e.g.
    /// `http://192.168.1.30:9000`. `None` = AWS (`https://s3.<region>.amazonaws.com`).
    /// Requests are always path-style (`/<bucket>/<key>`).
    pub endpoint: Option<String>,
    pub region: String,
    /// Env var NAME holding the access key id.
    pub access_key_env: String,
    /// Env var NAME holding the secret access key.
    pub secret_key_env: String,
    /// Optional env var NAME holding a session token (STS).
    pub session_token_env: Option<String>,
    /// Retries after the first attempt (total attempts = max_retries + 1).
    pub max_retries: u32,
    /// Backoff before retry N is `retry_base_ms * 2^(N-1)`.
    pub retry_base_ms: u64,
    pub timeout_ms: u64,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: None,
            region: "us-east-1".into(),
            access_key_env: "AWS_ACCESS_KEY_ID".into(),
            secret_key_env: "AWS_SECRET_ACCESS_KEY".into(),
            session_token_env: None,
            max_retries: 3,
            retry_base_ms: 200,
            timeout_ms: 30_000,
        }
    }
}

fn require_env(name: &str) -> Result<String, TransportError> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(TransportError::MissingCredentials(name.to_string())),
    }
}

/// `scheme://host[:port][...]` → `host[:port]` as ureq will send it in the
/// Host header (the `url` crate drops scheme-default ports, so must we —
/// the signed host header has to match the wire byte-for-byte).
fn host_from_base(base: &str) -> String {
    let no_scheme = base.split("://").nth(1).unwrap_or(base);
    let host = no_scheme.split('/').next().unwrap_or(no_scheme);
    if base.starts_with("https://") {
        host.strip_suffix(":443").unwrap_or(host).into()
    } else {
        host.strip_suffix(":80").unwrap_or(host).into()
    }
}

pub struct S3Transport {
    cfg: S3Config,
    creds: Credentials,
    agent: ureq::Agent,
    /// `scheme://host[:port]`, no trailing slash.
    base: String,
    /// Host header value as it appears on the wire.
    host: String,
}

impl S3Transport {
    /// Resolves credentials from the configured env vars now (fail fast at
    /// sink construction, not on the first flush).
    pub fn from_config(cfg: S3Config) -> Result<Self, TransportError> {
        let access_key = require_env(&cfg.access_key_env)?;
        let secret_key = require_env(&cfg.secret_key_env)?;
        let session_token = match &cfg.session_token_env {
            Some(name) => std::env::var(name).ok().filter(|v| !v.is_empty()),
            None => None,
        };
        let base = match &cfg.endpoint {
            Some(e) => e.trim_end_matches('/').to_string(),
            None => format!("https://s3.{}.amazonaws.com", cfg.region),
        };
        let host = host_from_base(&base);
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build();
        Ok(Self {
            creds: Credentials {
                access_key,
                secret_key,
                session_token,
            },
            cfg,
            agent,
            base,
            host,
        })
    }

    /// PUT `body` to `s3://bucket/key` (path-style). Re-signs each attempt so
    /// long backoffs can't push `x-amz-date` outside the 15-minute skew window.
    pub fn put(&self, bucket: &str, key: &str, body: &[u8]) -> Result<(), TransportError> {
        let path = format!("/{}/{}", uri_encode(bucket, true), uri_encode(key, false));
        let url = format!("{}{}", self.base, path);
        let payload_hash = sha256_hex(body);

        let attempts = self.cfg.max_retries + 1;
        let mut last = String::new();
        for attempt in 0..attempts {
            if attempt > 0 {
                let backoff = self.cfg.retry_base_ms.saturating_mul(1 << (attempt - 1));
                std::thread::sleep(Duration::from_millis(backoff));
            }
            let now = Utc::now();
            let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
            let mut extra: Vec<(&str, &str)> = Vec::new();
            if let Some(tok) = &self.creds.session_token {
                extra.push(("x-amz-security-token", tok));
            }
            let auth = sign_request(
                "PUT",
                &self.host,
                &path,
                &extra,
                &payload_hash,
                &now,
                &self.cfg.region,
                &self.creds,
            );

            let mut req = self
                .agent
                .put(&url)
                .set("x-amz-date", &amz_date)
                .set("x-amz-content-sha256", &payload_hash)
                .set("Authorization", &auth);
            if let Some(tok) = &self.creds.session_token {
                req = req.set("x-amz-security-token", tok);
            }

            match req.send_bytes(body) {
                Ok(_) => return Ok(()),
                Err(ureq::Error::Status(code, resp)) => {
                    let body_snip: String = resp
                        .into_string()
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect();
                    last = format!("HTTP {code}: {body_snip}");
                    if code < 500 {
                        // 4xx = auth / bucket / request shape — retrying can't fix it.
                        return Err(TransportError::PutFailed {
                            attempts: attempt + 1,
                            last,
                        });
                    }
                }
                Err(e) => last = format!("transport: {e}"),
            }
        }
        Err(TransportError::PutFailed { attempts, last })
    }
}

/// Build a [`PutFn`] backed by [`S3Transport`] — the drop-in transport for
/// [`crate::ParquetSink::new`].
pub fn s3_put_fn(cfg: S3Config) -> Result<PutFn, TransportError> {
    let transport = S3Transport::from_config(cfg)?;
    Ok(Arc::new(move |bucket: &str, key: &str, body: Vec<u8>| {
        transport.put(bucket, key, &body).map_err(|e| e.to_string())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(server_url: &str, ak_env: &str, sk_env: &str) -> S3Config {
        std::env::set_var(ak_env, "testak");
        std::env::set_var(sk_env, "testsk");
        S3Config {
            endpoint: Some(server_url.to_string()),
            access_key_env: ak_env.into(),
            secret_key_env: sk_env.into(),
            max_retries: 2,
            retry_base_ms: 1,
            ..Default::default()
        }
    }

    #[test]
    fn put_success_signed_path_style() {
        let mut server = mockito::Server::new();
        let m = server
            .mock(
                "PUT",
                "/lake/4002/dt%3D2026-06-12/hour%3D14/sensor%3Dbox/f.parquet",
            )
            .match_header(
                "x-amz-content-sha256",
                mockito::Matcher::Regex("^[0-9a-f]{64}$".into()),
            )
            .match_header(
                "authorization",
                mockito::Matcher::Regex(
                    "^AWS4-HMAC-SHA256 Credential=testak/[0-9]{8}/us-east-1/s3/aws4_request, \
                     SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                     Signature=[0-9a-f]{64}$"
                        .into(),
                ),
            )
            .with_status(200)
            .create();

        let t =
            S3Transport::from_config(test_cfg(&server.url(), "T895_AK_OK", "T895_SK_OK")).unwrap();
        t.put(
            "lake",
            "4002/dt=2026-06-12/hour=14/sensor=box/f.parquet",
            b"bytes",
        )
        .unwrap();
        m.assert();
    }

    #[test]
    fn put_retries_on_5xx() {
        let mut server = mockito::Server::new();
        // max_retries=2 → exactly 3 attempts.
        let m = server
            .mock("PUT", mockito::Matcher::Any)
            .with_status(503)
            .expect(3)
            .create();

        let t = S3Transport::from_config(test_cfg(&server.url(), "T895_AK_5XX", "T895_SK_5XX"))
            .unwrap();
        let err = t.put("lake", "k", b"x").unwrap_err();
        m.assert();
        assert!(err.to_string().contains("after 3 attempt(s)"), "{err}");
        assert!(err.to_string().contains("503"), "{err}");
    }

    #[test]
    fn put_does_not_retry_4xx() {
        let mut server = mockito::Server::new();
        let m = server
            .mock("PUT", mockito::Matcher::Any)
            .with_status(403)
            .expect(1)
            .create();

        let t = S3Transport::from_config(test_cfg(&server.url(), "T895_AK_4XX", "T895_SK_4XX"))
            .unwrap();
        let err = t.put("lake", "k", b"x").unwrap_err();
        m.assert();
        assert!(err.to_string().contains("after 1 attempt(s)"), "{err}");
    }

    #[test]
    fn missing_credentials_fail_fast() {
        let cfg = S3Config {
            access_key_env: "T895_DOES_NOT_EXIST".into(),
            ..Default::default()
        };
        // No `unwrap_err`: S3Transport intentionally has no Debug impl
        // (it holds resolved credentials).
        let err = S3Transport::from_config(cfg)
            .err()
            .expect("missing env must fail construction");
        assert!(matches!(err, TransportError::MissingCredentials(_)));
        assert!(err.to_string().contains("T895_DOES_NOT_EXIST"));
    }

    #[test]
    fn host_from_base_strips_default_ports_only() {
        assert_eq!(
            host_from_base("http://192.168.1.30:9000"),
            "192.168.1.30:9000"
        );
        assert_eq!(
            host_from_base("https://s3.us-east-1.amazonaws.com"),
            "s3.us-east-1.amazonaws.com"
        );
        assert_eq!(host_from_base("https://example.com:443"), "example.com");
        assert_eq!(host_from_base("http://example.com:80"), "example.com");
    }

    #[test]
    fn s3_put_fn_wires_transport() {
        let mut server = mockito::Server::new();
        let m = server.mock("PUT", "/b/k.parquet").with_status(200).create();
        let put = s3_put_fn(test_cfg(&server.url(), "T895_AK_FN", "T895_SK_FN")).unwrap();
        put("b", "k.parquet", b"data".to_vec()).unwrap();
        m.assert();
    }
}
