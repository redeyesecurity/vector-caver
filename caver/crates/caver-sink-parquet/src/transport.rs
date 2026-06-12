//! Built-in S3/MinIO transport for the parquet sink (caver-collector#895).
//!
//! Sync (`ureq`) like the rest of the caver workspace — no async runtime.
//! Credentials are resolved from environment variables whose *names* come
//! from config (never literal values), matching the search-peer `token_env`
//! convention. Retries 5xx/3xx/transport errors with exponential backoff;
//! 4xx fail immediately (auth/config problems don't heal by retrying).

use crate::sigv4::{sha256_hex, sign_request, uri_encode, Credentials};
use crate::sink::PutFn;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;

/// Backoff between retries never exceeds this, whatever the knobs say.
const MAX_BACKOFF_MS: u64 = 30_000;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("credentials: env var {0} is unset or empty")]
    MissingCredentials(String),
    #[error("endpoint: {0}")]
    BadEndpoint(String),
    #[error("s3 put failed after {attempts} attempt(s): {last}")]
    PutFailed { attempts: u32, last: String },
    #[error("healthcheck: {0}")]
    HealthcheckFailed(String),
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
    /// Backoff before retry N is `retry_base_ms * 2^(N-1)`, capped at
    /// [`MAX_BACKOFF_MS`].
    pub retry_base_ms: u64,
    pub timeout_ms: u64,
    /// Total wall-clock budget for one PUT *including* every retry and
    /// backoff sleep, in milliseconds. With the other defaults the unbounded
    /// worst case was ~121s (4 × 30s timeouts + backoff) — longer than
    /// vector's `graceful_shutdown_limit_secs` default of 60s, so a shutdown
    /// flush of an already-acknowledged final batch could be force-killed
    /// mid-retry and lost without reaching the DLQ (caver-collector#898).
    /// Keep this below the shutdown grace.
    pub put_deadline_ms: u64,
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
            put_deadline_ms: 45_000,
        }
    }
}

fn require_env(name: &str) -> Result<String, TransportError> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(TransportError::MissingCredentials(name.to_string())),
    }
}

/// Parse + normalize the endpoint with the same `url` crate ureq uses, so
/// the host we sign is byte-for-byte the Host header ureq puts on the wire
/// (lowercased host, scheme-default ports dropped, IPv6 brackets kept).
/// Returns `(base, host)`: `scheme://host[:port]` and `host[:port]`.
fn parse_endpoint(endpoint: &str) -> Result<(String, String), TransportError> {
    let u = url::Url::parse(endpoint)
        .map_err(|e| TransportError::BadEndpoint(format!("{endpoint}: {e}")))?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err(TransportError::BadEndpoint(format!(
            "{endpoint}: scheme must be http or https"
        )));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(TransportError::BadEndpoint(format!(
            "{endpoint}: userinfo not allowed in endpoint"
        )));
    }
    let host = u
        .host_str()
        .ok_or_else(|| TransportError::BadEndpoint(format!("{endpoint}: missing host")))?;
    // `Url::port()` is None for the scheme default — matching what ureq sends.
    let hostport = match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    Ok((format!("{}://{hostport}", u.scheme()), hostport))
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
    /// Resolves credentials from the configured env vars and validates the
    /// endpoint now (fail fast at sink construction, not on the first flush).
    pub fn from_config(cfg: S3Config) -> Result<Self, TransportError> {
        let access_key = require_env(&cfg.access_key_env)?;
        let secret_key = require_env(&cfg.secret_key_env)?;
        let session_token = match &cfg.session_token_env {
            Some(name) => std::env::var(name).ok().filter(|v| !v.is_empty()),
            None => None,
        };
        let endpoint = match &cfg.endpoint {
            Some(e) => e.clone(),
            None => format!("https://s3.{}.amazonaws.com", cfg.region),
        };
        let (base, host) = parse_endpoint(&endpoint)?;
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
    ///
    /// `key` must not contain `.`/`..` path segments — the `url` crate would
    /// normalize them on the wire while the signature covers the raw path
    /// (keys from [`crate::partition::build_key`] can never contain them).
    pub fn put(&self, bucket: &str, key: &str, body: &[u8]) -> Result<(), TransportError> {
        let path = format!("/{}/{}", uri_encode(bucket, true), uri_encode(key, false));
        let url = format!("{}{}", self.base, path);
        let payload_hash = sha256_hex(body);

        let attempts = self.cfg.max_retries.saturating_add(1);
        let budget = Duration::from_millis(self.cfg.put_deadline_ms);
        let start = std::time::Instant::now();
        let mut last = String::new();
        for attempt in 0..attempts {
            if attempt > 0 {
                let factor = 1u64.checked_shl(attempt - 1).unwrap_or(u64::MAX);
                let backoff = Duration::from_millis(
                    self.cfg
                        .retry_base_ms
                        .saturating_mul(factor)
                        .min(MAX_BACKOFF_MS),
                );
                // A retry that would sleep into (or past) the deadline is
                // abandoned NOW, so the batch reaches the DLQ while the
                // process is still alive — not after vector's shutdown grace
                // force-kills the flush thread (caver-collector#898).
                if start.elapsed().saturating_add(backoff) >= budget {
                    return Err(TransportError::PutFailed {
                        attempts: attempt,
                        last: format!(
                            "{last}; put_deadline_ms={} exhausted",
                            self.cfg.put_deadline_ms
                        ),
                    });
                }
                std::thread::sleep(backoff);
            }
            // Never let a single attempt run past the remaining budget: the
            // per-request timeout shrinks as the deadline approaches.
            let remaining = budget.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(TransportError::PutFailed {
                    attempts: attempt,
                    last: format!(
                        "{last}; put_deadline_ms={} exhausted",
                        self.cfg.put_deadline_ms
                    ),
                });
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
                .timeout(remaining.min(Duration::from_millis(self.cfg.timeout_ms)))
                .set("x-amz-date", &amz_date)
                .set("x-amz-content-sha256", &payload_hash)
                .set("Authorization", &auth);
            if let Some(tok) = &self.creds.session_token {
                req = req.set("x-amz-security-token", tok);
            }

            match req.send_bytes(body) {
                // ureq only maps >=400 to Error::Status, and it does NOT
                // follow redirects for a PUT with a body — a 3xx here (AWS
                // 307 during new-bucket DNS propagation, 301 wrong-region)
                // means nothing was written. Never count it as success.
                Ok(resp) if (200..300).contains(&resp.status()) => return Ok(()),
                Ok(resp) => {
                    let code = resp.status();
                    let loc = resp.header("location").unwrap_or("-").to_string();
                    // 307 heals once DNS propagates → keep (bounded) retrying;
                    // 301 won't, but it still ends in the DLQ after the cap.
                    last = format!("HTTP {code} (redirect, not followed; location: {loc})");
                }
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

    /// Signed `HeadBucket` probe: verifies endpoint reachability, credential
    /// validity, and bucket existence/permission without writing an object.
    /// Single attempt, no retries — callers use it as a boot-time healthcheck
    /// and should get an answer fast (caver-collector#898). The previous
    /// healthcheck was a no-op, so a bad endpoint/bucket/secret only surfaced
    /// on the first flush, as a DLQ'd batch.
    pub fn head_bucket(&self, bucket: &str) -> Result<(), TransportError> {
        let path = format!("/{}", uri_encode(bucket, true));
        let url = format!("{}{}", self.base, path);
        let payload_hash = sha256_hex(b"");
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let mut extra: Vec<(&str, &str)> = Vec::new();
        if let Some(tok) = &self.creds.session_token {
            extra.push(("x-amz-security-token", tok));
        }
        let auth = sign_request(
            "HEAD",
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
            .head(&url)
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &payload_hash)
            .set("Authorization", &auth);
        if let Some(tok) = &self.creds.session_token {
            req = req.set("x-amz-security-token", tok);
        }
        match req.call() {
            Ok(resp) if (200..300).contains(&resp.status()) => Ok(()),
            // 301: wrong region for path-style; 307: bucket DNS still
            // propagating. Either way the lake is not writable from here.
            Ok(resp) => Err(TransportError::HealthcheckFailed(format!(
                "HEAD bucket {bucket:?}: HTTP {} (redirect, not followed)",
                resp.status()
            ))),
            Err(ureq::Error::Status(code, _)) => {
                let hint = match code {
                    403 => " (credentials lack access to the bucket)",
                    404 => " (bucket does not exist)",
                    _ => "",
                };
                Err(TransportError::HealthcheckFailed(format!(
                    "HEAD bucket {bucket:?}: HTTP {code}{hint}"
                )))
            }
            Err(e) => Err(TransportError::HealthcheckFailed(format!(
                "HEAD bucket {bucket:?}: transport: {e}"
            ))),
        }
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
    use std::sync::Mutex;

    /// `std::env::set_var` + libc `getenv` from parallel test threads is the
    /// classic setenv race — serialize every test that touches the env.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        let _g = ENV_LOCK.lock().unwrap();
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
        let _g = ENV_LOCK.lock().unwrap();
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
        let _g = ENV_LOCK.lock().unwrap();
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

    /// A 3xx comes back as Ok(Response) from ureq (no redirect-follow for
    /// PUT-with-body) — it must NOT be treated as a successful write.
    /// AWS really does this: 307 on new-bucket DNS propagation, 301 on
    /// wrong-region path-style.
    #[test]
    fn put_treats_3xx_as_failure_and_retries() {
        let _g = ENV_LOCK.lock().unwrap();
        let mut server = mockito::Server::new();
        let m = server
            .mock("PUT", mockito::Matcher::Any)
            .with_status(307)
            .with_header("location", "http://elsewhere.example/lake/k")
            .expect(3)
            .create();

        let t = S3Transport::from_config(test_cfg(&server.url(), "T895_AK_3XX", "T895_SK_3XX"))
            .unwrap();
        let err = t.put("lake", "k", b"x").unwrap_err();
        m.assert();
        assert!(err.to_string().contains("after 3 attempt(s)"), "{err}");
        assert!(err.to_string().contains("HTTP 307"), "{err}");
        assert!(err.to_string().contains("elsewhere.example"), "{err}");
    }

    /// put_deadline_ms bounds the whole retry loop: with a 1ms budget and a
    /// 10s backoff base, the 503 must NOT be retried (we'd sleep past the
    /// deadline) and the call must return promptly instead of after ~10s.
    #[test]
    fn put_deadline_abandons_retries_without_sleeping() {
        let _g = ENV_LOCK.lock().unwrap();
        let mut server = mockito::Server::new();
        let m = server
            .mock("PUT", mockito::Matcher::Any)
            .with_status(503)
            .expect(1)
            .create();

        let cfg = S3Config {
            retry_base_ms: 10_000,
            put_deadline_ms: 1,
            ..test_cfg(&server.url(), "T898_AK_DL", "T898_SK_DL")
        };
        let t = S3Transport::from_config(cfg).unwrap();
        let start = std::time::Instant::now();
        let err = t.put("lake", "k", b"x").unwrap_err();
        m.assert();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "must not sleep the 10s backoff"
        );
        assert!(err.to_string().contains("after 1 attempt(s)"), "{err}");
        assert!(
            err.to_string().contains("put_deadline_ms=1 exhausted"),
            "{err}"
        );
        assert!(
            err.to_string().contains("503"),
            "last error preserved: {err}"
        );
    }

    #[test]
    fn head_bucket_healthcheck() {
        let _g = ENV_LOCK.lock().unwrap();
        let mut server = mockito::Server::new();
        // Signed like a real request: same credential/signature shape as PUT.
        let ok = server
            .mock("HEAD", "/lake")
            .match_header(
                "authorization",
                mockito::Matcher::Regex("^AWS4-HMAC-SHA256 Credential=testak/".into()),
            )
            .with_status(200)
            .create();
        let t =
            S3Transport::from_config(test_cfg(&server.url(), "T898_AK_HC", "T898_SK_HC")).unwrap();
        t.head_bucket("lake").unwrap();
        ok.assert();

        let denied = server.mock("HEAD", "/secret").with_status(403).create();
        let err = t.head_bucket("secret").unwrap_err();
        denied.assert();
        assert!(matches!(err, TransportError::HealthcheckFailed(_)));
        assert!(err.to_string().contains("403"), "{err}");
        assert!(err.to_string().contains("lack access"), "{err}");

        let missing = server.mock("HEAD", "/nope").with_status(404).create();
        let err = t.head_bucket("nope").unwrap_err();
        missing.assert();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn missing_credentials_fail_fast() {
        let _g = ENV_LOCK.lock().unwrap();
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
    fn endpoint_parsing_matches_wire_host() {
        // Scheme-default ports dropped; explicit non-default ports kept.
        assert_eq!(
            parse_endpoint("http://192.168.1.30:9000").unwrap(),
            (
                "http://192.168.1.30:9000".into(),
                "192.168.1.30:9000".into()
            )
        );
        assert_eq!(
            parse_endpoint("https://s3.us-east-1.amazonaws.com").unwrap(),
            (
                "https://s3.us-east-1.amazonaws.com".into(),
                "s3.us-east-1.amazonaws.com".into()
            )
        );
        assert_eq!(
            parse_endpoint("https://example.com:443/").unwrap().1,
            "example.com"
        );
        assert_eq!(
            parse_endpoint("http://example.com:80").unwrap().1,
            "example.com"
        );
        // The url crate lowercases hosts on the wire — so must the signed host.
        assert_eq!(
            parse_endpoint("http://MinIO.Local:9000").unwrap().1,
            "minio.local:9000"
        );
        // IPv6 keeps brackets, exactly as ureq writes the Host header.
        assert_eq!(parse_endpoint("http://[::1]:9000").unwrap().1, "[::1]:9000");
        // Garbage fails fast at construction instead of retrying forever.
        assert!(parse_endpoint("192.168.1.30:9000").is_err());
        assert!(parse_endpoint("ftp://example.com").is_err());
        assert!(parse_endpoint("http://user@example.com:9000").is_err());
    }

    #[test]
    fn s3_put_fn_wires_transport() {
        let _g = ENV_LOCK.lock().unwrap();
        let mut server = mockito::Server::new();
        let m = server.mock("PUT", "/b/k.parquet").with_status(200).create();
        let put = s3_put_fn(test_cfg(&server.url(), "T895_AK_FN", "T895_SK_FN")).unwrap();
        put("b", "k.parquet", b"data".to_vec()).unwrap();
        m.assert();
    }
}
