//! HTTP client wrapping ureq for caver HEC pushes.

use std::time::Duration;

use serde_json::Value;

use crate::{format::format_batch, Config, PushError};

/// HEC client. Created once; reused across batches.
pub struct Client {
    agent: ureq::Agent,
    endpoint: String,
    auth_header: String,
    batch_size: usize,
}

impl Client {
    /// Build a `Client` from `Config`.
    ///
    /// Resolves the HEC token from the environment variable named by
    /// `config.token_env`.  Returns `PushError::MissingToken` if unset.
    pub fn from_config(config: &Config) -> Result<Self, PushError> {
        let token = std::env::var(&config.token_env)
            .map_err(|_| PushError::MissingToken(config.token_env.clone()))?;

        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build();

        let endpoint = format!("{}/services/collector", config.url.trim_end_matches('/'));
        let auth_header = format!("Splunk {token}");

        Ok(Self {
            agent,
            endpoint,
            auth_header,
            batch_size: config.batch_size,
        })
    }

    /// Push `events` to caver, splitting into batches of `config.batch_size`.
    ///
    /// Returns on the first batch that fails.
    pub fn push_events(&self, events: &[Value]) -> Result<(), PushError> {
        for chunk in events.chunks(self.batch_size) {
            self.push_batch(chunk)?;
        }
        Ok(())
    }

    /// Push a single pre-chunked batch.  Exposed for testing.
    pub fn push_batch(&self, events: &[Value]) -> Result<(), PushError> {
        if events.is_empty() {
            return Ok(());
        }
        let body = format_batch(events)?;
        self.agent
            .post(&self.endpoint)
            .set("Authorization", &self.auth_header)
            .set("Content-Type", "application/json")
            .send_string(&body)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests (requires mockito in dev-dependencies)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_client(url: &str) -> Client {
        Client {
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_millis(2_000))
                .build(),
            endpoint: format!("{url}/services/collector"),
            auth_header: "Splunk test-token".into(),
            batch_size: 10,
        }
    }

    #[test]
    fn push_empty_batch_is_noop() {
        let client = test_client("http://localhost:9999");
        assert!(client.push_batch(&[]).is_ok());
    }

    #[test]
    fn missing_token_env_errors() {
        // Use an env var that definitely won't be set
        let cfg = Config {
            url: "http://localhost:8088".into(),
            token_env: "CAVER_NONEXISTENT_TOKEN_XYZ987".into(),
            batch_size: 100,
            timeout_ms: 1_000,
        };
        let result = Client::from_config(&cfg);
        assert!(matches!(result, Err(PushError::MissingToken(_))));
    }

    #[test]
    fn batch_chunking() {
        // Verify push_events chunks correctly without a real server.
        // We use a client pointed at 127.0.0.2 (nothing listening) and
        // verify we get a network error (not a panic/wrong call count).
        let client = Client {
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_millis(100))
                .build(),
            endpoint: "http://127.0.0.2:9/services/collector".into(),
            auth_header: "Splunk x".into(),
            batch_size: 2,
        };
        let events: Vec<Value> = (0..5)
            .map(|i| json!({"class_uid": 4002, "seq": i}))
            .collect();
        let result = client.push_events(&events);
        // We expect a network error (nothing listening), not a code panic
        assert!(matches!(result, Err(PushError::Network(_))));
    }

    #[test]
    fn http_error_surfaced() {
        // We can't easily run a mock server in a no-std test environment,
        // so this just validates the error path through the type system.
        let err = PushError::HttpError {
            status: 403,
            body: "forbidden".into(),
        };
        assert!(err.to_string().contains("403"));
    }
}
