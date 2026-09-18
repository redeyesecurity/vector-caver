//! OAuth2 client-credentials token lifecycle.
//!
//! This module is transport-free on purpose. It does not open a socket: the
//! caller issues the token request (with whatever HTTP client Vector already
//! has) and hands the parsed JSON response back via
//! [`TokenCache::set_from_response`]. In return the cache answers the only two
//! questions the poll loop needs: "must I refresh before the next request?"
//! ([`TokenCache::needs_refresh`]) and "what bearer do I send?"
//! ([`TokenCache::bearer`]).

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

/// Errors parsing an OAuth2 token-endpoint response.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    /// The token response body was not a JSON object.
    #[error("token response is not a JSON object")]
    NotObject,
    /// The token response had no non-empty string `access_token`.
    #[error("token response has no `access_token` string")]
    MissingAccessToken,
    /// `expires_in` was present but not a positive number (nor a numeric string).
    #[error("token response `expires_in` is not a positive number")]
    BadExpiresIn,
}

/// A fetched bearer token together with the instant it stops being usable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The bearer value to send in the `Authorization` header.
    pub access_token: String,
    /// Absolute expiry, computed as `fetched_at + expires_in`.
    pub expires_at: DateTime<Utc>,
}

impl Token {
    /// Parse an OAuth2 token-endpoint JSON response.
    ///
    /// `fetched_at` is when the token request completed; the absolute expiry is
    /// `fetched_at + expires_in`. A missing or null `expires_in` falls back to
    /// `default_ttl_secs`. `expires_in` is accepted as a JSON number or a
    /// numeric string (some providers return it quoted).
    pub fn from_response(
        body: &Value,
        fetched_at: DateTime<Utc>,
        default_ttl_secs: i64,
    ) -> Result<Self, TokenError> {
        let obj = body.as_object().ok_or(TokenError::NotObject)?;

        let access_token = obj
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(TokenError::MissingAccessToken)?
            .to_string();

        let ttl_secs = match obj.get("expires_in") {
            None | Some(Value::Null) => default_ttl_secs,
            Some(v) => parse_expires_in(v).ok_or(TokenError::BadExpiresIn)?,
        };

        Ok(Self {
            access_token,
            expires_at: fetched_at + Duration::seconds(ttl_secs),
        })
    }
}

/// Extract a positive `expires_in` (seconds) from a JSON number or numeric
/// string. Returns `None` for anything non-positive or unparseable.
fn parse_expires_in(v: &Value) -> Option<i64> {
    let secs = match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))?,
        Value::String(s) => s.trim().parse::<i64>().ok()?,
        _ => return None,
    };
    (secs > 0).then_some(secs)
}

/// Holds the current token and decides when a refresh is due.
///
/// The cache never fetches; it is fed by the caller. `needs_refresh` fires a
/// configurable `skew` *before* the real expiry so a token is replaced before
/// an in-flight request can race it to zero.
#[derive(Clone, Debug)]
pub struct TokenCache {
    token: Option<Token>,
    skew: Duration,
    default_ttl_secs: i64,
}

impl TokenCache {
    /// Create an empty cache.
    ///
    /// `skew_secs` is how far ahead of true expiry a refresh is forced
    /// (clamped to `>= 0`). `default_ttl_secs` is the assumed lifetime when a
    /// token response omits `expires_in`.
    pub fn new(skew_secs: i64, default_ttl_secs: i64) -> Self {
        Self {
            token: None,
            skew: Duration::seconds(skew_secs.max(0)),
            default_ttl_secs,
        }
    }

    /// True when there is no token yet, or the held token is within `skew` of
    /// expiry as of `now`.
    pub fn needs_refresh(&self, now: DateTime<Utc>) -> bool {
        match &self.token {
            None => true,
            Some(t) => now + self.skew >= t.expires_at,
        }
    }

    /// The current bearer value, if a token is held. Returns it regardless of
    /// expiry so a caller can still make a best-effort request if a refresh
    /// failed; pair with [`needs_refresh`](Self::needs_refresh) to decide.
    pub fn bearer(&self) -> Option<&str> {
        self.token.as_ref().map(|t| t.access_token.as_str())
    }

    /// The held token, if any.
    pub fn token(&self) -> Option<&Token> {
        self.token.as_ref()
    }

    /// Parse and store a token from a token-endpoint response body.
    pub fn set_from_response(
        &mut self,
        body: &Value,
        fetched_at: DateTime<Utc>,
    ) -> Result<(), TokenError> {
        self.token = Some(Token::from_response(
            body,
            fetched_at,
            self.default_ttl_secs,
        )?);
        Ok(())
    }

    /// Drop the held token, forcing the next [`needs_refresh`](Self::needs_refresh)
    /// to return `true`. Call this after a `401` so a stale token is not reused.
    pub fn clear(&mut self) {
        self.token = None;
    }
}

/// Build the `application/x-www-form-urlencoded` field pairs for an OAuth2
/// client-credentials token request. The caller URL-encodes and sends them as
/// the POST body. `scope` is omitted when `None` or empty.
pub fn client_credentials_form(
    client_id: &str,
    client_secret: &str,
    scope: Option<&str>,
) -> Vec<(String, String)> {
    let mut form = vec![
        ("grant_type".to_string(), "client_credentials".to_string()),
        ("client_id".to_string(), client_id.to_string()),
        ("client_secret".to_string(), client_secret.to_string()),
    ];
    if let Some(scope) = scope.filter(|s| !s.is_empty()) {
        form.push(("scope".to_string(), scope.to_string()));
    }
    form
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn parses_number_expires_in() {
        let body = json!({"access_token": "abc", "expires_in": 3600});
        let tok = Token::from_response(&body, t0(), 300).unwrap();
        assert_eq!(tok.access_token, "abc");
        assert_eq!(tok.expires_at, t0() + Duration::seconds(3600));
    }

    #[test]
    fn parses_string_expires_in() {
        let body = json!({"access_token": "abc", "expires_in": "1200"});
        let tok = Token::from_response(&body, t0(), 300).unwrap();
        assert_eq!(tok.expires_at, t0() + Duration::seconds(1200));
    }

    #[test]
    fn missing_expires_in_uses_default() {
        let body = json!({"access_token": "abc"});
        let tok = Token::from_response(&body, t0(), 900).unwrap();
        assert_eq!(tok.expires_at, t0() + Duration::seconds(900));
    }

    #[test]
    fn rejects_missing_access_token() {
        let body = json!({"expires_in": 3600});
        let err = Token::from_response(&body, t0(), 300).unwrap_err();
        assert_eq!(err, TokenError::MissingAccessToken);
    }

    #[test]
    fn rejects_empty_access_token() {
        let body = json!({"access_token": "", "expires_in": 3600});
        let err = Token::from_response(&body, t0(), 300).unwrap_err();
        assert_eq!(err, TokenError::MissingAccessToken);
    }

    #[test]
    fn rejects_non_object() {
        let body = json!(["not", "an", "object"]);
        let err = Token::from_response(&body, t0(), 300).unwrap_err();
        assert_eq!(err, TokenError::NotObject);
    }

    #[test]
    fn rejects_non_positive_expires_in() {
        let body = json!({"access_token": "abc", "expires_in": 0});
        let err = Token::from_response(&body, t0(), 300).unwrap_err();
        assert_eq!(err, TokenError::BadExpiresIn);
    }

    #[test]
    fn empty_cache_needs_refresh() {
        let cache = TokenCache::new(60, 300);
        assert!(cache.needs_refresh(t0()));
        assert_eq!(cache.bearer(), None);
    }

    #[test]
    fn fresh_token_does_not_need_refresh() {
        let mut cache = TokenCache::new(60, 300);
        let body = json!({"access_token": "abc", "expires_in": 3600});
        cache.set_from_response(&body, t0()).unwrap();
        // 100s later, far from the 3600s expiry minus 60s skew.
        assert!(!cache.needs_refresh(t0() + Duration::seconds(100)));
        assert_eq!(cache.bearer(), Some("abc"));
    }

    #[test]
    fn refresh_fires_inside_skew_window() {
        let mut cache = TokenCache::new(60, 300);
        let body = json!({"access_token": "abc", "expires_in": 3600});
        cache.set_from_response(&body, t0()).unwrap();
        // At expiry-30s (< 60s skew) a refresh is due even though not expired.
        assert!(cache.needs_refresh(t0() + Duration::seconds(3600 - 30)));
    }

    #[test]
    fn clear_forces_refresh() {
        let mut cache = TokenCache::new(60, 300);
        let body = json!({"access_token": "abc", "expires_in": 3600});
        cache.set_from_response(&body, t0()).unwrap();
        cache.clear();
        assert!(cache.needs_refresh(t0()));
        assert_eq!(cache.bearer(), None);
    }

    #[test]
    fn negative_skew_is_clamped() {
        let cache = TokenCache::new(-100, 300);
        // Clamped to 0, so an empty cache still needs a refresh (the None arm).
        assert!(cache.needs_refresh(t0()));
    }

    #[test]
    fn form_includes_scope_when_present() {
        let form = client_credentials_form("id", "secret", Some("a.b c.d"));
        assert!(form.contains(&("grant_type".to_string(), "client_credentials".to_string())));
        assert!(form.contains(&("client_id".to_string(), "id".to_string())));
        assert!(form.contains(&("client_secret".to_string(), "secret".to_string())));
        assert!(form.contains(&("scope".to_string(), "a.b c.d".to_string())));
    }

    #[test]
    fn form_omits_empty_scope() {
        let form = client_credentials_form("id", "secret", Some(""));
        assert!(!form.iter().any(|(k, _)| k == "scope"));
        let form = client_credentials_form("id", "secret", None);
        assert!(!form.iter().any(|(k, _)| k == "scope"));
    }
}
