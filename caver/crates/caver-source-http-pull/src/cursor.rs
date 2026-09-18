//! Checkpoint/cursor carried across polls.
//!
//! Two shapes cover almost every paginated pull API:
//!
//!   * [`CursorMode::NextLink`] - each response body carries an absolute URL to
//!     the next page (Microsoft Graph `@odata.nextLink`, a generic
//!     `links.next`, ...). We follow it until it is absent, then the next
//!     scrape interval starts over from the base endpoint. This walks *pages*.
//!   * [`CursorMode::Since`] - a time-window high-water mark. We send the last
//!     high-water value as a query parameter and advance it from a timestamp
//!     field on each record. This walks *time*, one window per interval.
//!
//! [`Cursor`] owns the mode and the running [`CursorState`], so the poll driver
//! only has to ask [`Cursor::next_request`] what to send and call
//! [`Cursor::advance`] with each response.

use serde_json::Value;

/// How a source paginates and checkpoints across polls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorMode {
    /// Follow an absolute next-page URL located by a JSON pointer in the
    /// response body (e.g. `/@odata.nextLink`).
    NextLink {
        /// RFC 6901 JSON pointer to the next-page URL string.
        pointer: String,
    },
    /// Send a high-water timestamp under `param` and advance it from the field
    /// at `record_time_pointer` (a pointer relative to each record).
    Since {
        /// Query-parameter name the high-water value is sent under.
        param: String,
        /// RFC 6901 JSON pointer, relative to a single record, to the timestamp
        /// field used to advance the window.
        record_time_pointer: String,
    },
}

/// The mutable part of a cursor: what to send on the next request. Kept
/// separate from [`CursorMode`] so it can be persisted and restored (a
/// checkpoint file, a KV store) without carrying the static configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CursorState {
    /// `NextLink` mode: the absolute URL to fetch next, mid-page-walk. `None`
    /// means "start from the base endpoint".
    pub next_url: Option<String>,
    /// `Since` mode: the high-water value to send on the next poll. `None` on
    /// the very first poll (unless seeded).
    pub since: Option<String>,
}

/// What the next HTTP request should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextRequest {
    /// Fetch this absolute URL exactly as given (it already carries any query
    /// string). Used when following a `nextLink`.
    Url(String),
    /// Fetch the configured base endpoint, adding these query parameters.
    Base(Vec<(String, String)>),
}

/// A cursor: pagination mode plus its running state.
#[derive(Clone, Debug)]
pub struct Cursor {
    mode: CursorMode,
    state: CursorState,
}

impl Cursor {
    /// A fresh cursor with empty state.
    pub fn new(mode: CursorMode) -> Self {
        Self {
            mode,
            state: CursorState::default(),
        }
    }

    /// A cursor restored from a persisted state.
    pub fn with_state(mode: CursorMode, state: CursorState) -> Self {
        Self { mode, state }
    }

    /// The current state (for persisting a checkpoint).
    pub fn state(&self) -> &CursorState {
        &self.state
    }

    /// The pagination mode.
    pub fn mode(&self) -> &CursorMode {
        &self.mode
    }

    /// Describe the next request: an absolute follow-URL when mid-walk in
    /// `NextLink` mode, otherwise the base endpoint plus any cursor query
    /// parameters.
    pub fn next_request(&self) -> NextRequest {
        match &self.mode {
            CursorMode::NextLink { .. } => match &self.state.next_url {
                Some(url) => NextRequest::Url(url.clone()),
                None => NextRequest::Base(Vec::new()),
            },
            CursorMode::Since { param, .. } => {
                let mut params = Vec::new();
                if let Some(since) = &self.state.since {
                    params.push((param.clone(), since.clone()));
                }
                NextRequest::Base(params)
            }
        }
    }

    /// Update the cursor from a response body and its extracted records.
    ///
    /// Returns `true` when there is another page to fetch immediately within
    /// this same scrape (only `NextLink` mode ever does). `Since` mode always
    /// returns `false`: it advances the high-water mark and waits for the next
    /// scrape interval.
    pub fn advance(&mut self, body: &Value, records: &[Value]) -> bool {
        match &self.mode {
            CursorMode::NextLink { pointer } => {
                let next = body
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let has_more = next.is_some();
                self.state.next_url = next;
                has_more
            }
            CursorMode::Since {
                record_time_pointer,
                ..
            } => {
                let mut hi = self.state.since.take();
                for rec in records {
                    if let Some(ts) = rec.pointer(record_time_pointer).and_then(value_as_time) {
                        hi = Some(match hi {
                            Some(cur) if time_ge(&cur, &ts) => cur,
                            _ => ts,
                        });
                    }
                }
                self.state.since = hi;
                false
            }
        }
    }
}

/// Render a record's timestamp value as a comparable string. Accepts a JSON
/// string (an ISO-8601/RFC-3339 instant) or a number (an epoch). Other shapes
/// are ignored so a malformed record cannot corrupt the high-water mark.
fn value_as_time(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Order two high-water strings. If both parse as numbers, compare numerically
/// (so epoch `9` < `10`); otherwise lexically (RFC-3339 sorts correctly that
/// way). Returns `true` when `a >= b`.
fn time_ge(a: &str, b: &str) -> bool {
    match (a.parse::<f64>(), b.parse::<f64>()) {
        (Ok(x), Ok(y)) => x >= y,
        _ => a >= b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn next_link(pointer: &str) -> Cursor {
        let mode = CursorMode::NextLink {
            pointer: pointer.to_string(),
        };
        Cursor::new(mode)
    }

    fn since_cursor(param: &str, ptr: &str) -> Cursor {
        let mode = CursorMode::Since {
            param: param.to_string(),
            record_time_pointer: ptr.to_string(),
        };
        Cursor::new(mode)
    }

    #[test]
    fn nextlink_starts_at_base() {
        let cursor = next_link("/@odata.nextLink");
        assert_eq!(cursor.next_request(), NextRequest::Base(Vec::new()));
    }

    #[test]
    fn nextlink_advances_and_follows() {
        let mut cursor = next_link("/@odata.nextLink");
        assert!(cursor.advance(&json!({"@odata.nextLink": "u2"}), &[]));
        let expected = NextRequest::Url("u2".to_string());
        assert_eq!(cursor.next_request(), expected);
    }

    #[test]
    fn nextlink_absent_ends_the_walk() {
        let mut cursor = next_link("/next");
        assert!(cursor.advance(&json!({"next": "u2"}), &[]));
        assert!(!cursor.advance(&json!({"other": 1}), &[]));
        assert_eq!(cursor.next_request(), NextRequest::Base(Vec::new()));
    }

    #[test]
    fn nextlink_empty_string_is_not_a_next_page() {
        let mut cursor = next_link("/next");
        assert!(!cursor.advance(&json!({"next": ""}), &[]));
    }

    #[test]
    fn since_sends_nothing_first_poll() {
        let cursor = since_cursor("since", "/ts");
        assert_eq!(cursor.next_request(), NextRequest::Base(Vec::new()));
    }

    #[test]
    fn since_advances_to_max_string_timestamp() {
        let mut cursor = since_cursor("since", "/ts");
        let records = vec![
            json!({"ts": "2026-01-01T00:00:01Z"}),
            json!({"ts": "2026-01-01T00:00:03Z"}),
            json!({"ts": "2026-01-01T00:00:02Z"}),
        ];
        cursor.advance(&json!({}), &records);
        assert_eq!(
            cursor.state().since.as_deref(),
            Some("2026-01-01T00:00:03Z")
        );
    }

    #[test]
    fn since_advances_numerically_not_lexically() {
        let mut cursor = since_cursor("from", "/epoch");
        let records = vec![json!({"epoch": 9}), json!({"epoch": 10})];
        cursor.advance(&json!({}), &records);
        assert_eq!(cursor.state().since.as_deref(), Some("10"));
    }

    #[test]
    fn since_never_goes_backwards() {
        let state = CursorState {
            since: Some("2026-06-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        let mode = CursorMode::Since {
            param: "since".to_string(),
            record_time_pointer: "/ts".to_string(),
        };
        let mut cursor = Cursor::with_state(mode, state);
        cursor.advance(&json!({}), &[json!({"ts": "2026-01-01T00:00:00Z"})]);
        assert_eq!(
            cursor.state().since.as_deref(),
            Some("2026-06-01T00:00:00Z")
        );
    }

    #[test]
    fn since_ignores_malformed_record_time() {
        let state = CursorState {
            since: Some("100".to_string()),
            ..Default::default()
        };
        let mode = CursorMode::Since {
            param: "since".to_string(),
            record_time_pointer: "/ts".to_string(),
        };
        let mut cursor = Cursor::with_state(mode, state);
        let records = vec![json!({"other": 1}), json!({"ts": null})];
        cursor.advance(&json!({}), &records);
        assert_eq!(cursor.state().since.as_deref(), Some("100"));
    }

    #[test]
    fn state_round_trips() {
        let state = CursorState {
            next_url: Some("https://api.example.com/p3".to_string()),
            since: None,
        };
        let mode = CursorMode::NextLink {
            pointer: "/next".to_string(),
        };
        let cursor = Cursor::with_state(mode, state.clone());
        assert_eq!(cursor.state(), &state);
        let expected = NextRequest::Url("https://api.example.com/p3".to_string());
        assert_eq!(cursor.next_request(), expected);
    }
}
