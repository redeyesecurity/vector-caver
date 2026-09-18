//! Stateful HTTP-pull logic for the caver collector.
//!
//! Stock Vector's `http_client` source is stateless: it re-issues the same
//! request on a fixed interval and decodes whatever comes back. Pulling from
//! real security/SaaS APIs needs three things it cannot do, and those three
//! things live here as pure, transport-agnostic logic so they can be unit
//! tested without a running Vector topology:
//!
//!   1. [`oauth`] - OAuth2 client-credentials token fetch with
//!      refresh-before-expiry. The caller performs the actual token HTTP
//!      request; this crate decides *when* a refresh is due and parses the
//!      token response.
//!   2. [`cursor`] - a checkpoint carried across polls, either a `nextLink`
//!      style absolute follow-URL or a time-window `since` high-water mark.
//!   3. [`extract`] - pulling the record array out of a response body via a
//!      JSON pointer (RFC 6901).
//!
//! The Vector integration (config struct, `SourceConfig`, the async poll loop
//! that does the HTTP) lives in the root vector workspace at
//! `src/sources/caver_http_pull/`, mirroring how `caver-sink-parquet` pairs
//! with `src/sinks/caver_parquet/`.
//!
//! Tracked: caver-collector#1842

pub mod cursor;
pub mod extract;
pub mod oauth;

pub use cursor::{Cursor, CursorMode, CursorState, NextRequest};
pub use extract::{extract_records, ExtractError};
pub use oauth::{client_credentials_form, Token, TokenCache, TokenError};
