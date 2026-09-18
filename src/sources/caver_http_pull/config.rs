//! Configuration and poll driver for the `caver_http_pull` source.
//!
//! The reusable, transport-free logic (OAuth2 token lifecycle, cursor
//! checkpoint, response-array extraction) lives in the `caver-source-http-pull`
//! crate. This module is the Vector integration: the
//! `#[configurable_component]` config, the `SourceConfig` impl, and the async
//! poll loop that does the actual HTTP with Vector's own client and decodes
//! each extracted record into an event.
//!
//! Why not the stock `http_client` source: its scrape loop is stateless. It
//! rebuilds its context every interval and cannot carry a bearer token, a
//! `nextLink`, or a `since` high-water mark from one poll to the next, nor pull
//! records out of a nested array. Those three are exactly this source's job.

use std::collections::HashMap;
use std::time::Duration;

use bytes::BytesMut;
use chrono::Utc;
use futures_util::FutureExt;
use http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderName, HeaderValue, Method, Request, StatusCode, Uri,
};
use hyper::Body;
use serde_json::Value;
use serde_with::serde_as;
use tokio_util::codec::Decoder as _;
use vector_lib::{
    codecs::{
        decoding::{DeserializerConfig, FramingConfig},
        JsonDeserializerConfig,
    },
    config::{LogNamespace, SourceOutput},
    configurable::configurable_component,
    event::Event,
    shutdown::ShutdownSignal,
};

use caver_source_http_pull::{
    client_credentials_form, extract_records, Cursor, CursorMode, NextRequest, TokenCache,
};

use crate::{
    codecs::{Decoder, DecodingConfig},
    config::{SourceConfig, SourceContext},
    http::HttpClient,
    internal_events::{EndpointBytesReceived, StreamClosedError},
    serde::default_framing_message_based,
    tls::{TlsConfig, TlsSettings},
    SourceSender,
};

const fn default_interval() -> Duration {
    Duration::from_secs(60)
}

const fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

const fn default_refresh_skew_secs() -> i64 {
    30
}

const fn default_token_ttl_secs() -> i64 {
    3600
}

const fn default_max_pages() -> usize {
    100
}

const fn default_method() -> PullMethod {
    PullMethod::Get
}

/// Records are JSON by default, so each extracted record becomes a structured
/// event out of the box.
fn default_decoding() -> DeserializerConfig {
    DeserializerConfig::Json(JsonDeserializerConfig::new(Default::default()))
}

/// HTTP method for the data request.
#[configurable_component]
#[derive(Clone, Copy, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum PullMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST (for query-style pull APIs that take a request body).
    Post,
}

impl From<PullMethod> for Method {
    fn from(method: PullMethod) -> Self {
        match method {
            PullMethod::Get => Self::GET,
            PullMethod::Post => Self::POST,
        }
    }
}

/// Authentication for the data request.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(tag = "strategy", rename_all = "snake_case")]
#[configurable(metadata(
    docs::enum_tag_description = "The authentication strategy for the data request."
))]
pub enum PullAuth {
    /// OAuth2 client-credentials grant. A bearer token is fetched from
    /// `token_url` and refreshed before it expires. The client secret is read
    /// from an environment variable so it never appears in a config file.
    Oauth2 {
        /// The OAuth2 token endpoint (the client-credentials grant is POSTed
        /// here as `application/x-www-form-urlencoded`).
        #[configurable(metadata(
            docs::examples = "https://login.microsoftonline.com/TENANT/oauth2/v2.0/token"
        ))]
        token_url: String,

        /// The OAuth2 client identifier.
        client_id: String,

        /// Name of the environment variable holding the OAuth2 client secret.
        /// The secret value itself is never written in config.
        #[configurable(metadata(docs::examples = "CAVER_HTTP_PULL_CLIENT_SECRET"))]
        client_secret_env: String,

        /// Optional OAuth2 scope requested for the token.
        #[serde(default)]
        #[configurable(metadata(docs::examples = "https://graph.microsoft.com/.default"))]
        scope: Option<String>,

        /// Refresh the token this many seconds before it actually expires, so an
        /// in-flight request cannot race expiry.
        #[serde(default = "default_refresh_skew_secs")]
        refresh_skew_secs: i64,

        /// Assumed token lifetime, in seconds, when the token response omits
        /// `expires_in`.
        #[serde(default = "default_token_ttl_secs")]
        default_token_ttl_secs: i64,
    },
    /// A static header, e.g. an API key. The value is read from an environment
    /// variable so it never appears in a config file.
    Header {
        /// The header name to set on every data request.
        #[configurable(metadata(docs::examples = "Authorization"))]
        name: String,

        /// Name of the environment variable holding the header value.
        #[configurable(metadata(docs::examples = "CAVER_HTTP_PULL_API_KEY"))]
        value_env: String,
    },
}

/// Pagination / checkpoint strategy carried across polls.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[configurable(metadata(
    docs::enum_tag_description = "How the source paginates and checkpoints across polls."
))]
pub enum Pagination {
    /// Follow an absolute next-page URL found in each response body until it is
    /// absent, then start over from the base endpoint on the next interval.
    NextLink {
        /// RFC 6901 JSON pointer to the next-page URL in the response body.
        #[configurable(metadata(docs::examples = "/@odata.nextLink"))]
        pointer: String,

        /// Maximum pages followed within a single poll, bounding a runaway
        /// pagination loop.
        #[serde(default = "default_max_pages")]
        max_pages: usize,
    },
    /// Send a high-water timestamp as a query parameter and advance it from a
    /// timestamp field on each record, so each poll asks only for newer data.
    Since {
        /// The query-parameter name the high-water value is sent under.
        #[configurable(metadata(docs::examples = "since"))]
        param: String,

        /// RFC 6901 JSON pointer, relative to a single record, to the timestamp
        /// field used to advance the window.
        #[configurable(metadata(docs::examples = "/createdDateTime"))]
        record_time_pointer: String,

        /// Optional initial high-water value sent on the first poll.
        #[serde(default)]
        start: Option<String>,
    },
}

/// Configuration for the `caver_http_pull` source.
#[serde_as]
#[configurable_component(source(
    "caver_http_pull",
    "Pull records from a stateful HTTP API: OAuth2 client-credentials auth, a cursor/nextLink checkpoint carried across polls, and response-array extraction."
))]
#[derive(Clone, Debug)]
pub struct CaverHttpPullConfig {
    /// The HTTP endpoint to pull records from. The full path must be specified.
    #[configurable(metadata(
        docs::examples = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    ))]
    pub endpoint: String,

    /// The interval between polls.
    #[serde(default = "default_interval")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "scrape_interval_secs")]
    #[configurable(metadata(docs::human_name = "Scrape Interval"))]
    pub interval: Duration,

    /// The timeout for each HTTP request.
    #[serde(default = "default_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "scrape_timeout_secs")]
    #[configurable(metadata(docs::human_name = "Scrape Timeout"))]
    pub timeout: Duration,

    /// The HTTP method used for the data request. The OAuth2 token request is
    /// always a POST regardless of this setting.
    #[serde(default = "default_method")]
    pub method: PullMethod,

    /// JSON pointer (RFC 6901) to the array of records in the response body. An
    /// empty pointer selects the whole body, for an API that returns a bare
    /// array.
    #[serde(default)]
    #[configurable(metadata(docs::examples = "/value"))]
    pub records_pointer: String,

    /// Treat a records pointer that resolves to a single object (not an array)
    /// as a one-record page instead of an error.
    #[serde(default)]
    pub wrap_single_object: bool,

    /// An optional request body sent with the data request, for `POST`-style
    /// pull APIs. Sent verbatim; `Content-Type` defaults to `application/json`
    /// unless set in `headers`.
    #[serde(default)]
    pub body: Option<String>,

    /// The namespace to use for logs. This overrides the global setting.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    pub log_namespace: Option<bool>,

    /// Authentication for the data request. Omit for an unauthenticated API.
    #[configurable(derived)]
    #[serde(default)]
    pub auth: Option<PullAuth>,

    /// Pagination / checkpoint strategy carried across polls. Omit for a
    /// stateless poll that re-requests the same endpoint every interval.
    #[configurable(derived)]
    #[serde(default)]
    pub pagination: Option<Pagination>,

    /// Static query-string parameters added to every data request.
    #[serde(default)]
    #[configurable(metadata(
        docs::additional_props_description = "A query-string parameter and its value."
    ))]
    pub query: HashMap<String, String>,

    /// Headers added to every data request.
    #[serde(default)]
    #[configurable(metadata(
        docs::additional_props_description = "An HTTP request header and its value(s)."
    ))]
    pub headers: HashMap<String, Vec<String>>,

    /// Decoder applied to each extracted record. Defaults to JSON so records
    /// become structured events.
    #[configurable(derived)]
    #[serde(default = "default_decoding")]
    pub decoding: DeserializerConfig,

    /// Framing applied before decoding each record.
    #[configurable(derived)]
    #[serde(default = "default_framing_message_based")]
    pub framing: FramingConfig,

    /// TLS configuration.
    #[configurable(derived)]
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

impl Default for CaverHttpPullConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://localhost/records".to_string(),
            interval: default_interval(),
            timeout: default_timeout(),
            method: default_method(),
            records_pointer: String::new(),
            wrap_single_object: false,
            body: None,
            log_namespace: None,
            auth: None,
            pagination: None,
            query: HashMap::new(),
            headers: HashMap::new(),
            decoding: default_decoding(),
            framing: default_framing_message_based(),
            tls: None,
        }
    }
}

impl_generate_config_from_default!(CaverHttpPullConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "caver_http_pull")]
impl SourceConfig for CaverHttpPullConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<crate::sources::Source> {
        let endpoint: Uri = self
            .endpoint
            .parse()
            .map_err(|e| format!("invalid `endpoint`: {e}"))?;

        let log_namespace = cx.log_namespace(self.log_namespace);

        let decoder =
            DecodingConfig::new(self.framing.clone(), self.decoding.clone(), log_namespace)
                .build()?;

        // Pre-parse the user headers once so a bad header name/value fails at
        // boot, not silently on every poll.
        let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
        for (name, values) in &self.headers {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| format!("invalid header name `{name}`: {e}"))?;
            for value in values {
                let header_value = HeaderValue::from_str(value)
                    .map_err(|e| format!("invalid value for header `{name}`: {e}"))?;
                headers.push((header_name.clone(), header_value));
            }
        }

        // Resolve auth (reads the secret env var now, so a missing secret is a
        // boot error rather than a per-request failure).
        let auth = match self.auth.as_ref() {
            Some(auth) => Some(PreparedAuth::from_config(auth)?),
            None => None,
        };

        let (cursor, max_pages) = match self.pagination.as_ref() {
            Some(Pagination::NextLink { pointer, max_pages }) => (
                Some(Cursor::new(CursorMode::NextLink {
                    pointer: pointer.clone(),
                })),
                (*max_pages).max(1),
            ),
            Some(Pagination::Since {
                param,
                record_time_pointer,
                start,
            }) => {
                let mut cursor = Cursor::new(CursorMode::Since {
                    param: param.clone(),
                    record_time_pointer: record_time_pointer.clone(),
                });
                if let Some(start) = start {
                    // Seed the first poll's high-water mark.
                    let mode = cursor.mode().clone();
                    cursor = Cursor::with_state(
                        mode,
                        caver_source_http_pull::CursorState {
                            since: Some(start.clone()),
                            ..Default::default()
                        },
                    );
                }
                (Some(cursor), 1)
            }
            None => (None, 1),
        };

        let tls = TlsSettings::from_options(self.tls.as_ref())?;
        let client: HttpClient<Body> =
            HttpClient::new(tls, &cx.proxy).map_err(|e| e.to_string())?;

        // Whether the user already set these headers, so we do not stomp them
        // with defaults. HeaderName normalizes to lowercase, but the config map
        // keys are raw strings, so compare case-insensitively.
        let has_accept = self
            .headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("accept"));
        let has_content_type = self
            .headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-type"));

        let source = HttpPullSource {
            client,
            endpoint,
            method: self.method.into(),
            timeout: self.timeout,
            query: self.query.clone().into_iter().collect(),
            headers,
            has_accept,
            has_content_type,
            body: self.body.clone(),
            auth,
            cursor,
            max_pages,
            records_pointer: self.records_pointer.clone(),
            wrap_object: self.wrap_single_object,
            decoder,
            log_namespace,
            out: cx.out,
        };

        let interval = self.interval;
        Ok(source.run(interval, cx.shutdown).boxed())
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global_log_namespace.merge(self.log_namespace);
        let schema_definition = self
            .decoding
            .schema_definition(log_namespace)
            .with_standard_vector_source_metadata();
        vec![SourceOutput::new_maybe_logs(
            self.decoding.output_type(),
            schema_definition,
        )]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

/// Auth resolved at build time: secrets already read from the environment and
/// header names/values already validated, so the poll loop never touches the
/// environment or fails to construct a header.
enum PreparedAuth {
    Oauth2 {
        token_url: Uri,
        client_id: String,
        client_secret: String,
        scope: Option<String>,
        cache: TokenCache,
    },
    Header {
        name: HeaderName,
        value: HeaderValue,
    },
}

impl PreparedAuth {
    fn from_config(auth: &PullAuth) -> Result<Self, String> {
        match auth {
            PullAuth::Oauth2 {
                token_url,
                client_id,
                client_secret_env,
                scope,
                refresh_skew_secs,
                default_token_ttl_secs,
            } => {
                let token_url: Uri = token_url
                    .parse()
                    .map_err(|e| format!("invalid `token_url`: {e}"))?;
                let client_secret = std::env::var(client_secret_env).map_err(|_| {
                    format!(
                        "environment variable `{client_secret_env}` (OAuth2 client secret) is not set"
                    )
                })?;
                Ok(Self::Oauth2 {
                    token_url,
                    client_id: client_id.clone(),
                    client_secret,
                    scope: scope.clone(),
                    cache: TokenCache::new(*refresh_skew_secs, *default_token_ttl_secs),
                })
            }
            PullAuth::Header { name, value_env } => {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid auth header name `{name}`: {e}"))?;
                let value = std::env::var(value_env).map_err(|_| {
                    format!("environment variable `{value_env}` (auth header value) is not set")
                })?;
                let value = HeaderValue::from_str(&value).map_err(|_| {
                    format!("value from `{value_env}` is not a valid HTTP header value")
                })?;
                Ok(Self::Header { name, value })
            }
        }
    }
}

/// The outcome of one HTTP request within a poll cycle.
enum FetchOutcome {
    /// Records decoded into events, plus whether another page should be fetched
    /// immediately (only `nextLink` pagination ever asks for more).
    Events { events: Vec<Event>, has_more: bool },
    /// The endpoint returned `401`; the OAuth2 token was cleared so the next
    /// cycle refreshes.
    Unauthorized,
    /// A transient error (network, timeout, non-success status, bad body). The
    /// page walk ends; the next interval retries.
    Failed,
}

/// The running poll driver. All state that must survive across polls (the
/// token cache and the cursor) lives here for the lifetime of the source.
struct HttpPullSource {
    client: HttpClient<Body>,
    endpoint: Uri,
    method: Method,
    timeout: Duration,
    query: Vec<(String, String)>,
    headers: Vec<(HeaderName, HeaderValue)>,
    has_accept: bool,
    has_content_type: bool,
    body: Option<String>,
    auth: Option<PreparedAuth>,
    cursor: Option<Cursor>,
    max_pages: usize,
    records_pointer: String,
    wrap_object: bool,
    decoder: Decoder,
    log_namespace: LogNamespace,
    out: SourceSender,
}

impl HttpPullSource {
    async fn run(mut self, interval: Duration, shutdown: ShutdownSignal) -> Result<(), ()> {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => break,
                _ = ticker.tick() => {
                    if self.poll_cycle().await.is_err() {
                        // Downstream is closed; stop the source.
                        return Err(());
                    }
                }
            }
        }
        Ok(())
    }

    /// One scrape interval: ensure a token, then walk pages (bounded by
    /// `max_pages`) sending events as they decode. Returns `Err` only when the
    /// downstream is closed.
    async fn poll_cycle(&mut self) -> Result<(), ()> {
        if let Err(error) = self.ensure_token().await {
            warn!(
                message = "OAuth2 token refresh failed; skipping this poll cycle.",
                %error,
            );
            return Ok(());
        }

        let mut pages = 0usize;
        loop {
            match self.fetch_one().await {
                FetchOutcome::Events { events, has_more } => {
                    if !events.is_empty() {
                        let count = events.len();
                        if self.out.send_batch(events).await.is_err() {
                            emit!(StreamClosedError { count });
                            return Err(());
                        }
                    }
                    pages += 1;
                    if !has_more || pages >= self.max_pages {
                        break;
                    }
                }
                FetchOutcome::Unauthorized => {
                    if let Some(PreparedAuth::Oauth2 { cache, .. }) = self.auth.as_mut() {
                        cache.clear();
                    }
                    break;
                }
                FetchOutcome::Failed => break,
            }
        }
        Ok(())
    }

    /// Refresh the OAuth2 token if one is due. No-op for header/no auth.
    async fn ensure_token(&mut self) -> Result<(), String> {
        let now = Utc::now();
        let (token_url, client_id, client_secret, scope) = match self.auth.as_ref() {
            Some(PreparedAuth::Oauth2 {
                token_url,
                client_id,
                client_secret,
                scope,
                cache,
            }) => {
                if !cache.needs_refresh(now) {
                    return Ok(());
                }
                (
                    token_url.clone(),
                    client_id.clone(),
                    client_secret.clone(),
                    scope.clone(),
                )
            }
            _ => return Ok(()),
        };

        let form = client_credentials_form(&client_id, &client_secret, scope.as_deref());
        // Scope the serializer so it is dropped before the await below: it holds
        // a non-Send `dyn Fn`, which would otherwise make the whole poll future
        // non-Send and fail `.boxed()`.
        let body = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.extend_pairs(form);
            serializer.finish()
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri(token_url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .body(Body::from(body))
            .map_err(|e| format!("failed to build token request: {e}"))?;

        let response = tokio::time::timeout(self.timeout, self.client.send(request))
            .await
            .map_err(|_| "token request timed out".to_string())?
            .map_err(|e| format!("token request failed: {e}"))?;

        let (parts, body) = response.into_parts();
        if !parts.status.is_success() {
            return Err(format!("token endpoint returned HTTP {}", parts.status));
        }
        let bytes = http_body::Body::collect(body)
            .await
            .map_err(|e| format!("failed to read token response: {e}"))?
            .to_bytes();
        let json: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("token response was not valid JSON: {e}"))?;

        let fetched_at = Utc::now();
        if let Some(PreparedAuth::Oauth2 { cache, .. }) = self.auth.as_mut() {
            cache
                .set_from_response(&json, fetched_at)
                .map_err(|e| format!("could not parse token response: {e}"))?;
        }
        Ok(())
    }

    /// Issue one data request (following a `nextLink` when mid-walk), decode
    /// the extracted records into events, and advance the cursor.
    async fn fetch_one(&mut self) -> FetchOutcome {
        let request_target = match &self.cursor {
            Some(cursor) => cursor.next_request(),
            None => NextRequest::Base(Vec::new()),
        };
        let uri = match &request_target {
            NextRequest::Url(url) => match url.parse::<Uri>() {
                Ok(uri) => uri,
                Err(error) => {
                    warn!(
                        message = "Invalid nextLink URL in response; ending page walk.",
                        %error,
                    );
                    return FetchOutcome::Failed;
                }
            },
            NextRequest::Base(params) => self.merged_uri(params),
        };
        let url = uri.to_string();

        let request = match self.build_request(&uri) {
            Ok(request) => request,
            Err(error) => {
                warn!(message = "Failed to build data request.", %error, url = %url);
                return FetchOutcome::Failed;
            }
        };

        let response = match tokio::time::timeout(self.timeout, self.client.send(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                warn!(message = "HTTP request failed.", %error, url = %url);
                return FetchOutcome::Failed;
            }
            Err(_) => {
                warn!(message = "HTTP request timed out.", url = %url);
                return FetchOutcome::Failed;
            }
        };

        let (parts, body) = response.into_parts();
        let status = parts.status;
        if status == StatusCode::UNAUTHORIZED {
            return FetchOutcome::Unauthorized;
        }
        if !status.is_success() {
            warn!(message = "Non-success HTTP status from pull endpoint.", %status, url = %url);
            return FetchOutcome::Failed;
        }

        let bytes = match http_body::Body::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => {
                warn!(message = "Failed to read response body.", %error, url = %url);
                return FetchOutcome::Failed;
            }
        };
        emit!(EndpointBytesReceived {
            byte_size: bytes.len(),
            protocol: uri.scheme_str().unwrap_or("http"),
            endpoint: url.as_str(),
        });

        let json: Value = match serde_json::from_slice(&bytes) {
            Ok(json) => json,
            Err(error) => {
                warn!(message = "Response body was not valid JSON.", %error, url = %url);
                return FetchOutcome::Failed;
            }
        };

        let records = match extract_records(&json, &self.records_pointer, self.wrap_object) {
            Ok(records) => records,
            Err(error) => {
                warn!(
                    message = "Could not locate the records array in the response.",
                    %error, url = %url,
                );
                return FetchOutcome::Failed;
            }
        };

        let mut events = Vec::with_capacity(records.len());
        for record in &records {
            self.decode_record(record, &mut events);
        }
        self.enrich(&mut events);

        let has_more = match self.cursor.as_mut() {
            Some(cursor) => cursor.advance(&json, &records),
            None => false,
        };

        FetchOutcome::Events { events, has_more }
    }

    /// Build the data request: method, URI, user headers, an `Accept: json`
    /// default, auth, and an optional body.
    fn build_request(&self, uri: &Uri) -> Result<Request<Body>, String> {
        let mut builder = Request::builder()
            .method(self.method.clone())
            .uri(uri.clone());

        for (name, value) in &self.headers {
            builder = builder.header(name.clone(), value.clone());
        }
        if !self.has_accept {
            builder = builder.header(ACCEPT, "application/json");
        }

        match &self.auth {
            Some(PreparedAuth::Oauth2 { cache, .. }) => {
                if let Some(bearer) = cache.bearer() {
                    let value = HeaderValue::from_str(&format!("Bearer {bearer}"))
                        .map_err(|_| "OAuth2 token is not a valid header value".to_string())?;
                    builder = builder.header(AUTHORIZATION, value);
                }
            }
            Some(PreparedAuth::Header { name, value }) => {
                builder = builder.header(name.clone(), value.clone());
            }
            None => {}
        }

        let body = match &self.body {
            Some(body) => {
                if !self.has_content_type {
                    builder = builder.header(CONTENT_TYPE, "application/json");
                }
                Body::from(body.clone())
            }
            None => Body::empty(),
        };

        builder
            .body(body)
            .map_err(|e| format!("failed to build request: {e}"))
    }

    /// Build the base-endpoint URI, merging any existing endpoint query string,
    /// the static `query` params, and the cursor's `since` param.
    fn merged_uri(&self, extra: &[(String, String)]) -> Uri {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        if let Some(existing) = self.endpoint.query() {
            serializer.extend_pairs(url::form_urlencoded::parse(existing.as_bytes()));
        }
        for (key, value) in &self.query {
            serializer.append_pair(key, value);
        }
        for (key, value) in extra {
            serializer.append_pair(key, value);
        }
        let query = serializer.finish();

        let mut builder = Uri::builder();
        if let Some(scheme) = self.endpoint.scheme() {
            builder = builder.scheme(scheme.clone());
        }
        if let Some(authority) = self.endpoint.authority() {
            builder = builder.authority(authority.clone());
        }
        let path_and_query = if query.is_empty() {
            self.endpoint.path().to_string()
        } else {
            format!("{}?{}", self.endpoint.path(), query)
        };
        builder
            .path_and_query(path_and_query)
            .build()
            .unwrap_or_else(|_| self.endpoint.clone())
    }

    /// Re-serialize one record and run it through the configured decoder,
    /// appending the resulting events.
    fn decode_record(&mut self, record: &Value, events: &mut Vec<Event>) {
        let bytes = match serde_json::to_vec(record) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(message = "Failed to re-serialize a record for decoding.", %error);
                return;
            }
        };
        let mut buf = BytesMut::with_capacity(bytes.len());
        buf.extend_from_slice(&bytes);
        loop {
            match self.decoder.decode_eof(&mut buf) {
                Ok(Some((decoded, _))) => events.extend(decoded),
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

    /// Stamp `source_type` and a receive timestamp on each event.
    fn enrich(&self, events: &mut [Event]) {
        let now = Utc::now();
        for event in events.iter_mut() {
            if let Event::Log(log) = event {
                self.log_namespace.insert_standard_vector_source_metadata(
                    log,
                    CaverHttpPullConfig::NAME,
                    now,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<CaverHttpPullConfig>();
    }

    #[test]
    fn parses_oauth2_and_nextlink() {
        let config: CaverHttpPullConfig = toml::from_str(
            r#"
            endpoint = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
            records_pointer = "/value"

            [auth]
            strategy = "oauth2"
            token_url = "https://login.microsoftonline.com/t/oauth2/v2.0/token"
            client_id = "abc"
            client_secret_env = "SECRET_ENV"
            scope = "https://graph.microsoft.com/.default"

            [pagination]
            mode = "next_link"
            pointer = "/@odata.nextLink"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.endpoint,
            "https://graph.microsoft.com/v1.0/auditLogs/signIns"
        );
        assert_eq!(config.records_pointer, "/value");
        match config.auth {
            Some(PullAuth::Oauth2 {
                ref client_id,
                ref client_secret_env,
                refresh_skew_secs,
                ..
            }) => {
                assert_eq!(client_id, "abc");
                assert_eq!(client_secret_env, "SECRET_ENV");
                assert_eq!(refresh_skew_secs, default_refresh_skew_secs());
            }
            other => panic!("expected oauth2 auth, got {other:?}"),
        }
        match config.pagination {
            Some(Pagination::NextLink {
                ref pointer,
                max_pages,
            }) => {
                assert_eq!(pointer, "/@odata.nextLink");
                assert_eq!(max_pages, default_max_pages());
            }
            other => panic!("expected next_link pagination, got {other:?}"),
        }
    }

    #[test]
    fn parses_header_auth_and_since() {
        let config: CaverHttpPullConfig = toml::from_str(
            r#"
            endpoint = "https://api.example.com/events"

            [auth]
            strategy = "header"
            name = "X-Api-Key"
            value_env = "API_KEY_ENV"

            [pagination]
            mode = "since"
            param = "since"
            record_time_pointer = "/createdAt"
            start = "2026-01-01T00:00:00Z"
            "#,
        )
        .unwrap();

        assert!(matches!(config.auth, Some(PullAuth::Header { .. })));
        match config.pagination {
            Some(Pagination::Since {
                ref param,
                ref record_time_pointer,
                ref start,
            }) => {
                assert_eq!(param, "since");
                assert_eq!(record_time_pointer, "/createdAt");
                assert_eq!(start.as_deref(), Some("2026-01-01T00:00:00Z"));
            }
            other => panic!("expected since pagination, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_sane() {
        let config = CaverHttpPullConfig::default();
        assert_eq!(config.interval, Duration::from_secs(60));
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(config.auth.is_none());
        assert!(config.pagination.is_none());
        assert!(matches!(config.method, PullMethod::Get));
    }

    #[test]
    fn prepared_auth_errors_when_secret_env_missing() {
        let auth = PullAuth::Oauth2 {
            token_url: "https://example.com/token".to_string(),
            client_id: "id".to_string(),
            client_secret_env: "DEFINITELY_UNSET_ENV_VAR_FOR_TEST".to_string(),
            scope: None,
            refresh_skew_secs: default_refresh_skew_secs(),
            default_token_ttl_secs: default_token_ttl_secs(),
        };
        // PreparedAuth deliberately has no Debug impl (it holds the resolved
        // secret), so avoid unwrap_err here.
        let err = PreparedAuth::from_config(&auth)
            .err()
            .expect("expected an error for a missing secret env var");
        assert!(err.contains("DEFINITELY_UNSET_ENV_VAR_FOR_TEST"));
    }
}
