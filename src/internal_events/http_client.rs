use std::time::Duration;

use http::{
    HeaderMap, Request, Response, Version,
    header::{self, HeaderValue},
};
use hyper::body::HttpBody;
use vector_lib::{
    NamedInternalEvent, counter, histogram,
    internal_event::{CounterName, HistogramName, InternalEvent, error_stage, error_type},
};

// ── Telemetry traits ──────────────────────────────────────────────────────────

/// Provides the data required to emit HTTP request telemetry.
///
/// `method`, `uri`, `sanitized_headers`, and `body_debug` are required; every
/// transport must implement them.
///
/// `version` is optional (default: `None`) because some transports — notably
/// the AWS SDK connector layer — do not expose HTTP version in their request
/// type.
pub trait HttpRequestTelemetry {
    fn method(&self) -> &str;
    fn uri(&self) -> String;
    fn headers(&self) -> HeaderMap<HeaderValue>;
    /// Returns the body size bounds as `(lower, upper)`.
    fn body_size_hint(&self) -> (u64, Option<u64>);
    /// Returns the HTTP version when the transport exposes it.
    fn version(&self) -> Option<Version> {
        None
    }

    /// Returns the headers with sensitive values redacted.
    ///
    /// Provided by default; implementors only need to implement [`headers`].
    fn sanitized_headers(&self) -> HeaderMap<HeaderValue> {
        remove_sensitive(self.headers())
    }
}

/// Provides the data required to emit HTTP response telemetry.
///
/// Same rationale as [`HttpRequestTelemetry`]: `version` is optional.
pub trait HttpResponseTelemetry {
    fn status_u16(&self) -> u16;
    fn headers(&self) -> HeaderMap<HeaderValue>;
    /// Returns the body size bounds as `(lower, upper)`.
    fn body_size_hint(&self) -> (u64, Option<u64>);
    /// Returns the HTTP version when the transport exposes it.
    fn version(&self) -> Option<Version> {
        None
    }

    /// Returns the headers with sensitive values redacted.
    ///
    /// Provided by default; implementors only need to implement [`headers`].
    fn sanitized_headers(&self) -> HeaderMap<HeaderValue> {
        remove_sensitive(self.headers())
    }
}

// ── Implementations for the hyper HTTP types (full data) ──────────────────────

impl<T: HttpBody> HttpRequestTelemetry for Request<T> {
    fn method(&self) -> &str {
        self.method().as_str()
    }

    fn uri(&self) -> String {
        self.uri().to_string()
    }

    fn headers(&self) -> HeaderMap<HeaderValue> {
        self.headers().clone()
    }

    fn body_size_hint(&self) -> (u64, Option<u64>) {
        let hint = self.body().size_hint();
        (hint.lower(), hint.upper())
    }

    fn version(&self) -> Option<Version> {
        Some(self.version())
    }
}

impl<T: HttpBody> HttpResponseTelemetry for Response<T> {
    fn status_u16(&self) -> u16 {
        self.status().as_u16()
    }

    fn headers(&self) -> HeaderMap<HeaderValue> {
        self.headers().clone()
    }

    fn body_size_hint(&self) -> (u64, Option<u64>) {
        let hint = self.body().size_hint();
        (hint.lower(), hint.upper())
    }

    fn version(&self) -> Option<Version> {
        Some(self.version())
    }
}

// ── Events ────────────────────────────────────────────────────────────────────

#[derive(Debug, NamedInternalEvent)]
pub struct AboutToSendHttpRequest<'a, T: HttpRequestTelemetry> {
    pub request: &'a T,
}

impl<T: HttpRequestTelemetry> InternalEvent for AboutToSendHttpRequest<'_, T> {
    fn emit(self) {
        debug!(
            message = "Sending HTTP request.",
            uri = %self.request.uri(),
            method = %self.request.method(),
            version = ?self.request.version(),
            headers = ?self.request.sanitized_headers(),
            body = %FormatBodySizeHint::from(self.request.body_size_hint()),
        );
        counter!(CounterName::HttpClientRequestsSentTotal, "method" => self.request.method().to_string())
            .increment(1);
    }
}

#[derive(Debug, NamedInternalEvent)]
pub struct GotHttpResponse<'a, T: HttpResponseTelemetry> {
    pub response: &'a T,
    pub roundtrip: Duration,
}

impl<T: HttpResponseTelemetry> InternalEvent for GotHttpResponse<'_, T> {
    fn emit(self) {
        let status = self.response.status_u16();
        let status_str = status.to_string();
        debug!(
            message = "HTTP response.",
            status = %status,
            version = ?self.response.version(),
            headers = ?self.response.sanitized_headers(),
            body = %FormatBodySizeHint::from(self.response.body_size_hint()),

        );
        counter!(CounterName::HttpClientResponsesTotal, "status" => status_str.clone())
            .increment(1);
        histogram!(HistogramName::HttpClientRttSeconds).record(self.roundtrip);
        histogram!(HistogramName::HttpClientResponseRttSeconds, "status" => status_str)
            .record(self.roundtrip);
    }
}

#[derive(Debug, NamedInternalEvent)]
pub struct GotHttpWarning<'a> {
    pub error: &'a dyn std::error::Error,
    pub roundtrip: Duration,
}

impl InternalEvent for GotHttpWarning<'_> {
    fn emit(self) {
        warn!(
            message = "HTTP error.",
            error = %self.error,
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::PROCESSING,
        );
        counter!(CounterName::HttpClientErrorsTotal, "error_kind" => self.error.to_string())
            .increment(1);
        histogram!(HistogramName::HttpClientRttSeconds).record(self.roundtrip);
        histogram!(HistogramName::HttpClientErrorRttSeconds, "error_kind" => self.error.to_string())
            .record(self.roundtrip);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn remove_sensitive(mut headers: HeaderMap<HeaderValue>) -> HeaderMap<HeaderValue> {
    for name in &[
        header::AUTHORIZATION,
        header::PROXY_AUTHORIZATION,
        header::COOKIE,
        header::SET_COOKIE,
    ] {
        if let Some(value) = headers.get_mut(name) {
            value.set_sensitive(true);
        }
    }
    headers
}

/// Formats a body size hint `(lower, upper)` for debug logging.
struct FormatBodySizeHint(u64, Option<u64>);

impl From<(u64, Option<u64>)> for FormatBodySizeHint {
    fn from((lower, upper): (u64, Option<u64>)) -> Self {
        FormatBodySizeHint(lower, upper)
    }
}

impl std::fmt::Display for FormatBodySizeHint {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match (self.0, self.1) {
            (0, None) => write!(fmt, "[unknown]"),
            (lower, None) => write!(fmt, "[>={lower} bytes]"),

            (0, Some(0)) => write!(fmt, "[empty]"),
            (0, Some(upper)) => write!(fmt, "[<={upper} bytes]"),

            (lower, Some(upper)) if lower == upper => write!(fmt, "[{lower} bytes]"),
            (lower, Some(upper)) => write!(fmt, "[{lower}..={upper} bytes]"),
        }
    }
}
