//! Minimal AWS Signature Version 4 signing for S3 `PutObject`.
//!
//! Scope is deliberately narrow: header-based auth (no presigned URLs, no
//! chunked uploads), service hardcoded to `s3`. Pinned against the official
//! AWS SigV4 examples in the test module below.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// AWS-style URI encoding: RFC 3986 unreserved characters pass through,
/// everything else is `%XX`-encoded. `/` is preserved unless `encode_slash`.
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// Build the `Authorization` header value for an S3 request.
///
/// * `canonical_path` — already URI-encoded (see [`uri_encode`]), starts with `/`.
/// * `extra_headers` — additional headers to include in signing (e.g.
///   `x-amz-security-token`); names are lowercased, values trimmed.
///   `host`, `x-amz-content-sha256` and `x-amz-date` are always signed and
///   must be sent on the wire with exactly the values derived here.
/// * `payload_hash` — lowercase hex SHA-256 of the request body.
///
/// The query string is assumed empty (PutObject needs none).
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    method: &str,
    host: &str,
    canonical_path: &str,
    extra_headers: &[(&str, &str)],
    payload_hash: &str,
    timestamp: &DateTime<Utc>,
    region: &str,
    creds: &Credentials,
) -> String {
    let amz_date = timestamp.format("%Y%m%dT%H%M%SZ").to_string();
    let date = timestamp.format("%Y%m%d").to_string();

    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), host.trim().into()),
        ("x-amz-content-sha256".into(), payload_hash.into()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    for (k, v) in extra_headers {
        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    // Empty canonical query string between path and headers.
    let canonical_request = format!(
        "{method}\n{canonical_path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_creds() -> Credentials {
        Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    fn doc_ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// Official AWS example: GET Object
    /// <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>
    #[test]
    fn aws_doc_example_get_object() {
        let auth = sign_request(
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            &[("range", "bytes=0-9")],
            // SHA-256 of an empty payload.
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            &doc_ts(),
            "us-east-1",
            &doc_creds(),
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// Official AWS example: PUT Object (`test$file.text`) — also pins the
    /// URI encoding of `$` in the canonical path.
    #[test]
    fn aws_doc_example_put_object() {
        let payload_hash = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(
            payload_hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let auth = sign_request(
            "PUT",
            "examplebucket.s3.amazonaws.com",
            &format!("/{}", uri_encode("test$file.text", false)),
            &[
                ("date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            &payload_hash,
            &doc_ts(),
            "us-east-1",
            &doc_creds(),
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, \
             Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn uri_encode_lake_key() {
        assert_eq!(
            uri_encode("4002/dt=2026-06-12/hour=14/sensor=a b/x.parquet", false),
            "4002/dt%3D2026-06-12/hour%3D14/sensor%3Da%20b/x.parquet"
        );
        assert_eq!(uri_encode("my-bucket_0.9~ok", true), "my-bucket_0.9~ok");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }
}
