use std::path::PathBuf;
use std::sync::Arc;

use futures::{FutureExt, future};
use vector_lib::configurable::configurable_component;

use crate::{
    config::{AcknowledgementsConfig, GenerateConfig, Input, SinkConfig, SinkContext},
    sinks::{Healthcheck, VectorSink, caver_parquet::sink::CaverParquetSink},
};

const fn default_batch_size() -> usize {
    500
}

fn default_class_uid_field() -> String {
    "class_uid".into()
}

fn default_region() -> String {
    "us-east-1".into()
}

fn default_access_key_env() -> String {
    "AWS_ACCESS_KEY_ID".into()
}

fn default_secret_key_env() -> String {
    "AWS_SECRET_ACCESS_KEY".into()
}

const fn default_max_retries() -> u32 {
    3
}

fn default_writer_name() -> String {
    "collector".into()
}

fn default_staging_prefix() -> String {
    "uf/ocsf".into()
}

/// Object layout written to the lake.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LayoutConfig {
    /// The caver_staging PARQUET-CONTRACT (typed columns, zstd,
    /// `<staging_prefix>/<source>/year=/month=/day=/` keys) — the shape the
    /// Caver compactor and lake reader serve. Output is queryable out of the
    /// box, matching the Python collector's default.
    #[default]
    CaverStaging,
    /// The sink-original `<class_uid>/dt=` layout with all-string columns.
    /// NOT served by the Caver lake — opt in only for a non-Caver consumer.
    Native,
}

const fn default_retry_base_ms() -> u64 {
    200
}

const fn default_timeout_ms() -> u64 {
    30_000
}

/// Charset safe to embed raw in an object key (and the SigV4 canonical path):
/// anything outside it (`/`, spaces) breaks the lake layout or 403s whole
/// batches. All-dot segments (`.`, `..`) are also rejected — S3 stores them
/// literally, but they confuse path-mapped tooling and listings.
fn is_key_safe(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !s.bytes().all(|b| b == b'.')
}

/// Configuration for the `caver_parquet` sink.
#[configurable_component(sink(
    "caver_parquet",
    "Write OCSF events as partitioned Parquet objects to the Caver lake (S3/MinIO)."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CaverParquetConfig {
    /// The bucket holding the Caver lake.
    #[configurable(metadata(docs::examples = "splunk-events"))]
    pub bucket: String,

    /// Sensor identifier used in the lake partition path
    /// (`<class_uid>/dt=.../hour=.../sensor=<sensor_id>/...`).
    ///
    /// Must match `[A-Za-z0-9._-]+` (it is embedded in the object key).
    /// Defaults to the `HOSTNAME` environment variable, then `/etc/hostname`,
    /// then the literal `collector`.
    #[configurable(metadata(docs::examples = "edge-01"))]
    pub sensor_id: Option<String>,

    /// Event field carrying the OCSF `class_uid` used for partitioning.
    ///
    /// Only used by `layout = "native"`.
    #[serde(default = "default_class_uid_field")]
    pub class_uid_field: String,

    /// Object layout written to the lake.
    #[serde(default)]
    pub layout: LayoutConfig,

    /// caver_staging: source-name path segment
    /// (`<staging_prefix>/<source>/year=...`).
    ///
    /// Must match `[A-Za-z0-9._-]+`. Defaults to `sensor_id` (falling back to
    /// the literal `collector`), like the Python collector sink.
    #[configurable(metadata(docs::examples = "edge-01"))]
    pub source: Option<String>,

    /// caver_staging: filename writer prefix
    /// (`<writer_name>_YYYYMMDD_HHMMSS_<id>.parquet`).
    ///
    /// Must start with a letter and match `[A-Za-z][A-Za-z0-9._-]*` (the
    /// PARQUET-CONTRACT filename shape).
    #[serde(default = "default_writer_name")]
    pub writer_name: String,

    /// caver_staging: key prefix ahead of the source segment.
    ///
    /// Slash-separated segments, each matching `[A-Za-z0-9._-]+`; leading and
    /// trailing slashes are stripped. Change only if the lake's staging
    /// prefix differs from the default.
    #[serde(default = "default_staging_prefix")]
    #[configurable(metadata(docs::examples = "uf/ocsf"))]
    pub staging_prefix: String,

    /// Number of events buffered before a Parquet object is written.
    #[serde(default = "default_batch_size")]
    #[configurable(metadata(docs::examples = 500))]
    pub batch_size: usize,

    /// Local directory receiving failed batches as ndjson (dead-letter queue).
    ///
    /// Events are acknowledged when accepted into a batch, **before** the
    /// object PUT — a later PUT failure does not NACK them. Failed batches go
    /// here; if unset they are dropped (logged at error level and counted in
    /// `component_discarded_events_total`).
    ///
    /// Row shape depends on `layout`: `caver_staging` DLQ rows are
    /// post-preparation (string-typed `_time`, injected `index`/`class_uid`
    /// defaults), `native` rows are the raw accepted maps. Replay tooling
    /// must handle both shapes.
    #[configurable(metadata(docs::examples = "/var/lib/caver/dlq"))]
    pub dlq_path: Option<PathBuf>,

    /// Object-store endpoint, e.g. a MinIO URL (`http://minio.local:9000`).
    ///
    /// If unset, the AWS S3 endpoint for `region` is used.
    /// Requests are always path-style.
    #[configurable(metadata(docs::examples = "http://192.168.1.30:9000"))]
    pub endpoint: Option<String>,

    /// AWS region used for SigV4 signing.
    #[serde(default = "default_region")]
    pub region: String,

    /// Name of the environment variable holding the access key ID.
    ///
    /// The credential itself never appears in config files.
    #[serde(default = "default_access_key_env")]
    #[configurable(metadata(docs::examples = "CAVER_LAKE_ACCESS_KEY"))]
    pub access_key_env: String,

    /// Name of the environment variable holding the secret access key.
    #[serde(default = "default_secret_key_env")]
    #[configurable(metadata(docs::examples = "CAVER_LAKE_SECRET_KEY"))]
    pub secret_key_env: String,

    /// Name of the environment variable holding an optional session token.
    pub session_token_env: Option<String>,

    /// Retries per PUT after the first attempt (5xx/redirect/transport errors only).
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Base for the exponential retry backoff, in milliseconds.
    #[serde(default = "default_retry_base_ms")]
    pub retry_base_ms: u64,

    /// Per-request timeout, in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,
}

impl Default for CaverParquetConfig {
    fn default() -> Self {
        Self {
            bucket: "caver-lake".into(),
            sensor_id: None,
            class_uid_field: default_class_uid_field(),
            layout: LayoutConfig::default(),
            source: None,
            writer_name: default_writer_name(),
            staging_prefix: default_staging_prefix(),
            batch_size: default_batch_size(),
            dlq_path: None,
            endpoint: None,
            region: default_region(),
            access_key_env: default_access_key_env(),
            secret_key_env: default_secret_key_env(),
            session_token_env: None,
            max_retries: default_max_retries(),
            retry_base_ms: default_retry_base_ms(),
            timeout_ms: default_timeout_ms(),
            acknowledgements: AcknowledgementsConfig::default(),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "caver_parquet")]
impl SinkConfig for CaverParquetConfig {
    async fn build(&self, _cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        if self.batch_size == 0 {
            return Err("`batch_size` must be at least 1".into());
        }
        if let Some(sensor_id) = &self.sensor_id
            && !is_key_safe(sensor_id)
        {
            return Err(format!(
                "`sensor_id` must match [A-Za-z0-9._-]+ (it is embedded in the object key), got {sensor_id:?}"
            )
            .into());
        }
        if let Some(source) = &self.source {
            // Embedded raw in the staging object key, same hazard as sensor_id.
            if source.is_empty() || !is_key_safe(source) {
                return Err(format!(
                    "`source` must match [A-Za-z0-9._-]+ (it is embedded in the object key), got {source:?}"
                )
                .into());
            }
        }
        // PARQUET-CONTRACT filename regex requires the writer prefix to start
        // with a letter; the compactor skips files that don't match.
        if !self
            .writer_name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic())
            || !is_key_safe(&self.writer_name)
        {
            return Err(format!(
                "`writer_name` must match [A-Za-z][A-Za-z0-9._-]* (the PARQUET-CONTRACT filename shape), got {:?}",
                self.writer_name
            )
            .into());
        }
        let staging_prefix = self.staging_prefix.trim_matches('/');
        if staging_prefix.is_empty() || !staging_prefix.split('/').all(is_key_safe) {
            return Err(format!(
                "`staging_prefix` must be slash-separated [A-Za-z0-9._-]+ segments, got {:?}",
                self.staging_prefix
            )
            .into());
        }
        if self.acknowledgements.enabled() && self.dlq_path.is_none() {
            warn!(
                message = "`acknowledgements` are enabled but events are acked when accepted \
                 into a batch, before the object PUT; without a `dlq_path` a failed PUT \
                 drops the batch. Set `dlq_path` to make PUT failures recoverable."
            );
        }

        let s3_cfg = caver_sink_parquet::S3Config {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            access_key_env: self.access_key_env.clone(),
            secret_key_env: self.secret_key_env.clone(),
            session_token_env: self.session_token_env.clone(),
            max_retries: self.max_retries,
            retry_base_ms: self.retry_base_ms,
            timeout_ms: self.timeout_ms,
        };
        // Fails fast on missing credential env vars or a bad endpoint, so a
        // misconfigured sink refuses to boot instead of dropping data later.
        let put_fn = caver_sink_parquet::s3_put_fn(s3_cfg).map_err(|e| e.to_string())?;

        let layout = match self.layout {
            LayoutConfig::CaverStaging => caver_sink_parquet::Layout::CaverStaging,
            LayoutConfig::Native => caver_sink_parquet::Layout::Native,
        };
        let mut sink_cfg = caver_sink_parquet::Config {
            bucket: self.bucket.clone(),
            class_uid_field: self.class_uid_field.clone(),
            batch_size: self.batch_size,
            dlq_path: self.dlq_path.clone(),
            layout,
            source: self.source.clone(),
            writer_name: self.writer_name.clone(),
            staging_prefix: staging_prefix.to_owned(),
            ..Default::default()
        };
        if let Some(sensor_id) = &self.sensor_id {
            sink_cfg.sensor_id = sensor_id.clone();
        }
        let parquet = Arc::new(caver_sink_parquet::ParquetSink::new(sink_cfg, Some(put_fn)));

        let sink = CaverParquetSink::new(
            parquet,
            self.dlq_path.is_some(),
            self.layout == LayoutConfig::CaverStaging,
        );
        let healthcheck = future::ok(()).boxed();

        Ok((VectorSink::Stream(Box::new(sink)), healthcheck))
    }

    fn input(&self) -> Input {
        Input::log()
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

impl GenerateConfig for CaverParquetConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self::default()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::CaverParquetConfig;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<CaverParquetConfig>();
    }
}
