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

const fn default_retry_base_ms() -> u64 {
    200
}

const fn default_timeout_ms() -> u64 {
    30_000
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
    /// Defaults to the collector host name.
    #[configurable(metadata(docs::examples = "edge-01"))]
    pub sensor_id: Option<String>,

    /// Event field carrying the OCSF `class_uid` used for partitioning.
    #[serde(default = "default_class_uid_field")]
    pub class_uid_field: String,

    /// Number of events buffered before a Parquet object is written.
    #[serde(default = "default_batch_size")]
    #[configurable(metadata(docs::examples = 500))]
    pub batch_size: usize,

    /// Local directory receiving failed batches as ndjson (dead-letter queue).
    ///
    /// If unset, failed batches are dropped (counted in sink stats).
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

        let mut sink_cfg = caver_sink_parquet::Config {
            bucket: self.bucket.clone(),
            class_uid_field: self.class_uid_field.clone(),
            batch_size: self.batch_size,
            dlq_path: self.dlq_path.clone(),
            ..Default::default()
        };
        if let Some(sensor_id) = &self.sensor_id {
            sink_cfg.sensor_id = sensor_id.clone();
        }
        let parquet = Arc::new(caver_sink_parquet::ParquetSink::new(sink_cfg, Some(put_fn)));

        let sink = CaverParquetSink::new(parquet);
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
