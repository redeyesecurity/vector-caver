//! Config-reload monitoring for caver-collector.
//!
//! Vector supports hot-reload via SIGHUP.  Before swapping topology,
//! operators should validate the new config.  This module provides:
//!
//! - `validate_config(path)` — shells out to `vector validate <path>` and
//!   returns a `ReloadEvent` indicating pass or fail.
//! - `ReloadEvent` — structured outcome suitable for logging and metric
//!   emission.  The caller is responsible for incrementing
//!   `caver_config_reload_failed_total` and sending the Telegram alert on
//!   `ReloadEvent::Failed`.
//!
//! # Design note
//!
//! We deliberately keep I/O out of this crate (no HTTP calls, no signal
//! handlers).  The caller wires reload events to the alerting channel of their
//! choice so the library stays testable without network access.

use std::path::Path;
use std::process::Command;

use thiserror::Error;

/// Outcome of a config-reload validation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadEvent {
    /// Config validated successfully; safe to apply.
    Passed { config_path: String },
    /// Validation failed; keep the running topology.
    Failed { config_path: String, reason: String },
}

impl ReloadEvent {
    /// Returns `true` when the reload should be applied.
    pub fn should_apply(&self) -> bool {
        matches!(self, ReloadEvent::Passed { .. })
    }

    /// Human-readable summary line for logging.
    pub fn summary(&self) -> String {
        match self {
            ReloadEvent::Passed { config_path } => {
                format!("config reload PASSED: {config_path}")
            }
            ReloadEvent::Failed {
                config_path,
                reason,
            } => {
                format!("config reload FAILED: {config_path} — {reason}")
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ValidateError {
    #[error("vector binary not found or not executable: {0}")]
    VectorNotFound(String),
    #[error("I/O error running vector validate: {0}")]
    Io(#[from] std::io::Error),
}

/// Validate a Vector config file by running `vector validate <path>`.
///
/// Returns a `ReloadEvent` indicating whether the config is safe to apply.
/// Returns `Err` only when the `vector` binary itself cannot be executed.
///
/// # Arguments
///
/// * `config_path` — path to the Vector config file (YAML or TOML).
/// * `vector_bin` — path to the `vector` binary; pass `"vector"` to use `$PATH`.
pub fn validate_config(config_path: &str, vector_bin: &str) -> Result<ReloadEvent, ValidateError> {
    if !Path::new(config_path).exists() {
        return Ok(ReloadEvent::Failed {
            config_path: config_path.to_string(),
            reason: "config file not found".to_string(),
        });
    }

    let output = Command::new(vector_bin)
        .args(["validate", config_path])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ValidateError::VectorNotFound(vector_bin.to_string())
            } else {
                ValidateError::Io(e)
            }
        })?;

    if output.status.success() {
        Ok(ReloadEvent::Passed {
            config_path: config_path.to_string(),
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let reason = if stderr.is_empty() { stdout } else { stderr };
        Ok(ReloadEvent::Failed {
            config_path: config_path.to_string(),
            reason: reason.trim().to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_event_passed_should_apply() {
        let ev = ReloadEvent::Passed {
            config_path: "/etc/vector.yaml".into(),
        };
        assert!(ev.should_apply());
        assert!(ev.summary().contains("PASSED"));
    }

    #[test]
    fn reload_event_failed_should_not_apply() {
        let ev = ReloadEvent::Failed {
            config_path: "/etc/vector.yaml".into(),
            reason: "unknown field 'caver_bad'".into(),
        };
        assert!(!ev.should_apply());
        assert!(ev.summary().contains("FAILED"));
        assert!(ev.summary().contains("unknown field"));
    }

    #[test]
    fn missing_config_file_returns_failed_event() {
        let result = validate_config("/this_file_definitely_does_not_exist_xyz.yaml", "vector");
        match result {
            Ok(ReloadEvent::Failed { reason, .. }) => {
                assert!(reason.contains("not found"));
            }
            Ok(ReloadEvent::Passed { .. }) => panic!("missing file should not pass"),
            Err(_) => {
                // Acceptable: 'vector' binary not installed in this environment
            }
        }
    }

    #[test]
    fn summary_contains_path() {
        let path = "/etc/caver/vector.yaml";
        let ev = ReloadEvent::Passed {
            config_path: path.into(),
        };
        assert!(ev.summary().contains(path));
    }
}
