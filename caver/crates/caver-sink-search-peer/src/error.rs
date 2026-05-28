use thiserror::Error;

#[derive(Debug, Error)]
pub enum PushError {
    #[error("token env var '{0}' not set")]
    MissingToken(String),

    #[error("HTTP {status}: {body}")]
    HttpError { status: u16, body: String },

    #[error("network error: {0}")]
    Network(String),

    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}

impl From<ureq::Error> for PushError {
    fn from(e: ureq::Error) -> Self {
        match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                PushError::HttpError { status: code, body }
            }
            ureq::Error::Transport(t) => PushError::Network(t.to_string()),
        }
    }
}
