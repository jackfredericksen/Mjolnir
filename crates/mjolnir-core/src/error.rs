use thiserror::Error;

#[derive(Debug, Error)]
pub enum MjolnirError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Scan error: {0}")]
    Scan(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Signature database error: {0}")]
    SignatureDb(String),

    #[error("YARA error: {0}")]
    Yara(String),

    #[error("Quarantine error: {0}")]
    Quarantine(String),

    #[error("Update error: {0}")]
    Update(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("ML engine error: {0}")]
    MachineLearning(String),

    #[error("Unsupported file format")]
    UnsupportedFormat,
}

pub type Result<T> = std::result::Result<T, MjolnirError>;
