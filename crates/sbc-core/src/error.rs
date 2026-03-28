use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Dialog error: {0}")]
    Dialog(String),

    #[error("Media error: {0}")]
    Media(String),

    #[error("Routing error: {0}")]
    Routing(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("rsip error: {0}")]
    Rsip(#[from] rsip::Error),

    #[error("Invalid branch parameter")]
    InvalidBranch,

    #[error("Missing required header: {0}")]
    MissingHeader(String),

    #[error("Invalid SIP message")]
    InvalidMessage,

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("{0}")]
    Other(String),
}

impl From<rcgen::Error> for Error {
    fn from(err: rcgen::Error) -> Self {
        Error::CertificateError(err.to_string())
    }
}
