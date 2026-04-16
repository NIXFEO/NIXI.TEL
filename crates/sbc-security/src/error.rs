use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Access denied")]
    AccessDenied,

    #[error("Trunk access denied")]
    TrunkAccessDenied,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("{0}")]
    Other(String),
}
