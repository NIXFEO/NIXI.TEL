use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("API error: {0}")]
    Api(String),

    #[error("Metrics error: {0}")]
    Metrics(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("{0}")]
    Other(String),
}
