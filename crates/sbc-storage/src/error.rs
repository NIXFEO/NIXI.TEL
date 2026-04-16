use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Redis error: {0}")]
    Redis(String),

    #[error("Session not found")]
    SessionNotFound,

    #[error("Trunk not found")]
    TrunkNotFound,

    // Phase 5: Database errors
    // #[error("Serialization error: {0}")]
    // Serialization(#[from] serde_json::Error),
    //
    // #[error("sqlx error: {0}")]
    // Sqlx(#[from] sqlx::Error),

    #[error("{0}")]
    Other(String),
}
