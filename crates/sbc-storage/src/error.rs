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

    /// A row violated a schema constraint (foreign key, uniqueness,
    /// CHECK, NOT NULL): the caller's data is wrong, not the database.
    /// `table`/`key` name the offending row when the caller knows it.
    #[error("{}{detail}", constraint_prefix(.table, .key))]
    Constraint {
        table: String,
        key: String,
        detail: String,
    },

    // Phase 5: Database errors
    // #[error("Serialization error: {0}")]
    // Serialization(#[from] serde_json::Error),
    //
    // #[error("sqlx error: {0}")]
    // Sqlx(#[from] sqlx::Error),
    #[error("{0}")]
    Other(String),
}

fn constraint_prefix(table: &str, key: &str) -> String {
    if table.is_empty() {
        String::new()
    } else {
        format!("{} '{}': ", table, key)
    }
}

impl Error {
    /// Attach the offending row to a constraint error (other errors pass
    /// through unchanged).
    pub fn at(self, table: &str, key: &str) -> Self {
        match self {
            Error::Constraint { detail, .. } => Error::Constraint {
                table: table.to_string(),
                key: key.to_string(),
                detail,
            },
            other => other,
        }
    }

    pub fn is_constraint(&self) -> bool {
        matches!(self, Error::Constraint { .. })
    }
}
