use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("RTP error: {0}")]
    Rtp(String),

    #[error("SDP error: {0}")]
    Sdp(String),

    #[error("Transcoding error: {0}")]
    Transcoding(String),

    #[error("WebRTC error: {0}")]
    WebRtc(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
