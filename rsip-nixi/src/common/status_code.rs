use crate::Error;
#[doc(hidden)]
pub use tokenizer::Tokenizer;

macro_rules! create_status_codes {
    ($($name:ident => $code:expr => $phrase:expr),*) => {

        /// The SIP [Response](super::super::Response) status code (or response code as SIP main
        /// RFC refers to them). This is not a `Copy` type because in case of an unknown (= not
        /// defined in any SIP RFC) status code, the reason is also provided inside the `Other`
        /// tuple variant.
        #[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Clone)]
        pub enum StatusCode {
            $(
                $name,
            )*
            Other(u16, String),
        }

        impl StatusCode {
            pub fn code(&self) -> u16 {
                match self {
                    $(
                        Self::$name => $code,
                    )*
                    Self::Other(code, _) => *code,
                }
            }

            /// The canonical reason phrase (RFC 3261 §21 and the RFCs that
            /// register the other codes), e.g. `487` → "Request Terminated".
            pub fn reason_phrase(&self) -> &str {
                match self {
                    $(
                        Self::$name => $phrase,
                    )*
                    Self::Other(_, reason) => reason.as_str(),
                }
            }
        }

        impl From<u16> for StatusCode {
            fn from(code: u16) -> Self {
                match code {
                    $(
                        $code => Self::$name,
                    )*
                    code => Self::Other(code, "Other".into()),
                }

            }
        }

        impl std::fmt::Display for StatusCode {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$name => write!(f, "{} {}", stringify!($code), $phrase),
                    )*
                    Self::Other(code, reason) => write!(f, "{} {}", code, reason),
                }
            }
        }

        //Here we decide to completely ignore the reason if the code can be mapped to a well known status
        impl<'a> std::convert::TryFrom<tokenizer::Tokenizer<'a, &'a str, char>> for StatusCode {
            type Error = Error;

            fn try_from(tokenizer: tokenizer::Tokenizer<'a, &'a str, char>) -> Result<Self, Self::Error> {
                match (tokenizer.code.parse::<u16>()?, tokenizer.reason) {
                    $(
                        ($code, _) => Ok(StatusCode::$name),
                    )*
                    (code, reason) => Ok(StatusCode::Other(code, reason.into())),
                }
            }
        }
    }
}

create_status_codes!(Trying => 100 => "Trying",
    Ringing => 180 => "Ringing",
    CallIsBeingForwarded => 181 => "Call Is Being Forwarded",
    Queued => 182 => "Queued",
    SessionProgress => 183 => "Session Progress",
    EarlyDialogTerminated => 199 => "Early Dialog Terminated",
    OK => 200 => "OK",
    Accepted => 201 => "Accepted",
    NoNotification => 204 => "No Notification",
    MultipleChoices => 300 => "Multiple Choices",
    MovedPermanently => 301 => "Moved Permanently",
    MovedTemporarily => 302 => "Moved Temporarily",
    UseProxy => 305 => "Use Proxy",
    AlternativeService => 380 => "Alternative Service",
    BadRequest => 400 => "Bad Request",
    Unauthorized => 401 => "Unauthorized",
    PaymentRequired => 402 => "Payment Required",
    Forbidden => 403 => "Forbidden",
    NotFound => 404 => "Not Found",
    MethodNotAllowed => 405 => "Method Not Allowed",
    NotAcceptable => 406 => "Not Acceptable",
    ProxyAuthenticationRequired => 407 => "Proxy Authentication Required",
    RequestTimeout => 408 => "Request Timeout",
    Conflict => 409 => "Conflict",
    Gone => 410 => "Gone",
    LengthRequired => 411 => "Length Required",
    ConditionalRequestFailed => 412 => "Conditional Request Failed",
    RequestEntityTooLarge => 413 => "Request Entity Too Large",
    RequestUriTooLong => 414 => "Request-URI Too Long",
    UnsupportedMediaType => 415 => "Unsupported Media Type",
    UnsupportedUriScheme => 416 => "Unsupported URI Scheme",
    UnknownResourcePriority => 417 => "Unknown Resource-Priority",
    BadExtension => 420 => "Bad Extension",
    ExtensionRequired => 421 => "Extension Required",
    SessionIntervalTooSmall => 422 => "Session Interval Too Small",
    IntervalTooBrief => 423 => "Interval Too Brief",
    BadLocationInformation => 424 => "Bad Location Information",
    UseIdentityHeader => 428 => "Use Identity Header",
    ProvideReferrerIdentity => 429 => "Provide Referrer Identity",
    AnonymityDisallowed => 433 => "Anonymity Disallowed",
    BadIdentityInfo => 436 => "Bad Identity-Info",
    UnsupportedCertificate => 437 => "Unsupported Certificate",
    InvalidIdentityHeader => 438 => "Invalid Identity Header",
    FirstHopLacksOutboundSupport => 439 => "First Hop Lacks Outbound Support",
    MaxBreadthExceeded => 440 => "Max-Breadth Exceeded",
    BadInfoPackage => 469 => "Bad Info Package",
    ConsentNeeded => 470 => "Consent Needed",
    TemporarilyUnavailable => 480 => "Temporarily Unavailable",
    CallTransactionDoesNotExist => 481 => "Call/Transaction Does Not Exist",
    LoopDetected => 482 => "Loop Detected",
    TooManyHops => 483 => "Too Many Hops",
    AddressIncomplete => 484 => "Address Incomplete",
    Ambiguous => 485 => "Ambiguous",
    BusyHere => 486 => "Busy Here",
    RequestTerminated => 487 => "Request Terminated",
    NotAcceptableHere => 488 => "Not Acceptable Here",
    BadEvent => 489 => "Bad Event",
    RequestPending => 491 => "Request Pending",
    Undecipherable => 493 => "Undecipherable",
    SecurityAgreementRequired => 494 => "Security Agreement Required",
    ServerInternalError => 500 => "Server Internal Error",
    NotImplemented => 501 => "Not Implemented",
    BadGateway => 502 => "Bad Gateway",
    ServiceUnavailable => 503 => "Service Unavailable",
    ServerTimeOut => 504 => "Server Time-out",
    VersionNotSupported => 505 => "Version Not Supported",
    MessageTooLarge => 513 => "Message Too Large",
    PreconditionFailure => 580 => "Precondition Failure",
    BusyEverywhere => 600 => "Busy Everywhere",
    Decline => 603 => "Decline",
    DoesNotExistAnywhere => 604 => "Does Not Exist Anywhere",
    NotAcceptableGlobal => 606 => "Not Acceptable",
    Unwanted => 607 => "Unwanted"
);

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Clone, Copy)]
pub enum StatusCodeKind {
    Provisional,
    Successful,
    Redirection,
    RequestFailure,
    ServerFailure,
    GlobalFailure,
    Other,
}

impl StatusCode {
    pub fn kind(&self) -> StatusCodeKind {
        let code = self.code();
        match code {
            code if (100..200).contains(&code) => StatusCodeKind::Provisional,
            code if (200..300).contains(&code) => StatusCodeKind::Successful,
            code if (300..400).contains(&code) => StatusCodeKind::Redirection,
            code if (400..500).contains(&code) => StatusCodeKind::RequestFailure,
            code if (500..600).contains(&code) => StatusCodeKind::ServerFailure,
            code if (600..700).contains(&code) => StatusCodeKind::GlobalFailure,
            _ => StatusCodeKind::Other,
        }
    }
}

impl From<StatusCode> for u16 {
    fn from(from: StatusCode) -> u16 {
        from.code()
    }
}

impl Default for StatusCode {
    fn default() -> Self {
        Self::OK
    }
}

impl<'a> std::convert::TryFrom<tokenizer::Tokenizer<'a, &'a [u8], u8>> for StatusCode {
    type Error = Error;

    fn try_from(tokenizer: tokenizer::Tokenizer<'a, &'a [u8], u8>) -> Result<Self, Self::Error> {
        use std::str::from_utf8;

        Self::try_from(Tokenizer::from((
            from_utf8(tokenizer.code)?,
            from_utf8(tokenizer.reason)?,
        )))
    }
}

#[doc(hidden)]
mod tokenizer {
    use crate::{AbstractInput, AbstractInputItem, GResult, GenericNomError, TokenizerError};
    use std::marker::PhantomData;

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct Tokenizer<'a, T, I>
    where
        T: AbstractInput<'a, I>,
        I: AbstractInputItem<I>,
    {
        pub code: T,
        pub reason: T,
        phantom1: PhantomData<&'a T>,
        phantom2: PhantomData<I>,
    }

    impl<'a, T, I> From<(T, T)> for Tokenizer<'a, T, I>
    where
        T: AbstractInput<'a, I>,
        I: AbstractInputItem<I>,
    {
        fn from(from: (T, T)) -> Self {
            Self {
                code: from.0,
                reason: from.1,
                phantom1: PhantomData,
                phantom2: PhantomData,
            }
        }
    }

    impl<'a, T, I> Tokenizer<'a, T, I>
    where
        T: AbstractInput<'a, I>,
        I: AbstractInputItem<I>,
    {
        pub fn tokenize(part: T) -> GResult<T, Self> {
            use nom::{
                branch::alt,
                bytes::complete::{tag, take, take_until},
                combinator::rest,
                sequence::tuple,
            };

            let (rem, (code, _, reason)) =
                tuple((take(3usize), tag(" "), alt((take_until("\r\n"), rest))))(part).map_err(
                    |_: GenericNomError<'a, T>| TokenizerError::from(("status", part)).into(),
                )?;

            Ok((rem, (code, reason).into()))
        }
    }
}
