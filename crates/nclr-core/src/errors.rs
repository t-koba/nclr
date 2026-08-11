//! Error types and exit-code mapping per the specification's exit code table.

use std::fmt;

/// Exit codes mandated by the project's exit code table.
pub mod exit {
    pub const OK: i32 = 0;
    pub const DEGRADED: i32 = 1;
    pub const UNSUPPORTED: i32 = 2;
    pub const USAGE: i32 = 64;
    pub const BACKEND_UNAVAILABLE: i32 = 69;
    pub const DEVICE_IO: i32 = 74;
    pub const INTERRUPTED: i32 = 75;
    pub const PERMISSION: i32 = 77;
    pub const INVALID: i32 = 78;
}

#[derive(Debug)]
pub enum Error {
    /// Command line usage error (64).
    Usage(String),
    /// No safe processing path exists / requested reach cannot be planned (2).
    Unsupported(String),
    /// Required backend or external capability unavailable (69).
    Backend(String),
    /// Device I/O or protocol error (74).
    Io(String, Option<std::io::Error>),
    /// Temporary failure or resumable interruption (75).
    Interrupted(String),
    /// Permission or safety interlock rejection (77).
    Permission(String),
    /// Invalid profile, plan, signature or schema (78).
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(m) => write!(f, "usage: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Backend(m) => write!(f, "backend unavailable: {m}"),
            Error::Io(m, src) => {
                if let Some(e) = src {
                    write!(f, "device I/O: {m}: {e}")
                } else {
                    write!(f, "device I/O: {m}")
                }
            }
            Error::Interrupted(m) => write!(f, "interrupted: {m}"),
            Error::Permission(m) => write!(f, "permission denied: {m}"),
            Error::Invalid(m) => write!(f, "invalid: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Construct an I/O error with context.
    pub fn io(ctx: impl Into<String>, src: Option<std::io::Error>) -> Error {
        Error::Io(ctx.into(), src)
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => exit::USAGE,
            Error::Unsupported(_) => exit::UNSUPPORTED,
            Error::Backend(_) => exit::BACKEND_UNAVAILABLE,
            Error::Io(_, _) => exit::DEVICE_IO,
            Error::Interrupted(_) => exit::INTERRUPTED,
            Error::Permission(_) => exit::PERMISSION,
            Error::Invalid(_) => exit::INVALID,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::io("I/O failure", Some(e))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_spec() {
        assert_eq!(exit::OK, 0);
        assert_eq!(exit::DEGRADED, 1);
        assert_eq!(exit::UNSUPPORTED, 2);
        assert_eq!(exit::USAGE, 64);
        assert_eq!(exit::BACKEND_UNAVAILABLE, 69);
        assert_eq!(exit::DEVICE_IO, 74);
        assert_eq!(exit::INTERRUPTED, 75);
        assert_eq!(exit::PERMISSION, 77);
        assert_eq!(exit::INVALID, 78);
    }

    #[test]
    fn exit_code_mapping() {
        assert_eq!(Error::Usage("x".into()).exit_code(), 64);
        assert_eq!(Error::Unsupported("x".into()).exit_code(), 2);
        assert_eq!(Error::Backend("x".into()).exit_code(), 69);
        assert_eq!(Error::io("x", None).exit_code(), 74);
        assert_eq!(Error::Interrupted("x".into()).exit_code(), 75);
        assert_eq!(Error::Permission("x".into()).exit_code(), 77);
        assert_eq!(Error::Invalid("x".into()).exit_code(), 78);
    }
}
