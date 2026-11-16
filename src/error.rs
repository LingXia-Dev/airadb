use std::fmt;

/// What went wrong, in a form callers can branch on.
///
/// The set grows over time; match with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The device did not answer (refused, no route, host down).
    Unreachable,
    /// The device did not answer in time.
    Timeout,
    /// No usable local network interface to discover on.
    NoNetwork,
    /// The device does not (yet) trust this client's key. Call
    /// [`Device::authorize`](crate::Device::authorize) and confirm on the device.
    Unauthorized,
    /// The connection dropped while in use.
    Disconnected,
    /// The device ran the command and reported failure (`pm` error, `sync`
    /// refusal, unknown service, …).
    Rejected,
    /// `pm install` reported failure.
    InstallFailed,
    /// The package (or its icon) is not on the device.
    NotFound,
    /// A caller-supplied argument is malformed.
    InvalidArg,
    /// Something on the wire did not follow the ADB protocol.
    Protocol,
    /// A key could not be generated, read, parsed or saved.
    Key,
    /// Local I/O failed.
    Io,
    /// The operation was cancelled.
    Cancelled,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::NoNetwork => "no network",
            Self::Unauthorized => "unauthorized",
            Self::Disconnected => "disconnected",
            Self::Rejected => "rejected",
            Self::InstallFailed => "install failed",
            Self::NotFound => "not found",
            Self::InvalidArg => "invalid argument",
            Self::Protocol => "protocol",
            Self::Key => "key",
            Self::Io => "i/o",
            Self::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error type of every airadb operation.
pub struct Error {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

/// Result type alias for ADB operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into(), source: None }
    }

    pub(crate) fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether retrying later can succeed (network trouble, dropped link).
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, ErrorKind::Unreachable | ErrorKind::Timeout | ErrorKind::Disconnected)
    }

    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, message)
    }

    pub(crate) fn rejected(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Rejected, message)
    }

    pub(crate) fn key(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Key, message)
    }

    pub(crate) fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, message)
    }

    pub(crate) fn disconnected() -> Self {
        Self::new(ErrorKind::Disconnected, "connection closed")
    }

    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unauthorized, message)
    }

    pub(crate) fn invalid_arg(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidArg, message)
    }

    /// Classify a failure to open a TCP connection.
    pub(crate) fn connect(addr: impl fmt::Display, err: std::io::Error) -> Self {
        let kind = match err.kind() {
            std::io::ErrorKind::TimedOut => ErrorKind::Timeout,
            _ => ErrorKind::Unreachable,
        };
        Self::new(kind, format!("cannot connect to {addr}: {err}")).with_source(err)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Error");
        s.field("kind", &self.kind).field("message", &self.message);
        if let Some(source) = &self.source {
            s.field("source", source);
        }
        s.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.kind)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        let kind = match err.kind() {
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => ErrorKind::Disconnected,
            std::io::ErrorKind::TimedOut => ErrorKind::Timeout,
            _ => ErrorKind::Io,
        };
        Self::new(kind, err.to_string()).with_source(err)
    }
}
