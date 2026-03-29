//! TLS error types.

use thiserror::Error;

/// Main error type for TLS operations.
#[derive(Debug, Error)]
pub enum TlsError {
    /// I/O error during read/write.
    #[error("I/O error: {0}")]
    Io(String),

    /// Handshake failed.
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// Certificate validation failed.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Received a TLS alert.
    #[error("received alert: {0}")]
    Alert(AlertDescription),

    /// Protocol violation.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Unexpected message type.
    #[error("unexpected message: expected {expected}, got {actual}")]
    UnexpectedMessage { expected: String, actual: String },

    /// Buffer too small.
    #[error("buffer too small: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },

    /// Invalid state for operation.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),
}

/// TLS alert descriptions per RFC 8446.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    /// Notifies the recipient that the sender will not send any more messages.
    CloseNotify = 0,

    /// An inappropriate message was received.
    UnexpectedMessage = 10,

    /// Record MAC verification failed.
    BadRecordMac = 20,

    /// Record exceeded maximum length.
    RecordOverflow = 22,

    /// Handshake failed for unspecified reason.
    HandshakeFailure = 40,

    /// Certificate was invalid.
    BadCertificate = 42,

    /// Certificate was unsupported.
    UnsupportedCertificate = 43,

    /// Certificate was revoked.
    CertificateRevoked = 44,

    /// Certificate has expired.
    CertificateExpired = 45,

    /// Certificate is not yet valid.
    CertificateUnknown = 46,

    /// A parameter was out of range or inconsistent.
    IllegalParameter = 47,

    /// CA certificate could not be located.
    UnknownCa = 48,

    /// Access was denied.
    AccessDenied = 49,

    /// Message could not be decoded.
    DecodeError = 50,

    /// Decryption failed.
    DecryptError = 51,

    /// Protocol version not supported.
    ProtocolVersion = 70,

    /// Server requires more security than client can provide.
    InsufficientSecurity = 71,

    /// Internal error.
    InternalError = 80,

    /// Inappropriate fallback detected.
    InappropriateFallback = 86,

    /// User canceled handshake.
    UserCanceled = 90,

    /// No renegotiation supported.
    NoRenegotiation = 100,

    /// Extension required but not provided.
    MissingExtension = 109,

    /// Extension not supported.
    UnsupportedExtension = 110,

    /// Certificate required but not provided.
    CertificateRequired = 116,

    /// No application protocol supported.
    NoApplicationProtocol = 120,

    /// Unknown alert.
    Unknown(u8),
}

impl AlertDescription {
    /// Create from a raw byte value.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            22 => AlertDescription::RecordOverflow,
            40 => AlertDescription::HandshakeFailure,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            86 => AlertDescription::InappropriateFallback,
            90 => AlertDescription::UserCanceled,
            100 => AlertDescription::NoRenegotiation,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            116 => AlertDescription::CertificateRequired,
            120 => AlertDescription::NoApplicationProtocol,
            v => AlertDescription::Unknown(v),
        }
    }

    /// Convert to raw byte value.
    pub fn to_u8(self) -> u8 {
        match self {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMac => 20,
            AlertDescription::RecordOverflow => 22,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateRevoked => 44,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::UnknownCa => 48,
            AlertDescription::AccessDenied => 49,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InsufficientSecurity => 71,
            AlertDescription::InternalError => 80,
            AlertDescription::InappropriateFallback => 86,
            AlertDescription::UserCanceled => 90,
            AlertDescription::NoRenegotiation => 100,
            AlertDescription::MissingExtension => 109,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::CertificateRequired => 116,
            AlertDescription::NoApplicationProtocol => 120,
            AlertDescription::Unknown(v) => v,
        }
    }
}

impl std::fmt::Display for AlertDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertDescription::CloseNotify => write!(f, "close_notify"),
            AlertDescription::UnexpectedMessage => write!(f, "unexpected_message"),
            AlertDescription::BadRecordMac => write!(f, "bad_record_mac"),
            AlertDescription::RecordOverflow => write!(f, "record_overflow"),
            AlertDescription::HandshakeFailure => write!(f, "handshake_failure"),
            AlertDescription::BadCertificate => write!(f, "bad_certificate"),
            AlertDescription::UnsupportedCertificate => write!(f, "unsupported_certificate"),
            AlertDescription::CertificateRevoked => write!(f, "certificate_revoked"),
            AlertDescription::CertificateExpired => write!(f, "certificate_expired"),
            AlertDescription::CertificateUnknown => write!(f, "certificate_unknown"),
            AlertDescription::IllegalParameter => write!(f, "illegal_parameter"),
            AlertDescription::UnknownCa => write!(f, "unknown_ca"),
            AlertDescription::AccessDenied => write!(f, "access_denied"),
            AlertDescription::DecodeError => write!(f, "decode_error"),
            AlertDescription::DecryptError => write!(f, "decrypt_error"),
            AlertDescription::ProtocolVersion => write!(f, "protocol_version"),
            AlertDescription::InsufficientSecurity => write!(f, "insufficient_security"),
            AlertDescription::InternalError => write!(f, "internal_error"),
            AlertDescription::InappropriateFallback => write!(f, "inappropriate_fallback"),
            AlertDescription::UserCanceled => write!(f, "user_canceled"),
            AlertDescription::NoRenegotiation => write!(f, "no_renegotiation"),
            AlertDescription::MissingExtension => write!(f, "missing_extension"),
            AlertDescription::UnsupportedExtension => write!(f, "unsupported_extension"),
            AlertDescription::CertificateRequired => write!(f, "certificate_required"),
            AlertDescription::NoApplicationProtocol => write!(f, "no_application_protocol"),
            AlertDescription::Unknown(v) => write!(f, "unknown({})", v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = TlsError::Handshake("test error".into());
        assert!(err.to_string().contains("handshake failed"));

        let err = TlsError::Certificate("invalid cert".into());
        assert!(err.to_string().contains("certificate error"));

        let err = TlsError::Crypto("bad key".into());
        assert!(err.to_string().contains("crypto error"));
    }

    #[test]
    fn test_alert_description() {
        let alert = AlertDescription::HandshakeFailure;
        assert_eq!(alert.to_u8(), 40);
        assert_eq!(
            AlertDescription::from_u8(40),
            AlertDescription::HandshakeFailure
        );
        assert_eq!(format!("{}", alert), "handshake_failure");

        let unknown = AlertDescription::from_u8(255);
        assert!(matches!(unknown, AlertDescription::Unknown(255)));
    }
}
