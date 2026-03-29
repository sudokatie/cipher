//! TLS Alert Protocol (RFC 8446 Section 6)

use crate::error::{AlertDescription, TlsError};

/// Alert level per RFC 8446
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    /// Warning alerts (non-fatal)
    Warning = 1,
    /// Fatal alerts (connection must terminate)
    Fatal = 2,
}

impl AlertLevel {
    /// Parse from byte
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(AlertLevel::Warning),
            2 => Some(AlertLevel::Fatal),
            _ => None,
        }
    }

    /// Convert to byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertLevel::Warning => write!(f, "warning"),
            AlertLevel::Fatal => write!(f, "fatal"),
        }
    }
}

/// TLS Alert message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    /// Alert level
    pub level: AlertLevel,
    /// Alert description
    pub description: AlertDescription,
}

impl Alert {
    /// Create a new alert
    pub fn new(level: AlertLevel, description: AlertDescription) -> Self {
        Self { level, description }
    }

    /// Create a fatal alert
    pub fn fatal(description: AlertDescription) -> Self {
        Self::new(AlertLevel::Fatal, description)
    }

    /// Create a warning alert
    pub fn warning(description: AlertDescription) -> Self {
        Self::new(AlertLevel::Warning, description)
    }

    /// Create a close_notify alert
    pub fn close_notify() -> Self {
        Self::warning(AlertDescription::CloseNotify)
    }

    /// Create an unexpected_message alert
    pub fn unexpected_message() -> Self {
        Self::fatal(AlertDescription::UnexpectedMessage)
    }

    /// Create a bad_record_mac alert
    pub fn bad_record_mac() -> Self {
        Self::fatal(AlertDescription::BadRecordMac)
    }

    /// Create a handshake_failure alert
    pub fn handshake_failure() -> Self {
        Self::fatal(AlertDescription::HandshakeFailure)
    }

    /// Create a bad_certificate alert
    pub fn bad_certificate() -> Self {
        Self::fatal(AlertDescription::BadCertificate)
    }

    /// Create a decode_error alert
    pub fn decode_error() -> Self {
        Self::fatal(AlertDescription::DecodeError)
    }

    /// Create an illegal_parameter alert
    pub fn illegal_parameter() -> Self {
        Self::fatal(AlertDescription::IllegalParameter)
    }

    /// Check if this is a fatal alert
    pub fn is_fatal(&self) -> bool {
        self.level == AlertLevel::Fatal
    }

    /// Check if this is a close_notify
    pub fn is_close_notify(&self) -> bool {
        self.description == AlertDescription::CloseNotify
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::Protocol("alert too short".into()));
        }

        let level = AlertLevel::from_u8(data[0])
            .ok_or_else(|| TlsError::Protocol(format!("invalid alert level: {}", data[0])))?;
        let description = AlertDescription::from_u8(data[1]);

        Ok(Self { level, description })
    }

    /// Encode to bytes
    pub fn encode(&self) -> [u8; 2] {
        [self.level.to_u8(), self.description.to_u8()]
    }

    /// Convert to TlsError
    pub fn to_error(&self) -> TlsError {
        TlsError::Alert(self.description)
    }
}

impl std::fmt::Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} alert: {}", self.level, self.description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_creation() {
        let alert = Alert::fatal(AlertDescription::HandshakeFailure);
        assert!(alert.is_fatal());
        assert!(!alert.is_close_notify());

        let close = Alert::close_notify();
        assert!(!close.is_fatal());
        assert!(close.is_close_notify());
    }

    #[test]
    fn test_alert_encode_parse() {
        let alert = Alert::fatal(AlertDescription::BadCertificate);
        let encoded = alert.encode();
        assert_eq!(encoded, [2, 42]);

        let parsed = Alert::parse(&encoded).unwrap();
        assert_eq!(parsed.level, AlertLevel::Fatal);
        assert_eq!(parsed.description, AlertDescription::BadCertificate);
    }

    #[test]
    fn test_alert_level() {
        assert_eq!(AlertLevel::from_u8(1), Some(AlertLevel::Warning));
        assert_eq!(AlertLevel::from_u8(2), Some(AlertLevel::Fatal));
        assert_eq!(AlertLevel::from_u8(3), None);
    }

    #[test]
    fn test_alert_display() {
        let alert = Alert::fatal(AlertDescription::DecodeError);
        let s = format!("{}", alert);
        assert!(s.contains("fatal"));
        assert!(s.contains("decode_error"));
    }
}
