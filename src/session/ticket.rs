//! Session ticket encryption and handling.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::{Rng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum ticket lifetime (7 days in seconds).
pub const MAX_TICKET_LIFETIME: u32 = 7 * 24 * 60 * 60;

/// Default ticket lifetime (24 hours in seconds).
pub const DEFAULT_TICKET_LIFETIME: u32 = 24 * 60 * 60;

/// Session data stored in the ticket.
#[derive(Clone, Debug)]
pub struct TicketData {
    /// Cipher suite used in the original session.
    pub cipher_suite: u16,
    /// Resumption master secret.
    pub resumption_secret: Vec<u8>,
    /// Creation timestamp (seconds since UNIX epoch).
    pub created_at: u64,
    /// Ticket age add value for obfuscation.
    pub age_add: u32,
    /// Application Layer Protocol Negotiation result.
    pub alpn: Option<String>,
    /// Server name (SNI).
    pub server_name: Option<String>,
}

impl TicketData {
    /// Create new ticket data from session state.
    pub fn new(cipher_suite: u16, resumption_secret: Vec<u8>) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let age_add = rand::thread_rng().gen();
        
        Self {
            cipher_suite,
            resumption_secret,
            created_at,
            age_add,
            alpn: None,
            server_name: None,
        }
    }

    /// Set ALPN protocol.
    pub fn with_alpn(mut self, alpn: impl Into<String>) -> Self {
        self.alpn = Some(alpn.into());
        self
    }

    /// Set server name.
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Check if ticket has expired.
    pub fn is_expired(&self, lifetime_secs: u32) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.created_at + lifetime_secs as u64
    }

    /// Get ticket age in milliseconds (with obfuscation).
    pub fn obfuscated_age(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let age_secs = (now - self.created_at) as u32;
        let age_ms = age_secs.saturating_mul(1000);
        age_ms.wrapping_add(self.age_add)
    }

    /// Serialize ticket data to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // Cipher suite (2 bytes)
        buf.extend_from_slice(&self.cipher_suite.to_be_bytes());
        
        // Resumption secret length + data
        buf.extend_from_slice(&(self.resumption_secret.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.resumption_secret);
        
        // Created at (8 bytes)
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        
        // Age add (4 bytes)
        buf.extend_from_slice(&self.age_add.to_be_bytes());
        
        // ALPN (length-prefixed)
        if let Some(ref alpn) = self.alpn {
            buf.push(alpn.len() as u8);
            buf.extend_from_slice(alpn.as_bytes());
        } else {
            buf.push(0);
        }
        
        // Server name (length-prefixed)
        if let Some(ref name) = self.server_name {
            buf.push(name.len() as u8);
            buf.extend_from_slice(name.as_bytes());
        } else {
            buf.push(0);
        }
        
        buf
    }

    /// Deserialize ticket data from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        
        let mut pos = 0;
        
        // Cipher suite
        let cipher_suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        
        // Resumption secret
        let secret_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + secret_len > data.len() {
            return None;
        }
        let resumption_secret = data[pos..pos + secret_len].to_vec();
        pos += secret_len;
        
        // Created at
        if pos + 8 > data.len() {
            return None;
        }
        let created_at = u64::from_be_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        
        // Age add
        if pos + 4 > data.len() {
            return None;
        }
        let age_add = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
        pos += 4;
        
        // ALPN
        if pos >= data.len() {
            return None;
        }
        let alpn_len = data[pos] as usize;
        pos += 1;
        let alpn = if alpn_len > 0 {
            if pos + alpn_len > data.len() {
                return None;
            }
            let s = String::from_utf8(data[pos..pos + alpn_len].to_vec()).ok()?;
            pos += alpn_len;
            Some(s)
        } else {
            None
        };
        
        // Server name
        if pos >= data.len() {
            return None;
        }
        let name_len = data[pos] as usize;
        pos += 1;
        let server_name = if name_len > 0 {
            if pos + name_len > data.len() {
                return None;
            }
            Some(String::from_utf8(data[pos..pos + name_len].to_vec()).ok()?)
        } else {
            None
        };
        
        Some(Self {
            cipher_suite,
            resumption_secret,
            created_at,
            age_add,
            alpn,
            server_name,
        })
    }
}

/// Encrypted session ticket.
#[derive(Clone, Debug)]
pub struct SessionTicket {
    /// Encrypted ticket data.
    pub encrypted: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: [u8; 12],
    /// Ticket lifetime in seconds.
    pub lifetime: u32,
}

impl SessionTicket {
    /// Encrypt ticket data with the given key.
    pub fn encrypt(data: &TicketData, key: &[u8; 32]) -> Result<Self, TicketError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| TicketError::EncryptionFailed)?;
        
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill(&mut nonce);
        
        let plaintext = data.to_bytes();
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| TicketError::EncryptionFailed)?;
        
        Ok(Self {
            encrypted,
            nonce,
            lifetime: DEFAULT_TICKET_LIFETIME,
        })
    }

    /// Decrypt ticket data with the given key.
    pub fn decrypt(&self, key: &[u8; 32]) -> Result<TicketData, TicketError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| TicketError::DecryptionFailed)?;
        
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.encrypted.as_ref())
            .map_err(|_| TicketError::DecryptionFailed)?;
        
        TicketData::from_bytes(&plaintext)
            .ok_or(TicketError::InvalidTicketData)
    }

    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // Lifetime (4 bytes)
        buf.extend_from_slice(&self.lifetime.to_be_bytes());
        
        // Nonce (12 bytes)
        buf.extend_from_slice(&self.nonce);
        
        // Encrypted data length + data
        buf.extend_from_slice(&(self.encrypted.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.encrypted);
        
        buf
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }
        
        let lifetime = u32::from_be_bytes(data[0..4].try_into().ok()?);
        
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[4..16]);
        
        let enc_len = u16::from_be_bytes([data[16], data[17]]) as usize;
        if data.len() < 18 + enc_len {
            return None;
        }
        let encrypted = data[18..18 + enc_len].to_vec();
        
        Some(Self {
            encrypted,
            nonce,
            lifetime,
        })
    }
}

/// NewSessionTicket message (TLS 1.3).
#[derive(Clone, Debug)]
pub struct NewSessionTicket {
    /// Ticket lifetime in seconds.
    pub ticket_lifetime: u32,
    /// Ticket age add for obfuscation.
    pub ticket_age_add: u32,
    /// Ticket nonce (for deriving PSK).
    pub ticket_nonce: Vec<u8>,
    /// The encrypted ticket.
    pub ticket: Vec<u8>,
    /// Extensions (optional).
    pub extensions: Vec<u8>,
}

impl NewSessionTicket {
    /// Create a new session ticket message.
    pub fn new(ticket: SessionTicket, age_add: u32) -> Self {
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill(&mut nonce);
        
        Self {
            ticket_lifetime: ticket.lifetime,
            ticket_age_add: age_add,
            ticket_nonce: nonce.to_vec(),
            ticket: ticket.to_bytes(),
            extensions: Vec::new(),
        }
    }

    /// Serialize to TLS wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // ticket_lifetime (4 bytes)
        buf.extend_from_slice(&self.ticket_lifetime.to_be_bytes());
        
        // ticket_age_add (4 bytes)
        buf.extend_from_slice(&self.ticket_age_add.to_be_bytes());
        
        // ticket_nonce (1-byte length + data)
        buf.push(self.ticket_nonce.len() as u8);
        buf.extend_from_slice(&self.ticket_nonce);
        
        // ticket (2-byte length + data)
        buf.extend_from_slice(&(self.ticket.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.ticket);
        
        // extensions (2-byte length + data)
        buf.extend_from_slice(&(self.extensions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.extensions);
        
        buf
    }

    /// Deserialize from TLS wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 13 {
            return None;
        }
        
        let mut pos = 0;
        
        // ticket_lifetime
        let ticket_lifetime = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
        pos += 4;
        
        // ticket_age_add
        let ticket_age_add = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
        pos += 4;
        
        // ticket_nonce
        let nonce_len = data[pos] as usize;
        pos += 1;
        if pos + nonce_len > data.len() {
            return None;
        }
        let ticket_nonce = data[pos..pos + nonce_len].to_vec();
        pos += nonce_len;
        
        // ticket
        if pos + 2 > data.len() {
            return None;
        }
        let ticket_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + ticket_len > data.len() {
            return None;
        }
        let ticket = data[pos..pos + ticket_len].to_vec();
        pos += ticket_len;
        
        // extensions
        if pos + 2 > data.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let extensions = if pos + ext_len <= data.len() {
            data[pos..pos + ext_len].to_vec()
        } else {
            Vec::new()
        };
        
        Some(Self {
            ticket_lifetime,
            ticket_age_add,
            ticket_nonce,
            ticket,
            extensions,
        })
    }
}

/// Ticket errors.
#[derive(Debug, Clone)]
pub enum TicketError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidTicketData,
    TicketExpired,
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "ticket encryption failed"),
            Self::DecryptionFailed => write!(f, "ticket decryption failed"),
            Self::InvalidTicketData => write!(f, "invalid ticket data"),
            Self::TicketExpired => write!(f, "ticket has expired"),
        }
    }
}

impl std::error::Error for TicketError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_data_roundtrip() {
        let data = TicketData::new(0x1301, vec![1, 2, 3, 4, 5, 6, 7, 8])
            .with_alpn("h2")
            .with_server_name("example.com");
        
        let bytes = data.to_bytes();
        let restored = TicketData::from_bytes(&bytes).unwrap();
        
        assert_eq!(restored.cipher_suite, data.cipher_suite);
        assert_eq!(restored.resumption_secret, data.resumption_secret);
        assert_eq!(restored.alpn, data.alpn);
        assert_eq!(restored.server_name, data.server_name);
    }

    #[test]
    fn test_ticket_encryption_decryption() {
        let key = [0u8; 32];
        let data = TicketData::new(0x1301, vec![1, 2, 3, 4]);
        
        let ticket = SessionTicket::encrypt(&data, &key).unwrap();
        let decrypted = ticket.decrypt(&key).unwrap();
        
        assert_eq!(decrypted.cipher_suite, data.cipher_suite);
        assert_eq!(decrypted.resumption_secret, data.resumption_secret);
    }

    #[test]
    fn test_ticket_wire_format() {
        let key = [0u8; 32];
        let data = TicketData::new(0x1301, vec![1, 2, 3, 4]);
        let ticket = SessionTicket::encrypt(&data, &key).unwrap();
        
        let bytes = ticket.to_bytes();
        let restored = SessionTicket::from_bytes(&bytes).unwrap();
        
        assert_eq!(restored.lifetime, ticket.lifetime);
        assert_eq!(restored.nonce, ticket.nonce);
        assert_eq!(restored.encrypted, ticket.encrypted);
    }

    #[test]
    fn test_new_session_ticket_roundtrip() {
        let key = [0u8; 32];
        let data = TicketData::new(0x1301, vec![1, 2, 3, 4]);
        let ticket = SessionTicket::encrypt(&data, &key).unwrap();
        let msg = NewSessionTicket::new(ticket, 12345);
        
        let bytes = msg.to_bytes();
        let restored = NewSessionTicket::from_bytes(&bytes).unwrap();
        
        assert_eq!(restored.ticket_lifetime, msg.ticket_lifetime);
        assert_eq!(restored.ticket_age_add, msg.ticket_age_add);
        assert_eq!(restored.ticket, msg.ticket);
    }

    #[test]
    fn test_obfuscated_age() {
        let data = TicketData::new(0x1301, vec![1, 2, 3, 4]);
        let age = data.obfuscated_age();
        // Age should include the age_add value
        assert!(age >= data.age_add || age < 1000); // Wrapping possible
    }

    #[test]
    fn test_ticket_expiration() {
        let mut data = TicketData::new(0x1301, vec![1, 2, 3, 4]);
        assert!(!data.is_expired(DEFAULT_TICKET_LIFETIME));
        
        // Manually set created_at to past
        data.created_at = 0;
        assert!(data.is_expired(DEFAULT_TICKET_LIFETIME));
    }
}
