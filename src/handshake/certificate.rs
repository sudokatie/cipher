//! Certificate message (RFC 8446 Section 4.4.2)

use crate::error::TlsError;
use crate::extensions::{encode_extensions, parse_extensions, Extension};

/// A single certificate entry
#[derive(Debug, Clone)]
pub struct CertificateEntry {
    /// DER-encoded X.509 certificate
    pub cert_data: Vec<u8>,
    /// Extensions for this certificate
    pub extensions: Vec<Extension>,
}

impl CertificateEntry {
    /// Create a new certificate entry
    pub fn new(cert_data: Vec<u8>) -> Self {
        Self {
            cert_data,
            extensions: Vec::new(),
        }
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<(Self, usize), TlsError> {
        if data.len() < 3 {
            return Err(TlsError::Protocol("CertificateEntry too short".into()));
        }

        let cert_len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
        if data.len() < 3 + cert_len + 2 {
            return Err(TlsError::Protocol("CertificateEntry truncated".into()));
        }

        let cert_data = data[3..3 + cert_len].to_vec();
        let mut offset = 3 + cert_len;

        // Extensions
        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let extensions = if ext_len > 0 && offset + ext_len <= data.len() {
            parse_extensions(&data[offset..offset + ext_len])?
        } else {
            Vec::new()
        };
        offset += ext_len;

        Ok((
            Self {
                cert_data,
                extensions,
            },
            offset,
        ))
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Certificate data length (3 bytes)
        let cert_len = self.cert_data.len() as u32;
        data.extend_from_slice(&cert_len.to_be_bytes()[1..4]);
        data.extend_from_slice(&self.cert_data);

        // Extensions
        let ext_data = encode_extensions(&self.extensions);
        data.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext_data);

        data
    }
}

/// Certificate message
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Certificate request context (empty for server cert)
    pub certificate_request_context: Vec<u8>,
    /// Certificate chain
    pub certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    /// Create a new Certificate message
    pub fn new(certs: Vec<Vec<u8>>) -> Self {
        Self {
            certificate_request_context: Vec::new(),
            certificate_list: certs.into_iter().map(CertificateEntry::new).collect(),
        }
    }

    /// Create an empty Certificate message
    pub fn empty() -> Self {
        Self {
            certificate_request_context: Vec::new(),
            certificate_list: Vec::new(),
        }
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 4 {
            return Err(TlsError::Protocol("Certificate too short".into()));
        }

        let ctx_len = data[0] as usize;
        if data.len() < 1 + ctx_len + 3 {
            return Err(TlsError::Protocol("Certificate truncated".into()));
        }
        let certificate_request_context = data[1..1 + ctx_len].to_vec();
        let mut offset = 1 + ctx_len;

        // Certificate list length (3 bytes)
        let list_len =
            u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        let mut certificate_list = Vec::new();
        let list_end = offset + list_len;

        while offset < list_end && offset < data.len() {
            let (entry, consumed) = CertificateEntry::parse(&data[offset..])?;
            certificate_list.push(entry);
            offset += consumed;
        }

        Ok(Self {
            certificate_request_context,
            certificate_list,
        })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Certificate request context
        data.push(self.certificate_request_context.len() as u8);
        data.extend_from_slice(&self.certificate_request_context);

        // Certificate list
        let mut list_data = Vec::new();
        for entry in &self.certificate_list {
            list_data.extend_from_slice(&entry.encode());
        }

        let list_len = list_data.len() as u32;
        data.extend_from_slice(&list_len.to_be_bytes()[1..4]);
        data.extend_from_slice(&list_data);

        data
    }

    /// Get the end-entity certificate (first in chain)
    pub fn end_entity_cert(&self) -> Option<&[u8]> {
        self.certificate_list
            .first()
            .map(|e| e.cert_data.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_empty() {
        let cert = Certificate::empty();
        let encoded = cert.encode();
        let parsed = Certificate::parse(&encoded).unwrap();
        assert!(parsed.certificate_list.is_empty());
    }

    #[test]
    fn test_certificate_with_data() {
        let cert = Certificate::new(vec![vec![1, 2, 3, 4, 5]]);
        let encoded = cert.encode();
        let parsed = Certificate::parse(&encoded).unwrap();
        assert_eq!(parsed.certificate_list.len(), 1);
        assert_eq!(parsed.end_entity_cert(), Some(&[1u8, 2, 3, 4, 5][..]));
    }
}
