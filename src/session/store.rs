//! Session ticket storage for clients and servers.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;

use crate::session::ticket::{SessionTicket, TicketData, DEFAULT_TICKET_LIFETIME};

/// Session store trait for ticket storage.
pub trait SessionStore: Send + Sync {
    /// Store a ticket for a server name.
    fn store(&self, server_name: &str, ticket: StoredTicket);
    
    /// Retrieve a ticket for a server name.
    fn get(&self, server_name: &str) -> Option<StoredTicket>;
    
    /// Remove a ticket for a server name.
    fn remove(&self, server_name: &str);
    
    /// Remove expired tickets.
    fn cleanup(&self);
}

/// A stored session ticket with metadata.
#[derive(Clone, Debug)]
pub struct StoredTicket {
    /// The encrypted ticket data.
    pub ticket: SessionTicket,
    /// The decrypted ticket data (client-side).
    pub data: Option<TicketData>,
    /// Server name this ticket is for.
    pub server_name: String,
    /// When this ticket was stored.
    pub stored_at: u64,
}

impl StoredTicket {
    /// Create a new stored ticket (server-side).
    pub fn new_server(ticket: SessionTicket, server_name: impl Into<String>) -> Self {
        Self {
            ticket,
            data: None,
            server_name: server_name.into(),
            stored_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Create a new stored ticket (client-side with data).
    pub fn new_client(
        ticket: SessionTicket,
        data: TicketData,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            ticket,
            data: Some(data),
            server_name: server_name.into(),
            stored_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Check if this ticket has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.stored_at + self.ticket.lifetime as u64
    }
}

/// In-memory session store.
pub struct MemorySessionStore {
    tickets: Arc<RwLock<HashMap<String, StoredTicket>>>,
    max_entries: usize,
}

impl MemorySessionStore {
    /// Create a new memory session store.
    pub fn new() -> Self {
        Self {
            tickets: Arc::new(RwLock::new(HashMap::new())),
            max_entries: 1000,
        }
    }

    /// Create with a custom max entry limit.
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            tickets: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
        }
    }

    /// Get the number of stored tickets.
    pub fn len(&self) -> usize {
        self.tickets.read().unwrap().len()
    }

    /// Check if store is empty.
    pub fn is_empty(&self) -> bool {
        self.tickets.read().unwrap().is_empty()
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for MemorySessionStore {
    fn store(&self, server_name: &str, ticket: StoredTicket) {
        let mut tickets = self.tickets.write().unwrap();
        
        // Enforce max entries by removing oldest if at limit
        if tickets.len() >= self.max_entries && !tickets.contains_key(server_name) {
            // Find and remove oldest entry
            let oldest = tickets
                .iter()
                .min_by_key(|(_, t)| t.stored_at)
                .map(|(k, _)| k.clone());
            
            if let Some(key) = oldest {
                tickets.remove(&key);
            }
        }
        
        tickets.insert(server_name.to_string(), ticket);
    }

    fn get(&self, server_name: &str) -> Option<StoredTicket> {
        let tickets = self.tickets.read().unwrap();
        tickets.get(server_name).cloned()
    }

    fn remove(&self, server_name: &str) {
        let mut tickets = self.tickets.write().unwrap();
        tickets.remove(server_name);
    }

    fn cleanup(&self) {
        let mut tickets = self.tickets.write().unwrap();
        tickets.retain(|_, t| !t.is_expired());
    }
}

/// Server-side ticket key manager for encryption/decryption.
pub struct TicketKeyManager {
    /// Current encryption key.
    current_key: [u8; 32],
    /// Previous key for decrypting older tickets.
    previous_key: Option<[u8; 32]>,
    /// When the current key was created.
    key_created_at: u64,
    /// Key rotation interval in seconds.
    rotation_interval: u64,
}

impl TicketKeyManager {
    /// Create a new key manager with a random key.
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        
        Self {
            current_key: key,
            previous_key: None,
            key_created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            rotation_interval: DEFAULT_TICKET_LIFETIME as u64,
        }
    }

    /// Create with a specific key (for testing).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            current_key: key,
            previous_key: None,
            key_created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            rotation_interval: DEFAULT_TICKET_LIFETIME as u64,
        }
    }

    /// Get the current encryption key.
    pub fn current_key(&self) -> &[u8; 32] {
        &self.current_key
    }

    /// Rotate to a new key.
    pub fn rotate(&mut self) {
        self.previous_key = Some(self.current_key);
        rand::thread_rng().fill(&mut self.current_key);
        self.key_created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Check if key rotation is needed.
    pub fn needs_rotation(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.key_created_at + self.rotation_interval
    }

    /// Try to decrypt with current key, then previous key.
    pub fn decrypt(&self, ticket: &SessionTicket) -> Option<TicketData> {
        // Try current key first
        if let Ok(data) = ticket.decrypt(&self.current_key) {
            return Some(data);
        }
        
        // Try previous key if available
        if let Some(ref prev_key) = self.previous_key {
            if let Ok(data) = ticket.decrypt(prev_key) {
                return Some(data);
            }
        }
        
        None
    }

    /// Encrypt ticket data with current key.
    pub fn encrypt(&self, data: &TicketData) -> Option<SessionTicket> {
        SessionTicket::encrypt(data, &self.current_key).ok()
    }
}

impl Default for TicketKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_store_basic() {
        let store = MemorySessionStore::new();
        let ticket = SessionTicket {
            encrypted: vec![1, 2, 3],
            nonce: [0; 12],
            lifetime: 3600,
        };
        let stored = StoredTicket::new_server(ticket, "example.com");
        
        store.store("example.com", stored.clone());
        
        let retrieved = store.get("example.com").unwrap();
        assert_eq!(retrieved.server_name, "example.com");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_memory_store_remove() {
        let store = MemorySessionStore::new();
        let ticket = SessionTicket {
            encrypted: vec![1, 2, 3],
            nonce: [0; 12],
            lifetime: 3600,
        };
        let stored = StoredTicket::new_server(ticket, "example.com");
        
        store.store("example.com", stored);
        assert_eq!(store.len(), 1);
        
        store.remove("example.com");
        assert_eq!(store.len(), 0);
        assert!(store.get("example.com").is_none());
    }

    #[test]
    fn test_memory_store_max_entries() {
        let store = MemorySessionStore::with_max_entries(2);
        
        for i in 0..3 {
            let ticket = SessionTicket {
                encrypted: vec![i as u8],
                nonce: [0; 12],
                lifetime: 3600,
            };
            let stored = StoredTicket::new_server(ticket, format!("server{}", i));
            store.store(&format!("server{}", i), stored);
        }
        
        // Should have evicted oldest, keeping only 2
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_key_manager_encrypt_decrypt() {
        let key = [42u8; 32];
        let manager = TicketKeyManager::with_key(key);
        
        let data = TicketData::new(0x1301, vec![1, 2, 3, 4]);
        let ticket = manager.encrypt(&data).unwrap();
        let decrypted = manager.decrypt(&ticket).unwrap();
        
        assert_eq!(decrypted.cipher_suite, data.cipher_suite);
        assert_eq!(decrypted.resumption_secret, data.resumption_secret);
    }

    #[test]
    fn test_key_manager_rotation() {
        let mut manager = TicketKeyManager::new();
        let old_key = *manager.current_key();
        
        // Encrypt with old key
        let data = TicketData::new(0x1301, vec![1, 2, 3, 4]);
        let ticket = manager.encrypt(&data).unwrap();
        
        // Rotate key
        manager.rotate();
        assert_ne!(*manager.current_key(), old_key);
        
        // Should still decrypt with previous key
        let decrypted = manager.decrypt(&ticket).unwrap();
        assert_eq!(decrypted.cipher_suite, data.cipher_suite);
    }

    #[test]
    fn test_stored_ticket_expiration() {
        let ticket = SessionTicket {
            encrypted: vec![1, 2, 3],
            nonce: [0; 12],
            lifetime: 1, // 1 second
        };
        let mut stored = StoredTicket::new_server(ticket, "example.com");
        
        // Fresh ticket should not be expired
        assert!(!stored.is_expired());
        
        // Manually set stored_at to past
        stored.stored_at = 0;
        assert!(stored.is_expired());
    }
}
