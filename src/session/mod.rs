//! TLS 1.3 session resumption support.
//!
//! Implements session tickets for fast reconnection without full handshake.

mod ticket;
mod store;

pub use ticket::{SessionTicket, TicketData, NewSessionTicket};
pub use store::{SessionStore, MemorySessionStore};
