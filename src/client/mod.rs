//! TLS Client implementation

mod async_connection;
mod config;
mod connection;

pub use async_connection::{connect as async_connect, AsyncTlsClient};
pub use config::TlsClientConfig;
pub use connection::TlsClient;
