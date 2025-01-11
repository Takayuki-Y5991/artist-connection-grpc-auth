pub mod domain;
pub mod ports;
pub mod adapters;

pub use ports::AuthenticationPort;
pub use domain::{AuthError, AuthResult};