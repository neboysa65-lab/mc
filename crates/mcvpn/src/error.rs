use thiserror::Error;

#[derive(Debug, Error)]
pub enum VpnError {
    #[error("network io: {0}")]
    Io(#[from] std::io::Error),
    #[error("minecraft protocol: {0}")]
    Mc(#[from] mc_protocol::McError),
    #[error("kicked from server: {0}")]
    Kick(String),
    #[error("timed out")]
    Timeout,
    #[error("authentication failed")]
    Auth,
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("device: {0}")]
    Device(String),
    #[error("shutdown")]
    Shutdown,
}

impl VpnError {
    /// Kick reasons arrive as JSON chat components; flatten for display.
    pub fn kick_reason(&self) -> Option<&str> {
        match self {
            VpnError::Kick(r) => Some(r.as_str()),
            _ => None,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            VpnError::Io(_) | VpnError::Timeout | VpnError::Shutdown
        )
    }
}

pub type VpnResult<T> = Result<T, VpnError>;
