#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct McError(pub String);

impl McError {
    pub fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }
}

pub type McResult<T> = Result<T, McError>;
