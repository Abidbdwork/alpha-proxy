use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Invalid address: {0}")]
    Address(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account expired")]
    AccountExpired,

    #[error("Account disabled")]
    AccountDisabled,

    #[error("Too many connections")]
    TooManyConnections,

    #[error("Too many authentication attempts")]
    TooManyAttempts,

    #[error("Backend error: {0}")]
    BackendError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid value for {field}: {message}")]
    InvalidValue {
        field: String,
        message: String,
    },

    #[error("File error: {0}")]
    FileError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),
}

impl From<AuthError> for ProxyError {
    fn from(err: AuthError) -> Self {
        ProxyError::Auth(err.to_string())
    }
}

impl From<ConfigError> for ProxyError {
    fn from(err: ConfigError) -> Self {
        ProxyError::Config(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_error_display() {
        let err = ProxyError::Auth("Invalid username".to_string());
        assert_eq!(err.to_string(), "Authentication error: Invalid username");

        let err = ProxyError::Protocol("Invalid SOCKS version".to_string());
        assert_eq!(err.to_string(), "Protocol error: Invalid SOCKS version");
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::InvalidCredentials;
        assert_eq!(err.to_string(), "Invalid credentials");

        let err = AuthError::AccountExpired;
        assert_eq!(err.to_string(), "Account expired");
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::MissingField("port".to_string());
        assert_eq!(err.to_string(), "Missing required field: port");

        let err = ConfigError::InvalidValue {
            field: "timeout".to_string(),
            message: "must be positive".to_string(),
        };
        assert_eq!(err.to_string(), "Invalid value for timeout: must be positive");
    }

    #[test]
    fn test_error_conversions() {
        let auth_err = AuthError::InvalidCredentials;
        let proxy_err: ProxyError = auth_err.into();
        assert!(matches!(proxy_err, ProxyError::Auth(_)));

        let config_err = ConfigError::MissingField("host".to_string());
        let proxy_err: ProxyError = config_err.into();
        assert!(matches!(proxy_err, ProxyError::Config(_)));
    }
}