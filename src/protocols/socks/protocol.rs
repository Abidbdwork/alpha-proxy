use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// SOCKS protocol version
pub const SOCKS5_VERSION: u8 = 0x05;

// Authentication methods
pub const AUTH_METHOD_NONE: u8 = 0x00;
pub const AUTH_METHOD_GSSAPI: u8 = 0x01;
pub const AUTH_METHOD_PASSWORD: u8 = 0x02;
pub const AUTH_METHOD_UNACCEPTABLE: u8 = 0xFF;

// Command types
pub const COMMAND_CONNECT: u8 = 0x01;
pub const COMMAND_BIND: u8 = 0x02;
pub const COMMAND_UDP_ASSOCIATE: u8 = 0x03;

// Address types
pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN: u8 = 0x03;
pub const ADDR_TYPE_IPV6: u8 = 0x04;

// Reply codes
pub const REPLY_SUCCESS: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub const REPLY_TTL_EXPIRED: u8 = 0x06;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, Clone, PartialEq)]
pub enum SocksAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

impl SocksAddr {
    pub fn to_bytes(&self) -> Bytes {
        match self {
            SocksAddr::Ipv4(addr) => {
                let mut bytes = Vec::with_capacity(5);
                bytes.push(ADDR_TYPE_IPV4);
                bytes.extend_from_slice(&addr.octets());
                bytes.into()
            }
            SocksAddr::Ipv6(addr) => {
                let mut bytes = Vec::with_capacity(17);
                bytes.push(ADDR_TYPE_IPV6);
                bytes.extend_from_slice(&addr.octets());
                bytes.into()
            }
            SocksAddr::Domain(domain) => {
                let mut bytes = Vec::with_capacity(2 + domain.len());
                bytes.push(ADDR_TYPE_DOMAIN);
                bytes.push(domain.len() as u8);
                bytes.extend_from_slice(domain.as_bytes());
                bytes.into()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct SocksRequest {
    pub command: u8,
    pub address: SocksAddr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    pub username: String,
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks_addr_ipv4() {
        let addr = SocksAddr::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let bytes = addr.to_bytes();
        assert_eq!(bytes[0], ADDR_TYPE_IPV4);
        assert_eq!(&bytes[1..], &[127, 0, 0, 1]);
    }

    #[test]
    fn test_socks_addr_ipv6() {
        let addr = SocksAddr::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let bytes = addr.to_bytes();
        assert_eq!(bytes[0], ADDR_TYPE_IPV6);
        assert_eq!(&bytes[1..], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_socks_addr_domain() {
        let addr = SocksAddr::Domain("example.com".to_string());
        let bytes = addr.to_bytes();
        assert_eq!(bytes[0], ADDR_TYPE_DOMAIN);
        assert_eq!(bytes[1], 11); // length of "example.com"
        assert_eq!(&bytes[2..], b"example.com");
    }
}