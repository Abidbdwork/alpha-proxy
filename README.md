# Alpha Proxy

A high-performance modular proxy server written in Rust, supporting multiple protocols and advanced features for production deployments.

## Features

- Multiple proxy protocols:
  - SOCKS5 (with authentication and IPv6)
  - SOCKS4
  - HTTP Forward Proxy
  - HTTPS CONNECT (TLS tunneling)
  - Transparent Proxy mode (TPROXY)

- Advanced networking:
  - Full IPv6 support
  - IP rotation strategies
  - Sticky sessions
  - Connection pooling
  - Multiple authentication backends

- Performance & Scalability:
  - Async I/O with Tokio
  - Low memory footprint
  - Horizontal scaling support
  - Connection rate limiting
  - Per-user bandwidth controls

- Monitoring & Management:
  - Prometheus metrics
  - Structured JSON logging
  - Admin REST API
  - CLI tools for management
  - Connection audit logs

## Quick Start

1. Install Rust (1.70 or later):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Clone and build:
   ```bash
   git clone https://github.com/Abidbdwork/alpha-proxy.git
   cd alpha-proxy
   cargo build --release
   ```

3. Create a basic configuration:
   ```bash
   mkdir config
   cat > config/config.toml << EOF
   [listen]
   socks5_addr = "127.0.0.1:1080"
   http_addr = "127.0.0.1:3128"

   [auth]
   backend = "csv"
   source = "users.csv"
   reload_interval = 300

   [metrics]
   prometheus_addr = "127.0.0.1:9090"
   EOF
   ```

4. Run the proxy:
   ```bash
   ./target/release/alpha-proxy -c config/config.toml
   ```

## Configuration

The proxy server is configured via TOML files. See [config.example.toml](config/config.example.toml) for a full example with comments.

### Authentication

Supports multiple authentication backends:
- CSV file (simple username:password list)
- MongoDB (for larger deployments)
- Custom backends via trait implementation

### IP Rotation

Four strategies available:
- Random: New IP for each connection
- Sticky: Consistent IP based on client
- Weighted: Load-balanced IP selection
- Static: Fixed IP per session/user

### Monitoring

- Prometheus metrics at `/metrics`
- Structured JSON logs
- Connection audit logs
- Per-user statistics

## Development

### Prerequisites

- Rust 1.70+
- CMake (for some dependencies)
- OpenSSL development libraries

### Building

```bash
# Debug build
cargo build

# Release build with optimizations
cargo build --release

# Run tests
cargo test

# Run with custom config
cargo run -- -c myconfig.toml
```

### Project Structure

```
src/
├── admin/       # Admin API and management interface
├── auth/        # Authentication backends
├── core/        # Core types and utilities
├── metrics/     # Prometheus metrics collection
└── protocols/   # Proxy protocol implementations
    ├── http/    # HTTP/HTTPS proxy
    ├── socks/   # SOCKS4/5 implementations
    └── transparent/  # TPROXY implementation
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

Please report security vulnerabilities to security@example.com.

## Acknowledgments

- [Tokio](https://tokio.rs/) for the async runtime
- [Hyper](https://hyper.rs/) for HTTP implementation
- All contributors and supporters of the project