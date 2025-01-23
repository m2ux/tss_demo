
# CGGMP21 Threshold Signature Demo Implementation

A Rust implementation of the CGGMP21 threshold signature scheme for secure distributed signing operations.

## Overview

This project implements the CGGMP21 protocol for distributed threshold signing operations, allowing a committee of parties to collectively manage cryptographic operations without requiring complete trust between participants. The implementation provides secure multiparty computation capabilities with threshold-based signing.

## Features

- **Distributed Committee Management**
  - Dynamic committee formation
  - Threshold-based participation
  - Secure member coordination

- **Threshold Signing Operations**
  - Distributed key generation
  - Secure key share management
  - Threshold-based signing operations

- **Protocol Security**
  - Implementation of CGGMP21 threshold signature scheme
  - Secure execution ID coordination
  - Protected auxiliary information generation

- **Robust Network Communication**
  - WebSocket-based messaging
  - Asynchronous operation handling
  - Reliable broadcast capabilities

## Protocol Flow

1. **Committee Formation**
   - Parties announce themselves to the network
   - Committee forms when sufficient members join
   - Threshold requirements are validated

2. **Execution ID Establishment**
   - Lowest-ID party proposes execution ID
   - Other parties validate and accept/reject
   - Consensus required for progression

3. **Key Generation**
   - Auxiliary information generation
   - Distributed key generation protocol
   - Individual key share creation

4. **Operational State**
   - Committee becomes ready for signing
   - Handles threshold signing requests
   - Maintains secure state management

## Technical Requirements

- Rust (latest stable version)
- Dependencies:
  - `cggmp21` and related crates
  - `tokio` for async runtime
  - `serde` for serialization
  - Additional dependencies listed in `Cargo.toml`

## Building

```bash
# Clone the repository
git clone https://github.com/input-output-hk/cggmp21-demo
cd cggmp21-demo

# Build the project
cargo build --release
```

## Running


 Start as a committee member:
 ```bash
 cggmp21-demo --committee --party-id <ID> --server <SERVER_ADDRESS>
 ```

 Initiate a signing operation:
 ```bash
 cggmp21-demo --message "Message to sign" --party-id <ID> --server <SERVER_ADDRESS>
 ```

 Run as coordination server:
 ```bash
 cggmp21-demo --server-mode --server <SERVER_ADDRESS>
 ```

Where:
- `<ID>` is the unique identifier for this committee member (e.g. 1)
- `<SERVER_ADDRESS>` is the WebSocket address of the coordination server (e.g. "ws://localhost:8080")

## Development

### Project Structure

```
src/
├── protocol.rs    - Committee protocol implementation
├── network.rs     - Network communication handling
├── signing.rs     - Signing protocol implementation
├── storage.rs     - Key and data storage management
└── error.rs       - Error handling definitions
```

### Key Components

- **Protocol**: Manages committee lifecycle and operations
- **Network**: Handles WebSocket-based communication
- **Signing**: Implements threshold signing operations
- **Storage**: Manages secure storage of keys and protocol data

## Security Considerations

- Requires a minimum of 3 committee members for security
- Implements threshold-based operations for distributed trust
- Secure key share generation and management
- Protected auxiliary information handling
- Consensus-based execution ID coordination

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

Apache 2.0 or MIT

## References

- [CGGMP21 Paper](https://eprint.iacr.org/2021/060.pdf)
- [Threshold ECDSA based on CGGMP21](https://github.com/LFDT-Lockness/cggmp21)

## Acknowledgments

This implementation is based on the CGGMP21 threshold signature scheme:
- Canetti, R., Goldwasser, S., Garg, S., Micali, S., & Popa, R. A. (2021)

## Support

For issues and feature requests, please use the GitHub issue tracker.

## Disclaimer

This implementation is provided as-is. Users should perform their own security review before using in production environments.