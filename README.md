# CGGMP21 ECDSA Threshold Signature Demo

A committee-based secure distributed signing service based upon the CGGMP21/FROST TSS scheme.

> [!WARNING]
> This project is in early development and is not guaranteed to be secure or stable. Use at your own risk.

## Overview

This project uses a CGGMP21/FROST protocol for distributed threshold signing operations, allowing a committee of parties to collectively manage cryptographic operations without requiring complete trust between participants. The implementation uses a P2P network architecture for secure communication and coordination.

## Features

- **Distributed Committee Management**
    - Dynamic committee formation using P2P discovery
    - Threshold-based participation (3-of-n)
    - Secure member coordination via LibP2P's GossipSub
    - Automatic peer discovery using Kademlia DHT

- **Threshold Signing Operations**
    - Distributed key generation
    - Secure key share management
    - Deterministic signer selection (lowest 3 party IDs)
    - Threshold signature generation (t=3)

- **P2P Network Architecture**
    - Kademlia DHT for peer discovery
    - GossipSub for reliable message broadcast
    - Noise protocol for transport encryption
    - Automatic retry mechanisms
    - Session-based message routing

- **Protocol Security**
    - Threshold signature scheme
    - LibP2P Noise encryption for P2P communication
    - AES-GCM encrypted key share storage
    - Message authentication using GossipSub
    - Protected auxiliary information generation

## Protocol Flow

1. **Network Initialization**
    - Bootstrap node starts on port 8000
    - Committee members connect on ports 10334 + party_id
    - P2P mesh network forms via Kademlia DHT
    - Service node connects on port 10344

2. **Committee Formation**
    - Committee members discover each other via bootstrap node
    - Members establish direct P2P connections
    - Committee forms when 3 or more members join
    - Members generate execution ID via consensus

3. **Key Generation**
    - Members generate auxiliary information
    - Perform distributed key generation
    - Store encrypted key shares (AES-GCM)
    - Members announce readiness for signing

4. **Signing Operations**
    - Service node submits signing requests
    - Available members respond within 5-second window
    - Lowest 3 party IDs selected as signers
    - Signers generate and verify threshold signature

## Known Weaknesses

The current implementation has several known weaknesses and limitations that should be addressed before considering 
this ready for anything more than basic demonstration use:

- **Timing Attack Vulnerability**
    - In signing.rs, signature verification uses non-constant-time comparison
    - Potential timing side-channel during signature share verification
    - Currently compares signatures using standard equality checks

- **State Transition Issues**
    - Some state transitions lack proper error handling in signing protocol
    - Committee state machine lacks recovery mechanisms for interrupted sessions
    - No automatic retry for failed state transitions

- **Network Security**
    - Bootstrap node becomes a single point of failure
    - No validation of bootstrap node identity
    - Peer discovery relies on trusted bootstrap nodes
    - No blacklisting mechanism for misbehaving peers (aka Identifiable Abort)

- **Protocol Limitations**
    - Fixed 5-second collection window may be inappropriate for some network conditions
    - Deterministic signer selection (lowest 3 IDs) could be gamed by malicious parties
    - No dynamic adjustment of threshold parameters
    - No support for party removal/addition after committee formation

- **Security Implementation**
    - Fixed nonce ("unique nonce") used in storage encryption
    - No secure key erasure from memory after operations
    - Limited protection against message replay attacks
    - No rate limiting for message broadcasts

- **Error Recovery**
    - Limited recovery mechanisms for network partitions
    - No automatic reconnection strategy for dropped peers
    - Incomplete cleanup of resources in some error cases
    - No persistent state recovery across restarts

- **Missing Features**
    - No member replacement protocol
    - No support for concurrent signing sessions
    - Limited monitoring and metrics collection
    - No persistent logging of protocol events

- **Performance Considerations**
    - Unbounded message queues could lead to memory issues
    - No backpressure mechanisms in P2P communication
    - GossipSub mesh might not scale efficiently with large number of parties
    - No message batching for network optimization

## Technical Requirements

- Rust (latest stable version)
- Dependencies:
    - `cggmp21` and related crates for threshold signatures
    - `libp2p` for P2P networking
    - `tokio` for async runtime
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

Start a bootstrap node for peer discovery:
```bash
cggmp21-demo bootstrap
```

Start committee members (run 3 or more):
```bash
cggmp21-demo committee --party-id 1
cggmp21-demo committee --party-id 2
cggmp21-demo committee --party-id 3
```

Start a service node to request signatures:
```bash
cggmp21-demo service
```

Note: Each node type uses specific ports:
- Bootstrap node: Port 8000
- Committee members: Port 10334 + party_id
- Service node: Port 10344

## Development

### Project Structure

```
src/
├── main.rs          - Application entry point and CLI
├── committee.rs     - Committee protocol implementation
├── signing.rs       - Signing protocol implementation
├── p2p_node.rs      - P2P networking core
├── p2p.rs           - P2P message delivery
├── p2p_behaviour.rs - P2P behavior implementation
├── service.rs       - Signing service implementation
├── message.rs       - Protocol message definitions
├── network.rs       - Network abstractions
├── storage.rs       - Key and data storage management
└── error.rs         - Error handling definitions
```

### Components

- **P2PNode**: Core P2P networking using LibP2P
    - Peer discovery via Kademlia DHT
    - Message broadcast using GossipSub
    - Transport encryption with Noise
    - Session-based routing

- **P2PBehaviour**: Network protocol behaviors
    - Kademlia for peer discovery
    - GossipSub for pub/sub messaging
    - Identify for peer metadata
    - Custom protocol handlers

- **Committee**: Protocol coordination
    - Committee formation and management
    - Distributed key generation
    - Member synchronization
    - State machine-based protocol

- **Signing**: Threshold signing operations
    - Signature share generation
    - Share verification
    - Deterministic signer selection
    - Round-based protocol

- **Service**: Request handling
    - Message signing requests
    - Committee coordination
    - Response aggregation
    - State management

- **Storage**: Secure data management
    - AES-GCM encrypted storage
    - Key share management
    - Session state persistence
    - Secure serialization

## Security Considerations

- Minimum of <t> committee members required
- P2P traffic encrypted using Noise protocol
- Key shares protected with AES-GCM
- GossipSub message authentication
- Consensus-based execution ID
- Deterministic signer selection
- 5-second collection window for signing
- Protected auxiliary information

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
- [LibP2P Documentation](https://docs.rs/libp2p)

## Acknowledgments

This implementation is based on the CGGMP21 threshold signature scheme:
- Canetti, R., Goldwasser, S., Garg, S., Micali, S., & Popa, R. A. (2021)

## Support

For issues and feature requests, please use the GitHub issue tracker.

## Disclaimer

This implementation is provided as-is. Users should perform their own security review before using in production environments.