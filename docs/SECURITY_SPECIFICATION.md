# WhatsApp-Grade Security Specification for Hypersend
===================================================

## Executive Summary

Hypersend implements WhatsApp-grade end-to-end encryption with the Signal Protocol,
providing cryptographic guarantees equivalent to WhatsApp while maintaining a
stateless server architecture that never stores plaintext messages or media.

## Security Architecture Overview

### Core Principles
1. **Zero-Knowledge Server**: Server never sees plaintext messages or media
2. **End-to-End Encryption**: All content encrypted client-side with Signal Protocol
3. **Perfect Forward Secrecy**: Compromise of long-term keys doesn't reveal past messages
4. **Post-Compromise Security**: Recovery from key compromise through DH ratcheting
5. **Multi-Device Isolation**: Per-device cryptographic sessions with independent ratchets
6. **Ephemeral Storage**: All data auto-deletes (24h TTL for media, 7 days for sessions)

### Cryptographic Stack
```
Application Layer:    Encrypted Messages (Signal Protocol)
Transport Layer:       TLS 1.3 + WebSocket (WSS)
Storage Layer:         Redis (ephemeral, encrypted blobs)
Media Layer:           Client-side AES-256-GCM + S3 (encrypted)
```

## Signal Protocol Implementation

### X3DH Handshake
- **Identity Keys**: X25519 (DH) + Ed25519 (signing)
- **Signed Pre-Keys**: Rotated every 7 days
- **One-Time Pre-Keys**: Batch of 100, replenished automatically
- **Ephemeral Keys**: Fresh per-session X25519 key pairs
- **Master Secret**: HKDF-SHA256 derivation from 5-6 DH shared secrets

### Double Ratchet
- **Root Key**: Updated via DH ratchet on each new remote DH public key
- **Chain Keys**: Symmetric ratchet for message keys
- **Message Keys**: One-time use, derived via HKDF-SHA256
- **Ratchet State**: Per-device, serialized to Redis with TTL
- **Forward Secrecy**: New message keys cannot decrypt old messages

### Key Management
```
Identity Key Pair:      Long-term (user lifetime)
Signed Pre-Key:         7 days rotation
One-Time Pre-Keys:      100 batch, single-use
Ephemeral Keys:         Per-session
Message Keys:           One-time use
Media Keys:             Per-file, per-device encrypted
```

## Multi-Device Architecture

### Device Linking
- **QR Code Only**: No manual key entry, prevents MITM
- **Primary Device Trust**: Root of trust established via primary device
- **Ephemeral Tokens**: 5-minute expiration for linking codes
- **Device Verification**: Cryptographic proof of device identity

### Per-Device Sessions
- **Independent Ratchets**: Each device maintains separate Double Ratchet
- **Message Fan-Out**: Encrypted separately for each receiving device
- **Device Revocation**: Immediate key destruction on device removal
- **Session Isolation**: Compromise of one device doesn't affect others

### Device Types Supported
- **Mobile**: Android, iOS (full cryptographic capabilities)
- **Desktop**: Windows, macOS, Linux (full cryptographic capabilities)
- **Web**: Limited capabilities, requires companion device

## Media Encryption & Lifecycle

### Client-Side Encryption
- **Algorithm**: AES-256-GCM with random 96-bit IV
- **Key Generation**: Cryptographically secure random 256-bit keys
- **Integrity**: GCM authentication tag prevents tampering
- **Chunking**: 1MB chunks for large files, each individually encrypted

### Per-Device Key Distribution
- **Key Packaging**: Media keys encrypted per receiving device
- **Session Binding**: Keys derived from device session keys
- **HMAC Protection**: Integrity verification of key packages
- **Anti-Replay**: One-time use download tokens

### Storage & Deletion
- **Server Storage**: Encrypted blobs only, never plaintext
- **TTL Enforcement**: 24-hour automatic deletion
- **ACK-Based Deletion**: Immediate deletion after all devices ACK
- **Secure Cleanup**: Cryptographic zeroization of keys

## Message Delivery Semantics

### Per-Device State Machine
```
PENDING → SENT → DELIVERED → READ → DELETED
    ↓       ↓        ↓        ↓        ↓
  Retry   Success  Success  Success  Cleanup
```

### Reliability Guarantees
- **Idempotent Processing**: Duplicate detection via message IDs
- **Exact-Once Delivery**: Sequence numbers prevent replay
- **Ordered Delivery**: Per-chat sequence ordering
- **Retry Logic**: Exponential backoff with max 7 attempts
- **Connection Recovery**: Automatic resumption on reconnection

### Delivery Receipts
- **Per-Device Tracking**: Independent status per device
- **Anonymous Receipts**: HMAC-based tokens prevent correlation
- **Privacy Preservation**: No timing correlation between devices
- **Batch Processing**: Efficient receipt aggregation

## Client-Side Security

### Local Storage Encryption
- **Database Encryption**: AES-256-GCM with device-specific keys
- **Key Derivation**: HKDF from device lock screen credentials
- **Secure Keystore**: OS-provided secure storage (Keychain/Keystore)
- **Memory Protection**: Zeroization of sensitive data

### Device Security
- **Root/Jailbreak Detection**: Automated detection with auto-wipe
- **Screenshot Protection**: OS-level prevention where supported
- **Screen Recording Prevention**: Block screen capture apps
- **Clipboard Security**: Automatic clearing of sensitive data
- **Auto-Wipe**: Immediate data destruction on compromise

### Authentication Security
- **Rate Limiting**: Exponential backoff on failed attempts
- **Device Binding**: Sessions bound to specific device identifiers
- **Session Timeout**: 30-minute inactivity timeout
- **Multi-Factor**: Optional biometric authentication

## Metadata Minimization

### Traffic Analysis Protection
- **IP Obfuscation**: Optional Tor/VPN integration
- **Timing Padding**: Random delays to prevent correlation
- **Size Padding**: Message size normalization
- **Connection Padding**: Dummy packets to obscure patterns

### Anonymous Operations
- **Delivery Receipts**: HMAC-based anonymous tokens
- **Read Receipts**: No correlation between sender/receiver timing
- **Online Status**: Granular privacy controls
- **Last Seen**: User-configurable privacy levels

## Threat Model

### Assumptions
- **Server Compromise**: Server may be fully compromised
- **Network Attacker**: Active MITM capabilities
- **Device Compromise**: Individual devices may be compromised
- **Storage Compromise**: Redis/S3 may be accessed
- ** Insider Threat**: Malicious server administrators

### Protections
```
Server Compromise:     ✅ Zero-knowledge architecture
Network MITM:          ✅ End-to-end encryption + certificate pinning
Device Compromise:     ✅ Per-device isolation, forward secrecy
Storage Compromise:    ✅ Client-side encryption only
Insider Threat:        ✅ No access to plaintext data
```

### Limitations
- **Quantum Computing**: Current algorithms not quantum-resistant
- **Social Engineering**: User education required
- **Device Security**: Depends on user device security practices
- **Backup Security**: User responsibility for secure backups

## Security Assumptions

### Cryptographic Assumptions
- **X25519 Security**: ECDH problem remains hard
- **Ed25519 Security**: ECDSA with curve25519 remains secure
- **AES-256 Security**: Symmetric encryption remains secure
- **SHA-256 Security**: Hash function remains collision-resistant
- **HKDF Security**: Key derivation function remains secure

### Implementation Assumptions
- **Random Number Generation**: CSPRNG provides sufficient entropy
- **Timing Attacks**: Implementation resistant to timing attacks
- **Side Channels**: Constant-time implementations where critical
- **Memory Safety**: No memory leaks of sensitive data
- **Certificate Validation**: Proper certificate chain validation

## Audit Checklist

### Cryptographic Implementation
- [ ] Signal Protocol correctly implemented
- [ ] X3DH handshake follows specification
- [ ] Double Ratchet maintains forward secrecy
- [ ] Key rotation schedules enforced
- [ ] Random number generation uses CSPRNG
- [ ] Constant-time implementations for sensitive operations

### Multi-Device Security
- [ ] Device linking uses QR codes only
- [ ] Per-device sessions properly isolated
- [ ] Device revocation immediately destroys keys
- [ ] Primary device trust model correctly implemented
- [ ] Device authentication properly validated

### Media Security
- [ ] Client-side encryption correctly implemented
- [ ] Per-device key distribution secure
- [ ] Media keys never stored server-side
- [ ] TTL enforcement for all media
- [ ] Secure deletion implemented

### Network Security
- [ ] TLS 1.3 with strong cipher suites
- [ ] Certificate pinning implemented
- [ ] WebSocket security properly configured
- [ ] Rate limiting prevents abuse
- [ ] DDoS protection in place

### Storage Security
- [ ] Redis encryption at rest
- [ ] S3 encryption with customer-managed keys
- [ ] Proper access controls implemented
- [ ] Audit logging enabled
- [ ] Backup encryption implemented

## Responsible Disclosure Policy

### Security Contact
- **Email**: security@hypersend.com
- **PGP Key**: Available on website
- **Response Time**: Within 24 hours
- **Bug Bounty**: Up to $10,000 for critical vulnerabilities

### Disclosure Process
1. **Initial Report**: Security researcher submits vulnerability
2. **Acknowledgment**: Team acknowledges within 24 hours
3. **Assessment**: Team assesses severity and impact
4. **Remediation**: Team fixes vulnerability
5. **Verification**: Researcher verifies fix
6. **Disclosure**: Coordinated public disclosure after fix

### Reward Structure
- **Critical**: $10,000 (remote code execution, data breach)
- **High**: $5,000 (cryptographic weaknesses, privilege escalation)
- **Medium**: $2,000 (information disclosure, DoS)
- **Low**: $500 (minor security issues)

## Compliance & Regulations

### Data Protection
- **GDPR Compliant**: Right to be forgotten, data portability
- **CCPA Compliant**: California privacy rights
- **PIPL Compliant**: China data protection law
- **LGPD Compliant**: Brazil data protection law

### Industry Standards
- **ISO 27001**: Information security management
- **SOC 2 Type II**: Security controls audit
- **NIST Cybersecurity Framework**: Security best practices
- **OWASP Top 10**: Web application security

## Conclusion

Hypersend provides WhatsApp-grade security guarantees through:
- **Signal Protocol**: Proven end-to-end encryption
- **Zero-Knowledge Architecture**: Server never sees plaintext
- **Multi-Device Support**: Secure device linking and isolation
- **Ephemeral Storage**: Automatic data deletion
- **Comprehensive Security**: Client-side protections and metadata minimization

The system is designed to protect against sophisticated adversaries while maintaining
usability and performance at WhatsApp scale (10M+ concurrent users).

---

**Document Version**: 1.0  
**Last Updated**: 2026-02-06  
**Classification**: Public  
**Next Review**: 2026-05-06
