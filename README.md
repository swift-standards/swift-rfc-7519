# swift-rfc-7519

Swift implementation of [RFC 7519: JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519.html)

## Overview

This package provides a **pure JWT implementation** without any cryptographic dependencies, making it lightweight, flexible, and universally compatible across all Swift platforms.

## Features

- ✅ **RFC 7519 Compliant**: Full implementation of the JWT specification
- 🪶 **Zero Dependencies**: Pure Swift implementation with no crypto dependencies
- 🌐 **Cross-Platform**: Works on all Swift platforms (Linux, Windows, macOS, iOS, etc.)
- 🔧 **Flexible**: Generic interface supports any cryptographic backend
- ⚡ **Fast**: Minimal overhead for parsing and inspection use cases
- 🧪 **Testable**: Easy to mock signers/verifiers for testing
- 📦 **Modular**: Choose your crypto implementation separately

## Installation

### Swift Package Manager

Add this to your Package.swift:

```swift
dependencies: [
    .package(url: "https://github.com/swift-web-standards/swift-rfc-7519.git", from: "1.0.0")
]
```

## Quick Start

### Core Usage (No Crypto Dependencies)

```swift
import RFC_7519

// Parse existing JWT
let jwt = try RFC_7519.JWT.parse(from: tokenString)

// Access claims
print("Issuer: \(jwt.payload.iss ?? "unknown")")
print("Subject: \(jwt.payload.sub ?? "unknown")")
print("Custom claim: \(jwt.payload.additionalClaim("role", as: String.self) ?? "none")")

// Validate timing (without signature verification)
try jwt.payload.validateTiming()
```

### With Cryptographic Functionality

For signing and verifying JWTs, use companion packages:

```swift
// Add crypto package
dependencies: [
    .package(url: "https://github.com/swift-web-standards/swift-rfc-7519.git", from: "1.0.0"),
    .package(url: "https://github.com/swift-web-standards/swift-rfc-7519-crypto.git", from: "1.0.0"),
]
```

```swift
import RFC_7519
import RFC_7519JWTCrypto

// Create and sign JWT
let jwt = try RFC_7519.JWT.hmacSHA256(
    issuer: "example.com",
    subject: "user123",
    expiresIn: 3600,
    claims: ["role": "admin"],
    secretKey: "my-secret-key"
)

// Verify JWT
let verificationKey = VerificationKey.symmetric(string: "my-secret-key")
let isValid = try jwt.verify(with: verificationKey)
```

### Generic Interface (Any Crypto Library)

```swift
import RFC_7519

// Create JWT with custom signer
let jwt = try RFC_7519.JWT(
    algorithmName: "HS256",
    issuer: "example.com", 
    subject: "user123",
    signer: { signingInput in
        // Use your preferred crypto library
        return yourCryptoLibrary.hmacSHA256(signingInput, key: "secret")
    }
)

// Verify with custom verifier
let isValid = try jwt.verify { signingInput, signature, algorithm in
    return yourCryptoLibrary.verifyHMAC(signature, for: signingInput, algorithm: algorithm)
}
```

## Architecture

### Core Package (This Repository)
- **Pure JWT parsing, validation, and serialization**
- **Generic signing/verification interfaces**
- **Zero cryptographic dependencies**

### Companion Packages
- **[swift-rfc-7519-crypto](https://github.com/swift-web-standards/swift-rfc-7519-crypto)**: Cross-platform crypto using swift-crypto
- **[swift-rfc-7519-cryptokit](https://github.com/swift-web-standards/swift-rfc-7519-cryptokit)**: Apple platforms using CryptoKit

## Supported JWT Features

- ✅ All standard registered claims (iss, sub, aud, exp, nbf, iat, jti)
- ✅ Custom claims with type-safe access
- ✅ Multiple audience support
- ✅ Timing validation with configurable clock skew
- ✅ Base64URL encoding/decoding (RFC 4648 Section 5)
- ✅ Compact serialization format
- ✅ Header parameter support (typ, alg, kid, cty, etc.)

## Testing

```swift
// Mock signer for testing
let mockSigner: (Data) throws -> Data = { _ in
    Data([0x01, 0x02, 0x03, 0x04])
}

let jwt = try RFC_7519.JWT(
    algorithmName: "HS256",
    issuer: "test",
    subject: "user", 
    signer: mockSigner
)
```

## Documentation

- **[RFC 7519 Specification](https://www.rfc-editor.org/rfc/rfc7519.html)**: Official JWT standard

## Use Cases

This package is perfect for:

- 🔍 **JWT Inspection**: Parse and examine JWT contents without verification
- 🧪 **Testing**: Mock JWT creation and verification for unit tests
- 🏗️ **Custom Crypto**: Integrate with specialized cryptographic libraries
- 📱 **Cross-Platform**: Deploy JWT functionality on any Swift platform
- 🪶 **Minimal Dependencies**: Keep your dependency graph clean

## License

This project is licensed under the MIT License - see the LICENSE file for details.