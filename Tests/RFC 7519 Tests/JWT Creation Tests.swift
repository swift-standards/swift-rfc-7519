//
//  JWT Creation Tests.swift
//  RFC_7519 Tests
//
//  Created by Generated on 2025-07-28.
//

import Testing
@testable import RFC_7519

@Suite
struct `JWT Creation Tests` {
    
    // MARK: - Generic JWT Creation Tests
    
    @Test
    func `JWT creation with generic signer`() throws {
        // Mock HMAC signer that just returns predictable bytes
        let mockSigner: (Data) throws -> Data = { signingInput in
            return [UInt8]([0x01, 0x02, 0x03, 0x04]) // Mock signature
        }
        
        let jwt = try RFC_7519.JWT(
            algorithmName: "HS256",
            issuer: "example.com",
            subject: "user123",
            audience: "api.example.com",
            expiresIn: 3600,
            claims: ["role": "admin"],
            signer: mockSigner
        )
        
        #expect(jwt.header.alg == "HS256")
        #expect(jwt.header.typ == "JWT")
        #expect(jwt.payload.iss == "example.com")
        #expect(jwt.payload.sub == "user123")
        #expect(jwt.payload.aud?.values == ["api.example.com"])
        #expect(jwt.payload.exp != nil)
        #expect(jwt.payload.iat != nil)
        #expect(jwt.payload.additionalClaim("role", as: String.self) == "admin")
        #expect(jwt.signature == [UInt8]([0x01, 0x02, 0x03, 0x04]))
    }
    
    @Test
    func `JWT creation with multiple audiences`() throws {
        let mockSigner: (Data) throws -> Data = { _ in Data() }
        
        let jwt = try RFC_7519.JWT(
            algorithmName: "HS256",
            issuer: "multi-aud-issuer",
            subject: "user",
            audiences: ["api1.example.com", "api2.example.com", "api3.example.com"],
            expiresIn: 3600,
            signer: mockSigner
        )
        
        #expect(jwt.payload.aud?.values == ["api1.example.com", "api2.example.com", "api3.example.com"])
    }
    
    @Test
    func `JWT creation with timing controls`() throws {
        let customIat = Date(timeIntervalSinceNow: -60) // 1 minute ago
        let customExp = Date(timeIntervalSinceNow: 7200) // 2 hours from now
        let customNbf = Date(timeIntervalSinceNow: 300) // 5 minutes from now
        
        let mockSigner: (Data) throws -> Data = { _ in Data() }
        
        let jwt = try RFC_7519.JWT(
            algorithmName: "HS256",
            issuer: "timing-issuer",
            subject: "timing-user",
            expiresAt: customExp,
            notBefore: customNbf,
            issuedAt: customIat,
            signer: mockSigner
        )
        
        #expect(abs(jwt.payload.iat!.timeIntervalSince1970 - customIat.timeIntervalSince1970) < 1.0)
        #expect(abs(jwt.payload.exp!.timeIntervalSince1970 - customExp.timeIntervalSince1970) < 1.0)
        #expect(abs(jwt.payload.nbf!.timeIntervalSince1970 - customNbf.timeIntervalSince1970) < 1.0)
    }
    
    @Test
    func `JWT creation with custom header parameters`() throws {
        let mockSigner: (Data) throws -> Data = { _ in Data() }
        
        let jwt = try RFC_7519.JWT(
            algorithmName: "HS256",
            issuer: "header-issuer",
            subject: "user",
            expiresIn: 3600,
            headerParameters: ["custom": "header-value", "version": 2],
            signer: mockSigner
        )
        
        #expect(jwt.header.additionalParameter("custom", as: String.self) == "header-value")
        #expect(jwt.header.additionalParameter("version", as: Int.self) == 2)
    }
    
    // MARK: - Generic Verification Tests
    
    @Test
    func `JWT verification with generic verifier`() throws {
        let expectedSignature = [UInt8]([0x05, 0x06, 0x07, 0x08])
        
        let mockSigner: (Data) throws -> Data = { _ in expectedSignature }
        
        let jwt = try RFC_7519.JWT(
            algorithmName: "HS256",
            issuer: "verify-issuer",
            subject: "verify-user",
            expiresIn: 3600,
            signer: mockSigner
        )
        
        // Mock verifier that checks if signature matches expected
        let mockVerifier: (Data, Data, String) throws -> Bool = { signingInput, signature, algorithm in
            guard algorithm == "HS256" else { return false }
            return signature == expectedSignature
        }
        
        let isValid = try jwt.verify(verifier: mockVerifier)
        #expect(isValid)
        
        // Test with wrong signature verifier
        let wrongVerifier: (Data, Data, String) throws -> Bool = { _, _, _ in false }
        let isInvalid = try jwt.verify(verifier: wrongVerifier)
        #expect(!isInvalid)
    }
    
    @Test
    func `JWT verification with timing validation`() throws {
        let mockSigner: (Data) throws -> Data = { _ in [UInt8]([0x09, 0x0A]) }
        
        // Create expired token
        let expiredJWT = try RFC_7519.JWT(
            algorithmName: "HS256",
            issuer: "expired-issuer",
            subject: "expired-user",
            expiresIn: -3600, // Expired 1 hour ago
            signer: mockSigner
        )
        
        let mockVerifier: (Data, Data, String) throws -> Bool = { _, _, _ in true }
        
        // Signature should be valid but timing should fail
        let isSignatureValid = try expiredJWT.verify(verifier: mockVerifier)
        #expect(isSignatureValid)
        
        #expect(throws: RFC_7519.Error.self) {
            try expiredJWT.verifyAndValidate(verifier: mockVerifier)
        }
        
        // Create valid token
        let validJWT = try RFC_7519.JWT(
            algorithmName: "HS256",
            issuer: "valid-issuer",
            subject: "valid-user",
            expiresIn: 3600,
            signer: mockSigner
        )
        
        // Both signature and timing should be valid
        let isValid = try validJWT.verifyAndValidate(verifier: mockVerifier)
        #expect(isValid)
    }
    
    @Test
    func `JWT verification with not-yet-valid token`() throws {
        let mockSigner: (Data) throws -> Data = { _ in [UInt8]([0x0B, 0x0C]) }
        
        let jwt = try RFC_7519.JWT(
            algorithmName: "HS256",
            issuer: "nbf-issuer",
            subject: "nbf-user",
            expiresIn: 7200, // Expires in 2 hours
            notBefore: Date(timeIntervalSinceNow: 3600), // Valid in 1 hour
            signer: mockSigner
        )
        
        let mockVerifier: (Data, Data, String) throws -> Bool = { _, _, _ in true }
        
        // Signature should be valid but timing should fail
        let isSignatureValid = try jwt.verify(verifier: mockVerifier)
        #expect(isSignatureValid)
        
        #expect(throws: RFC_7519.Error.self) {
            try jwt.verifyAndValidate(verifier: mockVerifier)
        }
    }
    
    // MARK: - Edge Cases
    
    @Test
    func `JWT with no algorithm (none)`() throws {
        let mockSigner: (Data) throws -> Data = { _ in Data() } // Empty signature for 'none'
        
        let jwt = try RFC_7519.JWT(
            algorithmName: "none",
            issuer: "none-issuer",
            subject: "none-user",
            expiresIn: 3600,
            signer: mockSigner
        )
        
        #expect(jwt.header.alg == "none")
        #expect(jwt.signature.isEmpty)
        
        // Verification should work with 'none' algorithm
        let noneVerifier: (Data, Data, String) throws -> Bool = { _, signature, algorithm in
            return algorithm == "none" && signature.isEmpty
        }
        
        let isValid = try jwt.verify(verifier: noneVerifier)
        #expect(isValid)
    }
    
    @Test
    func `JWT creation with custom algorithm`() throws {
        let customSigner: (Data) throws -> Data = { signingInput in
            // Custom signature algorithm - just reverse the bytes for testing
            return Data(signingInput.reversed())
        }
        
        let jwt = try RFC_7519.JWT(
            algorithmName: "CUSTOM",
            issuer: "custom-issuer",
            subject: "custom-user",
            expiresIn: 3600,
            signer: customSigner
        )
        
        #expect(jwt.header.alg == "CUSTOM")
        
        // Verify with matching custom verifier
        let customVerifier: (Data, Data, String) throws -> Bool = { signingInput, signature, algorithm in
            guard algorithm == "CUSTOM" else { return false }
            let expectedSignature = Data(signingInput.reversed())
            return signature == expectedSignature
        }
        
        let isValid = try jwt.verify(verifier: customVerifier)
        #expect(isValid)
    }
    
    @Test
    func `JWT creation error handling`() throws {
        let failingSigner: (Data) throws -> Data = { _ in
            struct SigningError: Swift.Error {}
            throw SigningError()
        }
        
        #expect(throws: (any Error).self) {
            try RFC_7519.JWT(
                algorithmName: "HS256",
                issuer: "error-issuer",
                subject: "error-user",
                signer: failingSigner
            )
        }
    }
}
