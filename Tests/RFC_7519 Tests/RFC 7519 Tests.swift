//
//  RFC 7519 Tests.swift
//  RFC_7519 Tests
//
//  Created by Generated on 2025-07-28.
//

import Testing
import Foundation
@testable import RFC_7519

@Suite("RFC 7519 Tests")
struct RFC_7519_Tests {
    
    // MARK: - JWT Parsing Tests
    
    @Test("JWT parsing from valid token")
    func testValidJWTParsing() throws {
        // Example JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}.signature
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        let jwt = try RFC_7519.JWT.parse(from: token)
        
        #expect(jwt.header.alg == "HS256")
        #expect(jwt.header.typ == "JWT")
        #expect(jwt.payload.sub == "1234567890")
        #expect(jwt.payload.additionalClaim("name", as: String.self) == "John Doe")
        #expect(jwt.payload.iat == Date(timeIntervalSince1970: 1516239022))
    }
    
    @Test("JWT parsing with invalid format")
    func testInvalidJWTFormat() {
        // Too few parts
        #expect(throws: RFC_7519.Error.self) {
            try RFC_7519.JWT.parse(from: "invalid.token")
        }
        
        // Too many parts
        #expect(throws: RFC_7519.Error.self) {
            try RFC_7519.JWT.parse(from: "too.many.parts.here")
        }
        
        // Empty string
        #expect(throws: RFC_7519.Error.self) {
            try RFC_7519.JWT.parse(from: "")
        }
    }
    
    @Test("JWT parsing with invalid base64url encoding")
    func testInvalidBase64URLEncoding() {
        // Invalid base64url in header
        #expect(throws: RFC_7519.Error.self) {
            try RFC_7519.JWT.parse(from: "invalid@base64.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
        }
        
        // Invalid base64url in payload  
        #expect(throws: RFC_7519.Error.self) {
            try RFC_7519.JWT.parse(from: "eyJhbGciOiJIUzI1NiJ9.invalid@base64.signature")
        }
        
        // Invalid base64url in signature
        #expect(throws: RFC_7519.Error.self) {
            try RFC_7519.JWT.parse(from: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid@base64")
        }
    }
    
    @Test("JWT parsing with invalid JSON")
    func testInvalidJSON() {
        // Invalid JSON in header (base64url encoded "{invalid json}")
        #expect(throws: RFC_7519.Error.self) {
            try RFC_7519.JWT.parse(from: "e2ludmFsaWQganNvbn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
        }
        
        // Invalid JSON in payload
        #expect(throws: RFC_7519.Error.self) {
            try RFC_7519.JWT.parse(from: "eyJhbGciOiJIUzI1NiJ9.e2ludmFsaWQganNvbn0.signature")
        }
    }
    
    // MARK: - JWT Serialization Tests
    
    @Test("JWT compact serialization")
    func testCompactSerialization() throws {
        let header = RFC_7519.JWT.Header(alg: "HS256", typ: "JWT")
        let payload = RFC_7519.JWT.Payload(
            sub: "1234567890",
            iat: Date(timeIntervalSince1970: 1516239022),
            additionalClaims: ["name": "John Doe"]
        )
        let signature = Data([0x49, 0xF9, 0x4A, 0xC7, 0x04, 0x49, 0x48, 0xC7])
        
        let jwt = RFC_7519.JWT(header: header, payload: payload, signature: signature)
        let serialized = try jwt.compactSerialization()
        
        let parts = serialized.components(separatedBy: ".")
        #expect(parts.count == 3)
        
        // Verify round trip
        let parsedJWT = try RFC_7519.JWT.parse(from: serialized)
        #expect(parsedJWT.header.alg == "HS256")
        #expect(parsedJWT.payload.sub == "1234567890")
    }
    
    @Test("JWT signing input generation")
    func testSigningInput() throws {
        let header = RFC_7519.JWT.Header(alg: "HS256")
        let payload = RFC_7519.JWT.Payload(sub: "test")
        let jwt = RFC_7519.JWT(header: header, payload: payload, signature: Data())
        
        let signingInput = try jwt.signingInput()
        let signingInputString = String(data: signingInput, encoding: .ascii)
        
        #expect(signingInputString != nil)
        #expect(signingInputString!.contains("."))
        #expect(signingInputString!.components(separatedBy: ".").count == 2)
    }
    
    @Test("JWT preserves original base64url strings for efficiency")
    func testOriginalBase64URLPreservation() throws {
        // Use a real JWT with known base64url components
        let originalToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        // Parse the JWT
        let jwt = try RFC_7519.JWT.parse(from: originalToken)
        
        // Get signing input - should use original base64url strings
        let signingInput = try jwt.signingInput()
        let signingInputString = String(data: signingInput, encoding: .ascii)!
        
        // Since we preserved the original strings, the signing input should be exactly the original header.payload
        let originalComponents = originalToken.components(separatedBy: ".")
        let originalSigningInput = "\(originalComponents[0]).\(originalComponents[1])"
        
        #expect(signingInputString == originalSigningInput)
        
        // Also test that compact serialization preserves the original strings
        let serialized = try jwt.compactSerialization()
        #expect(serialized == originalToken)
    }
    
    // MARK: - Header Tests
    
    @Test("JWT header with basic fields")
    func testBasicHeader() {
        let header = RFC_7519.JWT.Header(alg: "HS256", typ: "JWT")
        
        #expect(header.alg == "HS256")
        #expect(header.typ == "JWT")
        #expect(header.cty == nil)
        #expect(header.kid == nil)
    }
    
    @Test("JWT header with all fields")
    func testHeaderWithAllFields() {
        let additionalParams: [String: Any] = ["custom": "value", "number": 42]
        let header = RFC_7519.JWT.Header(
            alg: "RS256",
            typ: "JWT",
            cty: "application/json",
            kid: "key-1",
            additionalParameters: additionalParams
        )
        
        #expect(header.alg == "RS256")
        #expect(header.typ == "JWT")
        #expect(header.cty == "application/json")
        #expect(header.kid == "key-1")
        #expect(header.additionalParameter("custom", as: String.self) == "value")
        #expect(header.additionalParameter("number", as: Int.self) == 42)
    }
    
    @Test("JWT header coding round trip")
    func testHeaderCodingRoundTrip() throws {
        let header = RFC_7519.JWT.Header(
            alg: "ES256",
            typ: "JWT",
            kid: "test-key",
            additionalParameters: ["custom": "value"]
        )
        
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        
        let data = try encoder.encode(header)
        let decodedHeader = try decoder.decode(RFC_7519.JWT.Header.self, from: data)
        
        #expect(header.alg == decodedHeader.alg)
        #expect(header.typ == decodedHeader.typ)
        #expect(header.kid == decodedHeader.kid)
        #expect(header.additionalParameter("custom", as: String.self) == 
                decodedHeader.additionalParameter("custom", as: String.self))
    }
    
    // MARK: - Payload Tests
    
    @Test("JWT payload with basic claims")
    func testBasicPayload() {
        let payload = RFC_7519.JWT.Payload(iss: "example.com", sub: "user123")
        
        #expect(payload.sub == "user123")
        #expect(payload.iss == "example.com")
        #expect(payload.aud == nil)
        #expect(payload.exp == nil)
    }
    
    @Test("JWT payload with all registered claims")
    func testPayloadWithAllRegisteredClaims() {
        let issuedAt = Date()
        let expiration = Date(timeIntervalSinceNow: 3600)
        let notBefore = Date(timeIntervalSinceNow: -60)
        
        let payload = RFC_7519.JWT.Payload(
            iss: "https://example.com",
            sub: "user123",
            aud: .single("api.example.com"),
            exp: expiration,
            nbf: notBefore,
            iat: issuedAt,
            jti: "token-id-123"
        )
        
        #expect(payload.iss == "https://example.com")
        #expect(payload.sub == "user123")
        #expect(payload.aud?.values == ["api.example.com"])
        #expect(payload.jti == "token-id-123")
        
        // Check dates with tolerance
        if let exp = payload.exp {
            #expect(abs(exp.timeIntervalSince1970 - expiration.timeIntervalSince1970) < 1.0)
        }
        if let nbf = payload.nbf {
            #expect(abs(nbf.timeIntervalSince1970 - notBefore.timeIntervalSince1970) < 1.0)
        }
        if let iat = payload.iat {
            #expect(abs(iat.timeIntervalSince1970 - issuedAt.timeIntervalSince1970) < 1.0)
        }
    }
    
    @Test("JWT payload with additional claims")
    func testPayloadWithAdditionalClaims() {
        let additionalClaims: [String: Any] = [
            "role": "admin",
            "permissions": ["read", "write"],
            "active": true,
            "score": 95.5
        ]
        
        let payload = RFC_7519.JWT.Payload(
            sub: "user123",
            additionalClaims: additionalClaims
        )
        
        #expect(payload.additionalClaim("role", as: String.self) == "admin")
        #expect(payload.additionalClaim("active", as: Bool.self) == true)
        #expect(payload.additionalClaim("score", as: Double.self) == 95.5)
    }
    
    @Test("JWT payload coding round trip")
    func testPayloadCodingRoundTrip() throws {
        let payload = RFC_7519.JWT.Payload(
            iss: "test-issuer",
            sub: "test-subject",
            aud: .multiple(["api1", "api2"]),
            exp: Date(timeIntervalSince1970: 1234567890),
            additionalClaims: ["custom": "value", "number": 42]
        )
        
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        
        let data = try encoder.encode(payload)
        let decodedPayload = try decoder.decode(RFC_7519.JWT.Payload.self, from: data)
        
        #expect(payload.iss == decodedPayload.iss)
        #expect(payload.sub == decodedPayload.sub)
        #expect(payload.aud?.values == decodedPayload.aud?.values)
        
        if let exp = payload.exp, let decodedExp = decodedPayload.exp {
            #expect(abs(exp.timeIntervalSince1970 - decodedExp.timeIntervalSince1970) < 1.0)
        }
        
        #expect(payload.additionalClaim("custom", as: String.self) ==
                decodedPayload.additionalClaim("custom", as: String.self))
    }
    
    // MARK: - Audience Tests
    
    @Test("Single audience handling")
    func testSingleAudience() {
        let audience = RFC_7519.JWT.Payload.Audience("api.example.com")
        
        #expect(audience.values == ["api.example.com"])
        #expect(audience.contains("api.example.com"))
        #expect(!audience.contains("other.com"))
    }
    
    @Test("Multiple audience handling")
    func testMultipleAudience() {
        let audience = RFC_7519.JWT.Payload.Audience(["api1.com", "api2.com"])
        
        #expect(audience.values == ["api1.com", "api2.com"])
        #expect(audience.contains("api1.com"))
        #expect(audience.contains("api2.com"))
        #expect(!audience.contains("api3.com"))
    }
    
    @Test("Audience initialization from single string array")
    func testAudienceFromSingleStringArray() {
        let audience = RFC_7519.JWT.Payload.Audience(["api.example.com"])
        
        // Should convert single-item array to single audience
        #expect(audience.values == ["api.example.com"])
        #expect(audience.contains("api.example.com"))
    }
    
    @Test("Audience coding round trip")
    func testAudienceCodingRoundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        
        // Test single audience
        let singleAudience = RFC_7519.JWT.Payload.Audience("api.example.com")
        let singleData = try encoder.encode(singleAudience)
        let decodedSingle = try decoder.decode(RFC_7519.JWT.Payload.Audience.self, from: singleData)
        #expect(singleAudience.values == decodedSingle.values)
        
        // Test multiple audience
        let multipleAudience = RFC_7519.JWT.Payload.Audience(["api1.com", "api2.com"])
        let multipleData = try encoder.encode(multipleAudience)
        let decodedMultiple = try decoder.decode(RFC_7519.JWT.Payload.Audience.self, from: multipleData)
        #expect(multipleAudience.values == decodedMultiple.values)
    }
    
    // MARK: - Timing Validation Tests
    
    @Test("Valid timing claims validation")
    func testValidTimingClaims() throws {
        let now = Date()
        let payload = RFC_7519.JWT.Payload(
            exp: Date(timeIntervalSinceNow: 3600), // Expires in 1 hour
            nbf: Date(timeIntervalSinceNow: -60),  // Valid since 1 minute ago
            iat: now
        )
        
        // Should not throw
        try payload.validateTiming(currentTime: now)
    }
    
    @Test("Expired token validation")
    func testExpiredToken() {
        let payload = RFC_7519.JWT.Payload(
            exp: Date(timeIntervalSinceNow: -3600) // Expired 1 hour ago
        )
        
        #expect(throws: RFC_7519.Error.self) {
            try payload.validateTiming()
        }
    }
    
    @Test("Not yet valid token validation")
    func testNotYetValidToken() {
        let payload = RFC_7519.JWT.Payload(
            nbf: Date(timeIntervalSinceNow: 3600) // Valid in 1 hour
        )
        
        #expect(throws: RFC_7519.Error.self) {
            try payload.validateTiming()
        }
    }
    
    @Test("Clock skew tolerance")
    func testClockSkewTolerance() throws {
        let now = Date()
        let payload = RFC_7519.JWT.Payload(
            exp: Date(timeIntervalSinceNow: -30) // Expired 30 seconds ago
        )
        
        // Should not throw with 60 second clock skew (default)
        try payload.validateTiming(currentTime: now, clockSkew: 60)
        
        // Should throw with 10 second clock skew
        #expect(throws: RFC_7519.Error.self) {
            try payload.validateTiming(currentTime: now, clockSkew: 10)
        }
    }
    
    // MARK: - Base64URL Encoding Tests
    
    @Test("Base64URL encoding properties")
    func testBase64URLEncoding() {
        let testData = "Hello, World!".data(using: .utf8)!
        let encoded = testData.base64URLEncodedString()
        
        // Should not contain +, /, or = characters
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains("/"))
        #expect(!encoded.contains("="))
    }
    
    @Test("Base64URL decoding round trip")
    func testBase64URLDecoding() {
        let original = "Hello, World!"
        let data = original.data(using: .utf8)!
        let encoded = data.base64URLEncodedString()
        let decoded = Data(base64URLEncoded: encoded)
        
        #expect(decoded != nil)
        #expect(String(data: decoded!, encoding: .utf8) == original)
    }
    
    @Test("Base64URL padding handling")
    func testBase64URLPaddingHandling() {
        // Test strings that would need different amounts of padding
        let testCases = ["A", "AB", "ABC", "ABCD"]
        
        for testCase in testCases {
            let data = testCase.data(using: .utf8)!
            let encoded = data.base64URLEncodedString()
            let decoded = Data(base64URLEncoded: encoded)
            
            #expect(decoded != nil, "Failed to decode: \(encoded)")
            #expect(String(data: decoded!, encoding: .utf8) == testCase, "Round trip failed for: \(testCase)")
        }
    }
    
    // MARK: - AnyCodable Tests
    
    @Test("AnyCodable with basic types")
    func testAnyCodableWithBasicTypes() {
        let stringValue = AnyCodable("test")
        let intValue = AnyCodable(42)
        let boolValue = AnyCodable(true)
        let doubleValue = AnyCodable(3.14)
        
        #expect(stringValue.value as? String == "test")
        #expect(intValue.value as? Int == 42)
        #expect(boolValue.value as? Bool == true)
        #expect(doubleValue.value as? Double == 3.14)
    }
    
    @Test("AnyCodable coding round trip")
    func testAnyCodableCodingRoundTrip() throws {
        let original = AnyCodable("test value")
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        
        let data = try encoder.encode(original)
        let decoded = try decoder.decode(AnyCodable.self, from: data)
        
        #expect(decoded.value as? String == "test value")
    }
    
    @Test("AnyCodable equality")
    func testAnyCodableEquality() {
        let string1 = AnyCodable("test")
        let string2 = AnyCodable("test")
        let string3 = AnyCodable("different")
        
        #expect(string1 == string2)
        #expect(string1 != string3)
        
        let int1 = AnyCodable(42)
        let int2 = AnyCodable(42)
        let int3 = AnyCodable(24)
        
        #expect(int1 == int2)
        #expect(int1 != int3)
    }
    
    // MARK: - Error Tests
    
    @Test("Error localized descriptions")
    func testErrorLocalizedDescriptions() {
        let formatError = RFC_7519.Error.invalidFormat("test message")
        let expiredError = RFC_7519.Error.tokenExpired("expired at time")
        let notValidError = RFC_7519.Error.tokenNotYetValid("not valid until time")
        let signatureError = RFC_7519.Error.invalidSignature("signature mismatch")
        let algorithmError = RFC_7519.Error.unsupportedAlgorithm("unknown algorithm")
        
        #expect(formatError.localizedDescription.contains("Invalid JWT format"))
        #expect(expiredError.localizedDescription.contains("expired"))
        #expect(notValidError.localizedDescription.contains("not yet valid"))
        #expect(signatureError.localizedDescription.contains("Invalid JWT signature"))
        #expect(algorithmError.localizedDescription.contains("Unsupported algorithm"))
    }
    
    // MARK: - Edge Cases
    
    @Test("Edge case: whitespace handling in token parsing")
    func testWhitespaceHandling() throws {
        // Use a valid base64url signature
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.validBase64UrlSignature"
        let tokenWithWhitespace = "  \(token)  "
        
        // JWT parsing should handle trimming internally if needed
        let trimmedToken = tokenWithWhitespace.trimmingCharacters(in: .whitespacesAndNewlines)
        let jwt = try RFC_7519.JWT.parse(from: trimmedToken)
        #expect(jwt.payload.sub == "test")
    }
    
    @Test("Edge case: large payload handling")
    func testLargePayload() throws {
        let largeClaims = (0..<100).reduce(into: [String: Any]()) { result, index in
            result["claim_\(index)"] = "value_\(index)_" + String(repeating: "x", count: 100)
        }
        
        let payload = RFC_7519.JWT.Payload(
            sub: "test",
            additionalClaims: largeClaims
        )
        
        let header = RFC_7519.JWT.Header(alg: "HS256")
        let jwt = RFC_7519.JWT(header: header, payload: payload, signature: Data())
        
        let serialized = try jwt.compactSerialization()
        let parsed = try RFC_7519.JWT.parse(from: serialized)
        
        #expect(parsed.payload.sub == "test")
        #expect(parsed.payload.additionalClaim("claim_0", as: String.self)?.hasPrefix("value_0_") == true)
    }
    
    @Test("Edge case: minimal valid JWT")
    func testMinimalValidJWT() throws {
        let header = RFC_7519.JWT.Header(alg: "none")
        let payload = RFC_7519.JWT.Payload()
        let jwt = RFC_7519.JWT(header: header, payload: payload, signature: Data())
        
        let serialized = try jwt.compactSerialization()
        let parsed = try RFC_7519.JWT.parse(from: serialized)
        
        #expect(parsed.header.alg == "none")
        #expect(parsed.payload.sub == nil)
        #expect(parsed.payload.iss == nil)
    }
    
    @Test("Edge case: header without typ field")
    func testHeaderWithoutTyp() throws {
        let header = RFC_7519.JWT.Header(alg: "HS256", typ: nil)
        let payload = RFC_7519.JWT.Payload(sub: "test")
        let jwt = RFC_7519.JWT(header: header, payload: payload, signature: Data())
        
        let serialized = try jwt.compactSerialization()
        let parsed = try RFC_7519.JWT.parse(from: serialized)
        
        #expect(parsed.header.alg == "HS256")
        #expect(parsed.header.typ == nil)
        #expect(parsed.payload.sub == "test")
    }
}