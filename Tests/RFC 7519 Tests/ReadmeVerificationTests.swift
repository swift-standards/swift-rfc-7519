//
//  ReadmeVerificationTests.swift
//  swift-rfc-7519
//
//  Verifies that README code examples actually work
//

import RFC_7519
import Testing

@Suite
struct `README Verification` {

    @Test
    func `README Line 48-68: Parsing and Inspecting JWTs`() throws {
        // Create a test JWT manually
        let header = RFC_7519.JWT.Header(alg: "HS256", typ: "JWT")
        let payload = RFC_7519.JWT.Payload(
            iss: "example.com",
            sub: "user123",
            exp: Date(timeIntervalSince1970: 1_730_000_000)
        )
        let jwt = RFC_7519.JWT(header: header, payload: payload, signature: Data())

        // Serialize and parse back
        let tokenString = try jwt.compactSerialization()
        let parsedJWT = try RFC_7519.JWT.parse(from: tokenString)

        // Access standard claims
        #expect(parsedJWT.payload.iss == "example.com")
        #expect(parsedJWT.payload.sub == "user123")
        #expect(parsedJWT.payload.exp?.timeIntervalSince1970 == 1_730_000_000)

        // Check header information
        #expect(parsedJWT.header.alg == "HS256")
        #expect(parsedJWT.header.typ == "JWT")
    }

    @Test
    func `README Line 72-83: Validating JWT Timing`() throws {
        // Create an expired token
        let expiredPayload = RFC_7519.JWT.Payload(
            iss: "example.com",
            sub: "user123",
            exp: Date().addingTimeInterval(-3600)
        )

        // Should throw token expired error
        #expect(throws: RFC_7519.Error.self) {
            try expiredPayload.validateTiming()
        }

        // Create a valid token
        let validPayload = RFC_7519.JWT.Payload(
            iss: "example.com",
            sub: "user123",
            exp: Date().addingTimeInterval(3600),
            nbf: Date().addingTimeInterval(-60)
        )

        // Should not throw
        try validPayload.validateTiming()
        try validPayload.validateTiming(clockSkew: 120)
    }

    @Test
    func `README Line 87-110: Creating JWTs`() throws {
        // Create JWT payload
        let payload = RFC_7519.JWT.Payload(
            iss: "example.com",
            sub: "user123",
            aud: .single("https://api.example.com"),
            exp: Date().addingTimeInterval(3600),
            iat: Date(),
            additionalClaims: ["role": "admin", "department": "engineering"]
        )

        // Create JWT header
        let header = RFC_7519.JWT.Header(
            alg: "HS256",
            typ: "JWT"
        )

        // Create JWT
        let signature = [UInt8]([0x01, 0x02, 0x03])
        let jwt = RFC_7519.JWT(header: header, payload: payload, signature: signature)

        // Serialize to string
        let tokenString = try jwt.compactSerialization()
        #expect(!tokenString.isEmpty)
        #expect(tokenString.contains("."))

        // Verify it can be parsed back
        let parsed = try RFC_7519.JWT.parse(from: tokenString)
        #expect(parsed.payload.iss == "example.com")
        #expect(parsed.payload.sub == "user123")
    }

    @Test
    func `README Line 114-137: Working with Audiences`() throws {
        // Single audience
        let payload1 = RFC_7519.JWT.Payload(
            iss: "example.com",
            sub: "user123",
            aud: .single("https://api.example.com")
        )

        // Multiple audiences
        let payload2 = RFC_7519.JWT.Payload(
            iss: "example.com",
            sub: "user123",
            aud: .multiple(["https://api.example.com", "https://admin.example.com"])
        )

        // Access audience values
        if case .single(let aud) = payload1.aud {
            #expect(aud == "https://api.example.com")
        } else {
            Issue.record("Expected single audience")
        }

        if case .multiple(let auds) = payload2.aud {
            #expect(auds.count == 2)
            #expect(auds[0] == "https://api.example.com")
            #expect(auds[1] == "https://admin.example.com")
        } else {
            Issue.record("Expected multiple audiences")
        }
    }

    @Test
    func `README Line 143-154: JWT Structure`() throws {
        let header = RFC_7519.JWT.Header(alg: "HS256")
        let payload = RFC_7519.JWT.Payload(iss: "test")
        let signature = [UInt8]([0x01, 0x02])

        let jwt = RFC_7519.JWT(header: header, payload: payload, signature: signature)

        // Test parsing
        let token = try jwt.compactSerialization()
        let parsed = try RFC_7519.JWT.parse(from: token)
        #expect(parsed.header.alg == "HS256")

        // Test signing input
        let signingInput = try jwt.signingInput()
        #expect(!signingInput.isEmpty)
    }

    @Test
    func `README Line 158-167: Header`() throws {
        let header = RFC_7519.JWT.Header(
            alg: "HS256",
            typ: "JWT",
            cty: "application/json",
            kid: "key123",
            additionalParameters: ["custom": "value"]
        )

        #expect(header.alg == "HS256")
        #expect(header.typ == "JWT")
        #expect(header.cty == "application/json")
        #expect(header.kid == "key123")

        // Test additional parameters
        let customValue = header.additionalParameter("custom", as: String.self)
        #expect(customValue == "value")
    }

    @Test
    func `README Line 171-184: Payload Claims`() throws {
        let now = Date()

        let payload = RFC_7519.JWT.Payload(
            iss: "issuer",
            sub: "subject",
            aud: .single("audience"),
            exp: now.addingTimeInterval(3600),
            nbf: now,
            iat: now,
            jti: "unique-id",
            additionalClaims: ["role": "admin"]
        )

        #expect(payload.iss == "issuer")
        #expect(payload.sub == "subject")
        #expect(payload.jti == "unique-id")

        // Test additional claims
        let role = payload.additionalClaim("role", as: String.self)
        #expect(role == "admin")

        // Test timing validation
        try payload.validateTiming()
    }

    @Test
    func `README Line 188-193: Audience Type`() throws {
        let singleAud = RFC_7519.JWT.Payload.Audience.single("api.example.com")
        let multiAud = RFC_7519.JWT.Payload.Audience.multiple(["api1.example.com", "api2.example.com"])

        // Test encoding/decoding
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let singleData = try encoder.encode(singleAud)
        let decodedSingle = try decoder.decode(RFC_7519.JWT.Payload.Audience.self, from: singleData)
        #expect(singleAud == decodedSingle)

        let multiData = try encoder.encode(multiAud)
        let decodedMulti = try decoder.decode(RFC_7519.JWT.Payload.Audience.self, from: multiData)
        #expect(multiAud == decodedMulti)
    }

    @Test
    func `README Line 197-204: Error Types`() throws {
        // Test invalid format error
        #expect(throws: RFC_7519.Error.self) {
            _ = try RFC_7519.JWT.parse(from: "invalid.token")
        }

        // Test expired token error
        let expiredPayload = RFC_7519.JWT.Payload(
            exp: Date().addingTimeInterval(-3600)
        )
        #expect(throws: RFC_7519.Error.self) {
            try expiredPayload.validateTiming()
        }

        // Test not yet valid error
        let futurePayload = RFC_7519.JWT.Payload(
            nbf: Date().addingTimeInterval(3600)
        )
        #expect(throws: RFC_7519.Error.self) {
            try futurePayload.validateTiming()
        }
    }

    @Test
    func `Additional: Custom claims type safety`() throws {
        let payload = RFC_7519.JWT.Payload(
            iss: "test",
            additionalClaims: [
                "stringValue": "hello",
                "intValue": 42,
                "boolValue": true,
                "arrayValue": [1, 2, 3],
            ]
        )

        // Test type-safe access
        #expect(payload.additionalClaim("stringValue", as: String.self) == "hello")
        #expect(payload.additionalClaim("intValue", as: Int.self) == 42)
        #expect(payload.additionalClaim("boolValue", as: Bool.self) == true)

        // Test wrong type returns nil
        #expect(payload.additionalClaim("stringValue", as: Int.self) == nil)
    }

    @Test
    func `Additional: JWT round-trip consistency`() throws {
        let originalHeader = RFC_7519.JWT.Header(
            alg: "RS256",
            typ: "JWT",
            kid: "2024-key"
        )
        let originalPayload = RFC_7519.JWT.Payload(
            iss: "https://issuer.example.com",
            sub: "1234567890",
            aud: .multiple(["https://api.example.com", "https://admin.example.com"]),
            exp: Date().addingTimeInterval(3600),
            iat: Date(),
            additionalClaims: ["scope": "read write"]
        )
        let originalSignature = [UInt8]([0xDE, 0xAD, 0xBE, 0xEF])

        let originalJWT = RFC_7519.JWT(
            header: originalHeader,
            payload: originalPayload,
            signature: originalSignature
        )

        // Serialize
        let tokenString = try originalJWT.compactSerialization()

        // Parse
        let parsedJWT = try RFC_7519.JWT.parse(from: tokenString)

        // Verify all fields match
        #expect(parsedJWT.header.alg == originalHeader.alg)
        #expect(parsedJWT.header.typ == originalHeader.typ)
        #expect(parsedJWT.header.kid == originalHeader.kid)
        #expect(parsedJWT.payload.iss == originalPayload.iss)
        #expect(parsedJWT.payload.sub == originalPayload.sub)
        #expect(parsedJWT.signature == originalSignature)
    }
}
