//
//  RFC 7519 conveniences.swift
//  swift-rfc-7519
//
//  Created by Generated on 2025-07-28.
//


// MARK: - Generic JWT Creation Interface

extension RFC_7519.JWT {
    /// Creates a signed JWT with custom configuration using a generic signing interface
    /// - Parameters:
    ///   - algorithmName: Algorithm name (e.g., "HS256", "ES256")
    ///   - issuer: Token issuer
    ///   - subject: Token subject
    ///   - audience: Token audience (optional)
    ///   - audiences: Multiple audiences (optional)
    ///   - expiresIn: Expiration time in seconds from now
    ///   - expiresAt: Specific expiration date
    ///   - notBefore: Not before time (optional)
    ///   - issuedAt: Issued at time (defaults to now)
    ///   - jti: JWT ID (optional)
    ///   - claims: Additional custom claims
    ///   - headerParameters: Additional header parameters
    ///   - signer: Function that signs the data
    /// - Throws: `Error` if creation fails
    public init(
        algorithmName: String,
        issuer: String? = nil,
        subject: String? = nil,
        audience: String? = nil,
        audiences: [String]? = nil,
        expiresIn: TimeInterval? = nil,
        expiresAt: Date? = nil,
        notBefore: Date? = nil,
        issuedAt: Date? = Date(),
        jti: String? = nil,
        claims: [String: Any] = [:],
        headerParameters: [String: Any] = [:],
        signer: (_ signingInput: Data) throws -> Data
    ) throws {
        // Determine audience
        let aud: Payload.Audience?
        if let audiences = audiences {
            aud = Payload.Audience(audiences)
        } else if let audience = audience {
            aud = .single(audience)
        } else {
            aud = nil
        }
        
        // Determine expiration
        let exp: Date?
        if let expiresAt = expiresAt {
            exp = expiresAt
        } else if let expiresIn = expiresIn {
            exp = Date(timeIntervalSinceNow: expiresIn)
        } else {
            exp = nil
        }
        
        // Create header
        let header = Header(
            alg: algorithmName,
            typ: "JWT",
            cty: nil,
            kid: nil,
            additionalParameters: headerParameters.isEmpty ? nil : headerParameters
        )
        
        // Create payload
        let payload = Payload(
            iss: issuer,
            sub: subject,
            aud: aud,
            exp: exp,
            nbf: notBefore,
            iat: issuedAt,
            jti: jti,
            additionalClaims: claims.isEmpty ? nil : claims
        )
        
        // Create JWT with empty signature first
        let unsignedJWT = RFC_7519.JWT(header: header, payload: payload, signature: Data())
        
        // Get signing input
        let signingInput = try unsignedJWT.signingInput()
        
        // Sign the data using the provided signer function
        let signature = try signer(signingInput)
        
        // Initialize self with signed JWT
        self.init(header: header, payload: payload, signature: signature)
    }
}

// MARK: - Generic JWT Verification Interface

extension RFC_7519.JWT {
    /// Verifies the JWT signature using a generic verification function
    /// - Parameter verifier: Function that verifies the signature
    /// - Returns: True if signature is valid
    /// - Throws: `Error` if verification fails
    public func verify(verifier: (_ signingInput: Data, _ signature: Data, _ algorithm: String) throws -> Bool) throws -> Bool {
        let signingInput = try self.signingInput()
        return try verifier(signingInput, signature, header.alg)
    }
    
    /// Verifies the JWT signature and validates timing claims using a generic verification function
    /// - Parameters:
    ///   - verifier: Function that verifies the signature
    ///   - currentTime: Current time for validation (defaults to now)
    ///   - clockSkew: Allowed clock skew in seconds (defaults to 60)
    /// - Returns: True if signature and timing are valid
    /// - Throws: `Error` if verification or validation fails
    public func verifyAndValidate(
        verifier: (_ signingInput: Data, _ signature: Data, _ algorithm: String) throws -> Bool,
        currentTime: Date = Date(),
        clockSkew: TimeInterval = 60
    ) throws -> Bool {
        // First verify signature
        let isValidSignature = try verify(verifier: verifier)
        guard isValidSignature else { return false }
        
        // Then validate timing
        try payload.validateTiming(currentTime: currentTime, clockSkew: clockSkew)
        
        return true
    }
}
