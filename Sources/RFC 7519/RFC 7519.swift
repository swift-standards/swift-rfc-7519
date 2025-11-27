//
//  RFC 7519.swift
//  swift-rfc-7519
//
//  Created by Generated on 2025-07-28.
//


/// Implementation of RFC 7519: JSON Web Token (JWT)
/// 
/// See: https://www.rfc-editor.org/rfc/rfc7519.html
public enum RFC_7519 {
    /// Represents a JSON Web Token according to RFC 7519
    public struct JWT: Codable, Hashable, Sendable {
        public let header: Header
        public let payload: Payload
        public let signature: Data
        
        /// Original base64url encoded strings for efficient signing input
        private let headerBase64URL: String?
        private let payloadBase64URL: String?
        
        /// Creates a JWT from its components
        /// - Parameters:
        ///   - header: The JWT header
        ///   - payload: The JWT payload (claims)
        ///   - signature: The signature bytes
        public init(header: Header, payload: Payload, signature: Data) {
            self.header = header
            self.payload = payload
            self.signature = signature
            self.headerBase64URL = nil
            self.payloadBase64URL = nil
        }
        
        /// Creates a JWT from its components with original base64url strings
        /// - Parameters:
        ///   - header: The JWT header
        ///   - payload: The JWT payload (claims)
        ///   - signature: The signature bytes
        ///   - headerBase64URL: Original base64url encoded header string
        ///   - payloadBase64URL: Original base64url encoded payload string
        private init(header: Header, payload: Payload, signature: Data, headerBase64URL: String, payloadBase64URL: String) {
            self.header = header
            self.payload = payload
            self.signature = signature
            self.headerBase64URL = headerBase64URL
            self.payloadBase64URL = payloadBase64URL
        }
        
        /// Parses a JWT from its compact serialization format
        /// - Parameter token: The JWT string in format "header.payload.signature"
        /// - Returns: Parsed JWT
        /// - Throws: `Error` for invalid format or malformed components
        public static func parse(from token: String) throws -> JWT {
            let components = token.components(separatedBy: ".")
            guard components.count == 3 else {
                throw Error.invalidFormat("JWT must have exactly 3 parts separated by dots")
            }
            
            // Decode header
            guard let headerData = Data(base64URLEncoded: components[0]) else {
                throw Error.invalidFormat("Invalid base64url encoding in header")
            }
            
            let header: Header
            do {
                header = try JSONDecoder().decode(Header.self, from: headerData)
            } catch {
                throw Error.invalidFormat("Invalid JSON in header: \(error.localizedDescription)")
            }
            
            // Decode payload
            guard let payloadData = Data(base64URLEncoded: components[1]) else {
                throw Error.invalidFormat("Invalid base64url encoding in payload")
            }
            
            let payload: Payload
            do {
                payload = try JSONDecoder().decode(Payload.self, from: payloadData)
            } catch {
                throw Error.invalidFormat("Invalid JSON in payload: \(error.localizedDescription)")
            }
            
            // Decode signature
            guard let signature = Data(base64URLEncoded: components[2]) else {
                throw Error.invalidFormat("Invalid base64url encoding in signature")
            }
            
            return JWT(header: header, payload: payload, signature: signature, headerBase64URL: components[0], payloadBase64URL: components[1])
        }
        
        /// Serializes the JWT to its compact format
        /// - Returns: JWT string in format "header.payload.signature"
        /// - Throws: `Error` if encoding fails
        public func compactSerialization() throws -> String {
            let headerBase64: String
            let payloadBase64: String
            
            // Use original base64url strings if available for efficiency and consistency
            if let originalHeaderBase64 = headerBase64URL, let originalPayloadBase64 = payloadBase64URL {
                headerBase64 = originalHeaderBase64
                payloadBase64 = originalPayloadBase64
            } else {
                // Fallback to re-encoding if original strings are not available
                let encoder = JSONEncoder()
                encoder.outputFormatting = .sortedKeys
                
                let headerData = try encoder.encode(header)
                let payloadData = try encoder.encode(payload)
                
                headerBase64 = headerData.base64URLEncodedString()
                payloadBase64 = payloadData.base64URLEncodedString()
            }
            
            let signatureBase64 = signature.base64URLEncodedString()
            
            return "\(headerBase64).\(payloadBase64).\(signatureBase64)"
        }
        
        /// Gets the signing input (header.payload) for signature verification
        /// - Returns: The data to be signed/verified
        /// - Throws: `Error` if encoding fails
        public func signingInput() throws -> Data {
            // Use original base64url strings if available for efficiency
            if let headerBase64 = headerBase64URL, let payloadBase64 = payloadBase64URL {
                return "\(headerBase64).\(payloadBase64)".data(using: .ascii)!
            }
            
            // Fallback to re-encoding if original strings are not available
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            
            let headerData = try encoder.encode(header)
            let payloadData = try encoder.encode(payload)
            
            let headerBase64 = headerData.base64URLEncodedString()
            let payloadBase64 = payloadData.base64URLEncodedString()
            
            return "\(headerBase64).\(payloadBase64)".data(using: .ascii)!
        }
    }
}

// MARK: - JWT Header

extension RFC_7519.JWT {
    /// JWT Header as defined in RFC 7519
    public struct Header: Codable, Hashable, Sendable {
        /// Token type - typically "JWT"
        public let typ: String?
        
        /// Algorithm used to sign the JWT
        public let alg: String
        
        /// Content type - used when nested JWTs are employed
        public let cty: String?
        
        /// Key ID - hint indicating which key was used to secure the JWT
        public let kid: String?
        
        /// Additional header parameters
        private let additionalParameters: [String: AnyCodable]?
        
        /// Creates a JWT header
        /// - Parameters:
        ///   - alg: The algorithm used to sign the JWT (required)
        ///   - typ: The token type (optional, typically "JWT")
        ///   - cty: The content type (optional)
        ///   - kid: The key ID (optional)
        ///   - additionalParameters: Additional header parameters
        public init(
            alg: String,
            typ: String? = "JWT",
            cty: String? = nil,
            kid: String? = nil,
            additionalParameters: [String: Any]? = nil
        ) {
            self.alg = alg
            self.typ = typ
            self.cty = cty
            self.kid = kid
            self.additionalParameters = additionalParameters?.mapValues(AnyCodable.init)
        }
        
        /// Gets additional parameter value
        /// - Parameter key: Parameter name
        /// - Returns: Parameter value if present
        public func additionalParameter<T>(_ key: String, as type: T.Type) -> T? {
            return additionalParameters?[key]?.value as? T
        }
        
        private enum CodingKeys: String, CodingKey, CaseIterable {
            case typ, alg, cty, kid
        }
        
        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)
            
            self.typ = try container.decodeIfPresent(String.self, forKey: .typ)
            self.alg = try container.decode(String.self, forKey: .alg)
            self.cty = try container.decodeIfPresent(String.self, forKey: .cty)
            self.kid = try container.decodeIfPresent(String.self, forKey: .kid)
            
            // Decode additional parameters
            var additional: [String: AnyCodable] = [:]
            for key in dynamicContainer.allKeys {
                if !CodingKeys.allCases.map({ $0.stringValue }).contains(key.stringValue) {
                    additional[key.stringValue] = try dynamicContainer.decode(AnyCodable.self, forKey: key)
                }
            }
            self.additionalParameters = additional.isEmpty ? nil : additional
        }
        
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            var dynamicContainer = encoder.container(keyedBy: DynamicCodingKey.self)
            
            try container.encodeIfPresent(typ, forKey: .typ)
            try container.encode(alg, forKey: .alg)
            try container.encodeIfPresent(cty, forKey: .cty)
            try container.encodeIfPresent(kid, forKey: .kid)
            
            // Encode additional parameters
            if let additionalParameters = additionalParameters {
                for (key, value) in additionalParameters {
                    let codingKey = DynamicCodingKey(stringValue: key)!
                    try dynamicContainer.encode(value, forKey: codingKey)
                }
            }
        }
    }
}

// MARK: - JWT Payload (Claims)

extension RFC_7519.JWT {
    /// JWT Payload containing claims as defined in RFC 7519
    public struct Payload: Codable, Hashable, Sendable {
        // Registered claim names (RFC 7519 Section 4.1)
        
        /// Issuer - identifies the principal that issued the JWT
        public let iss: String?
        
        /// Subject - identifies the principal that is the subject of the JWT
        public let sub: String?
        
        /// Audience - identifies the recipients that the JWT is intended for
        public let aud: Audience?
        
        /// Expiration Time - identifies the expiration time after which the JWT must not be accepted
        public let exp: Date?
        
        /// Not Before - identifies the time before which the JWT must not be accepted
        public let nbf: Date?
        
        /// Issued At - identifies the time at which the JWT was issued
        public let iat: Date?
        
        /// JWT ID - provides a unique identifier for the JWT
        public let jti: String?
        
        /// Additional claims
        private let additionalClaims: [String: AnyCodable]?
        
        /// Creates a JWT payload
        /// - Parameters:
        ///   - iss: Issuer
        ///   - sub: Subject
        ///   - aud: Audience (string or array of strings)
        ///   - exp: Expiration time
        ///   - nbf: Not before time
        ///   - iat: Issued at time
        ///   - jti: JWT ID
        ///   - additionalClaims: Additional custom claims
        public init(
            iss: String? = nil,
            sub: String? = nil,
            aud: Audience? = nil,
            exp: Date? = nil,
            nbf: Date? = nil,
            iat: Date? = nil,
            jti: String? = nil,
            additionalClaims: [String: Any]? = nil
        ) {
            self.iss = iss
            self.sub = sub
            self.aud = aud
            self.exp = exp
            self.nbf = nbf
            self.iat = iat
            self.jti = jti
            self.additionalClaims = additionalClaims?.mapValues(AnyCodable.init)
        }
        
        /// Gets additional claim value
        /// - Parameter key: Claim name
        /// - Returns: Claim value if present
        public func additionalClaim<T>(_ key: String, as type: T.Type) -> T? {
            return additionalClaims?[key]?.value as? T
        }
        
        /// Validates the token timing claims
        /// - Parameters:
        ///   - currentTime: Current time to validate against (defaults to now)
        ///   - clockSkew: Allowed clock skew in seconds (defaults to 60)
        /// - Throws: `Error.tokenExpired` or `Error.tokenNotYetValid`
        public func validateTiming(currentTime: Date = Date(), clockSkew: TimeInterval = 60) throws {
            if let exp = exp, currentTime.timeIntervalSince1970 > exp.timeIntervalSince1970 + clockSkew {
                throw RFC_7519.Error.tokenExpired("Token expired at \(exp)")
            }
            
            if let nbf = nbf, currentTime.timeIntervalSince1970 < nbf.timeIntervalSince1970 - clockSkew {
                throw RFC_7519.Error.tokenNotYetValid("Token not valid before \(nbf)")
            }
        }
        
        private enum CodingKeys: String, CodingKey, CaseIterable {
            case iss, sub, aud, exp, nbf, iat, jti
        }
        
        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)
            
            self.iss = try container.decodeIfPresent(String.self, forKey: .iss)
            self.sub = try container.decodeIfPresent(String.self, forKey: .sub)
            self.aud = try container.decodeIfPresent(Audience.self, forKey: .aud)
            
            // Decode Unix timestamps as Dates
            if let expTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .exp) {
                self.exp = Date(timeIntervalSince1970: expTimestamp)
            } else {
                self.exp = nil
            }
            
            if let nbfTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .nbf) {
                self.nbf = Date(timeIntervalSince1970: nbfTimestamp)
            } else {
                self.nbf = nil
            }
            
            if let iatTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .iat) {
                self.iat = Date(timeIntervalSince1970: iatTimestamp)
            } else {
                self.iat = nil
            }
            
            self.jti = try container.decodeIfPresent(String.self, forKey: .jti)
            
            // Decode additional claims
            var additional: [String: AnyCodable] = [:]
            for key in dynamicContainer.allKeys {
                if !CodingKeys.allCases.map({ $0.stringValue }).contains(key.stringValue) {
                    additional[key.stringValue] = try dynamicContainer.decode(AnyCodable.self, forKey: key)
                }
            }
            self.additionalClaims = additional.isEmpty ? nil : additional
        }
        
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            var dynamicContainer = encoder.container(keyedBy: DynamicCodingKey.self)
            
            try container.encodeIfPresent(iss, forKey: .iss)
            try container.encodeIfPresent(sub, forKey: .sub)
            try container.encodeIfPresent(aud, forKey: .aud)
            
            // Encode Dates as Unix timestamps
            if let exp = exp {
                try container.encode(exp.timeIntervalSince1970, forKey: .exp)
            }
            if let nbf = nbf {
                try container.encode(nbf.timeIntervalSince1970, forKey: .nbf)
            }
            if let iat = iat {
                try container.encode(iat.timeIntervalSince1970, forKey: .iat)
            }
            
            try container.encodeIfPresent(jti, forKey: .jti)
            
            // Encode additional claims
            if let additionalClaims = additionalClaims {
                for (key, value) in additionalClaims {
                    let codingKey = DynamicCodingKey(stringValue: key)!
                    try dynamicContainer.encode(value, forKey: codingKey)
                }
            }
        }
    }
}

// MARK: - Audience Type

extension RFC_7519.JWT.Payload {
    /// Represents the audience claim which can be a string or array of strings
    public enum Audience: Codable, Hashable, Sendable {
        case single(String)
        case multiple([String])
        
        /// Creates audience from a single string
        /// - Parameter audience: Single audience string
        public init(_ audience: String) {
            self = .single(audience)
        }
        
        /// Creates audience from multiple strings
        /// - Parameter audiences: Array of audience strings
        public init(_ audiences: [String]) {
            if audiences.count == 1 {
                self = .single(audiences[0])
            } else {
                self = .multiple(audiences)
            }
        }
        
        /// Returns all audience values as an array
        public var values: [String] {
            switch self {
            case .single(let audience):
                return [audience]
            case .multiple(let audiences):
                return audiences
            }
        }
        
        /// Checks if the audience contains a specific value
        /// - Parameter audience: Audience to check for
        /// - Returns: True if the audience is present
        public func contains(_ audience: String) -> Bool {
            return values.contains(audience)
        }
        
        public init(from decoder: any Decoder) throws {
            let container = try decoder.singleValueContainer()
            
            if let single = try? container.decode(String.self) {
                self = .single(single)
            } else if let multiple = try? container.decode([String].self) {
                self = .multiple(multiple)
            } else {
                throw DecodingError.typeMismatch(
                    Audience.self,
                    DecodingError.Context(
                        codingPath: decoder.codingPath,
                        debugDescription: "Audience must be a string or array of strings"
                    )
                )
            }
        }
        
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.singleValueContainer()
            
            switch self {
            case .single(let audience):
                try container.encode(audience)
            case .multiple(let audiences):
                try container.encode(audiences)
            }
        }
    }
}

// MARK: - Error Handling

extension RFC_7519 {
    /// Errors that can occur during JWT operations
    public enum Error: Swift.Error, Codable, Hashable, Sendable {
        case invalidFormat(String)
        case tokenExpired(String)
        case tokenNotYetValid(String)
        case invalidSignature(String)
        case unsupportedAlgorithm(String)
        
        public var localizedDescription: String {
            switch self {
            case .invalidFormat(let message):
                return "Invalid JWT format: \(message)"
            case .tokenExpired(let message):
                return "JWT token expired: \(message)"
            case .tokenNotYetValid(let message):
                return "JWT token not yet valid: \(message)"
            case .invalidSignature(let message):
                return "Invalid JWT signature: \(message)"
            case .unsupportedAlgorithm(let message):
                return "Unsupported algorithm: \(message)"
            }
        }
    }
}

// MARK: - Utility Types

/// Type-erased codable value for additional parameters/claims
public enum AnyCodable: Codable, Hashable, Sendable {
    case string(String)
    case integer(Int)
    case double(Double)
    case bool(Bool)
    case array([AnyCodable])
    case dictionary([String: AnyCodable])
    
    public init(_ value: Any) {
        switch value {
        case let string as String:
            self = .string(string)
        case let int as Int:
            self = .integer(int)
        case let double as Double:
            self = .double(double)
        case let bool as Bool:
            self = .bool(bool)
        case let array as [Any]:
            self = .array(array.map(AnyCodable.init))
        case let dictionary as [String: Any]:
            self = .dictionary(dictionary.mapValues(AnyCodable.init))
        default:
            // Fallback to string representation
            self = .string(String(describing: value))
        }
    }
    
    public var value: Any {
        switch self {
        case .string(let string):
            return string
        case .integer(let int):
            return int
        case .double(let double):
            return double
        case .bool(let bool):
            return bool
        case .array(let array):
            return array.map(\.value)
        case .dictionary(let dictionary):
            return dictionary.mapValues(\.value)
        }
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let int = try? container.decode(Int.self) {
            self = .integer(int)
        } else if let double = try? container.decode(Double.self) {
            self = .double(double)
        } else if let bool = try? container.decode(Bool.self) {
            self = .bool(bool)
        } else if let array = try? container.decode([AnyCodable].self) {
            self = .array(array)
        } else if let dictionary = try? container.decode([String: AnyCodable].self) {
            self = .dictionary(dictionary)
        } else {
            throw DecodingError.typeMismatch(
                AnyCodable.self,
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Unsupported type")
            )
        }
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        
        switch self {
        case .string(let string):
            try container.encode(string)
        case .integer(let int):
            try container.encode(int)
        case .double(let double):
            try container.encode(double)
        case .bool(let bool):
            try container.encode(bool)
        case .array(let array):
            try container.encode(array)
        case .dictionary(let dictionary):
            try container.encode(dictionary)
        }
    }
}

/// Dynamic coding key for encoding/decoding additional parameters
struct DynamicCodingKey: CodingKey {
    var stringValue: String
    var intValue: Int?
    
    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }
    
    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

// MARK: - Base64URL Encoding

extension Data {
    /// Encodes data as base64url string (RFC 4648 Section 5)
    /// - Returns: Base64url encoded string
    func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacing("+", with: "-")
            .replacing("/", with: "_")
            .replacing("=", with: "")
    }
    
    /// Creates data from base64url encoded string
    /// - Parameter string: Base64url encoded string
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacing("-", with: "+")
            .replacing("_", with: "/")
        
        // Add padding if needed
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        
        self.init(base64Encoded: base64)
    }
}


