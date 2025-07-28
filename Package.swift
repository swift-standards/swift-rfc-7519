// swift-tools-version:6.0

import Foundation
import PackageDescription

extension String {
    static let rfc7519: Self = "RFC_7519"
}

extension Target.Dependency {
    static var rfc7519: Self { .target(name: .rfc7519) }
}

let package = Package(
    name: "swift-rfc-7519",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: .rfc7519, targets: [.rfc7519])
    ],
    dependencies: [
        // Add RFC dependencies here as needed
        // .package(url: "https://github.com/swift-web-standards/swift-rfc-1123.git", branch: "main"),
    ],
    targets: [
        .target(
            name: .rfc7519,
            dependencies: [
                // Add target dependencies here
            ]
        ),
        .testTarget(
            name: .rfc7519.tests,
            dependencies: [
                .rfc7519
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String { var tests: Self { self + " Tests" } }
