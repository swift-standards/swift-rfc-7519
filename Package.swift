// swift-tools-version:6.2

import PackageDescription

extension String {
    static let rfc7519: Self = "RFC 7519"
}

extension Target.Dependency {
    static var rfc7519: Self { .target(name: .rfc7519) }
}

let package = Package(
    name: "swift-rfc-7519",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11)
    ],
    products: [
        .library(name: .rfc7519, targets: [.rfc7519])
    ],
    dependencies: [
        .package(url: "https://github.com/swift-standards/swift-ieee-754.git", from: "0.1.0"),
        // Add RFC dependencies here as needed
        // .package(url: "https://github.com/swift-standards/swift-rfc-1123.git", from: "0.1.0"),
    ],
    targets: [
        .target(
            name: .rfc7519,
            dependencies: [
                .product(name: "IEEE 754", package: "swift-ieee-754"),
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

extension String {
    var tests: Self { self + " Tests" }
    var foundation: Self { self + " Foundation" }
}

for target in package.targets where ![.system, .binary, .plugin].contains(target.type) {
    let existing = target.swiftSettings ?? []
    target.swiftSettings = existing + [
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility")
    ]
}
