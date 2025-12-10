// swift-tools-version: 6.2

import PackageDescription

extension String {
    static let rfc7519: Self = "RFC 7519"
}

extension Target.Dependency {
    static var rfc7519: Self { .target(name: .rfc7519) }
    static var incits41986: Self { .product(name: "INCITS 4 1986", package: "swift-incits-4-1986") }
    static var standards: Self { .product(name: "Standards", package: "swift-standards") }
    static var rfc4648: Self { .product(name: "RFC 4648", package: "swift-rfc-4648") }
}

let package = Package(
    name: "swift-rfc-7519",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
    ],
    products: [
        .library(name: .rfc7519, targets: [.rfc7519])
    ],
    dependencies: [
        .package(url: "https://github.com/swift-standards/swift-incits-4-1986", from: "0.6.2"),
        .package(url: "https://github.com/swift-standards/swift-standards", from: "0.10.0"),
        .package(url: "https://github.com/swift-standards/swift-rfc-4648", from: "0.5.2"),
    ],
    targets: [
        .target(
            name: .rfc7519,
            dependencies: [
                .incits41986,
                .standards,
                .rfc4648,
            ]
        ),
        .testTarget(
            name: .rfc7519.tests,
            dependencies: [.rfc7519]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String {
    var tests: Self { self + " Tests" }
}

for target in package.targets where ![.system, .binary, .plugin].contains(target.type) {
    let existing = target.swiftSettings ?? []
    target.swiftSettings =
        existing + [
            .enableUpcomingFeature("ExistentialAny"),
            .enableUpcomingFeature("InternalImportsByDefault"),
            .enableUpcomingFeature("MemberImportVisibility"),
        ]
}
