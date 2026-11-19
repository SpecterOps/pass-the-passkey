// swift-tools-version: 6.2
import PackageDescription

// Nothing is built inside this folder. The Makefile points SwiftPM's scratch folder at the
// repository's Build/obj, and prepares libfido2, libcbor and libcrypto there as static
// libraries, so the product is one self-contained executable.
//
// The paths are absolute so that they hold whatever the working directory is. The location
// of the dependencies must match DEPS in the Makefile.
let root = Context.packageDirectory
let deps = "\(root)/../../Build/obj/phido2-macos/deps"

let package = Package(
    name: "phido2",
    // 26.4 introduced Foundation's base64url encoding options.
    platforms: [.macOS("26.4")],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-log", from: "1.6.0"),
    ],
    targets: [
        // Exposes the libfido2 and libcbor C headers to Swift as the module CFido2. The "C"
        // prefix is SwiftPM's convention for such modules, and the folder is named after it.
        .systemLibrary(name: "CFido2", path: "CFido2"),
        // The tool's sources lie directly in this folder, like those of the .NET projects.
        .executableTarget(
            name: "phido2",
            dependencies: [
                "CFido2",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: ".",
            exclude: ["CFido2", "Tests", "Makefile", "Info.plist"],
            swiftSettings: [.unsafeFlags(["-Xcc", "-I\(deps)/include"])],
            linkerSettings: [
                .unsafeFlags(["-L\(deps)/lib"]),
                // A single-file executable has no bundle, so its Info.plist is embedded.
                .unsafeFlags(["-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", "__info_plist",
                              "-Xlinker", "\(root)/Info.plist"]),
                .linkedLibrary("fido2"),
                .linkedLibrary("cbor"),
                .linkedLibrary("crypto"),
                .linkedLibrary("z"),
                .linkedFramework("IOKit"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        .testTarget(
            name: "phido2Tests",
            dependencies: ["phido2"],
            path: "Tests",
            swiftSettings: [.unsafeFlags(["-Xcc", "-I\(deps)/include"])]
        ),
    ],
    swiftLanguageModes: [.v5]
)
