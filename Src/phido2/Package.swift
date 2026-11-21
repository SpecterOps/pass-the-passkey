// swift-tools-version: 6.2
import PackageDescription

// One package, two platforms. The sources directly in this folder are shared; `macOS` and
// `Linux` hold what differs: the prompt's user interface and the way security keys are
// listened to. Each platform builds its own `phido2` executable on that platform.
//
// Nothing is built inside this folder. The Makefile points SwiftPM's scratch folder at the
// repository's Build/obj.
//
// - macOS: the Makefile prepares libfido2, libcbor and libcrypto there as static libraries,
//   so the product is one self-contained executable. The paths are absolute so that they
//   hold whatever the working directory is, and must match DEPS in the Makefile.
// - Linux: those libraries and GTK are the distribution's shared ones, found through
//   pkg-config; the Makefile links the Swift runtime statically.
let root = Context.packageDirectory
let deps = "\(root)/../../Build/obj/phido2-macos/deps"

let common: [Target.Dependency] = [
    "CFido2",
    .product(name: "ArgumentParser", package: "swift-argument-parser"),
    .product(name: "Logging", package: "swift-log"),
]
// Files in this folder that are not sources of the tool on any platform.
let notSources = ["CFido2", "CGtk", "Tests", "Makefile"]
// Chromium's artwork for the Linux prompt, and the files next to it that are not built in.
let artwork = "Linux/chromium"
let artworkNotes = ["LICENSE", "NOTICE", "passkey_usb_custom.icon", "passkey_usb_dark_custom.icon"].map { "\(artwork)/\($0)" }

#if os(macOS)
let headerSearch: [SwiftSetting] = [.unsafeFlags(["-Xcc", "-I\(deps)/include"])]
let targets: [Target] = [
    // Exposes the libfido2 and libcbor C headers to Swift as the module CFido2. The "C"
    // prefix is SwiftPM's convention for such modules, and the folder is named after it.
    .systemLibrary(name: "CFido2", path: "CFido2"),
    // The tool's sources lie directly in this folder, like those of the .NET projects.
    .executableTarget(
        name: "phido2",
        dependencies: common,
        path: ".",
        exclude: notSources + ["Linux", "macOS/Info.plist"],
        swiftSettings: headerSearch,
        linkerSettings: [
            .unsafeFlags(["-L\(deps)/lib"]),
            // A single-file executable has no bundle, so its Info.plist is embedded.
            .unsafeFlags(["-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", "__info_plist",
                          "-Xlinker", "\(root)/macOS/Info.plist"]),
            .linkedLibrary("fido2"),
            .linkedLibrary("cbor"),
            .linkedLibrary("crypto"),
            .linkedLibrary("z"),
            .linkedFramework("IOKit"),
            .linkedFramework("CoreFoundation"),
        ]
    ),
]
#else
let headerSearch: [SwiftSetting] = []
let targets: [Target] = [
    .systemLibrary(name: "CFido2", path: "CFido2", pkgConfig: "libfido2",
                   providers: [.apt(["libfido2-dev", "libcbor-dev", "libssl-dev"])]),
    // Exposes the GTK 3 C headers to Swift as the module CGtk, for the prompt's dialogs.
    .systemLibrary(name: "CGtk", path: "CGtk", pkgConfig: "gtk+-3.0",
                   providers: [.apt(["libgtk-3-dev"])]),
    .executableTarget(
        name: "phido2",
        dependencies: common + ["CGtk"],
        path: ".",
        exclude: notSources + artworkNotes + ["macOS"],
        // SwiftPM compiles these pictures into the executable as byte arrays
        // (`PackageResources.<file name>`), so the tool stays a single file. Its other kind
        // of resource is a folder that has to travel next to the executable.
        resources: ["passkey_usb.png", "passkey_usb_dark.png", "product_logo_64.png", "product_logo_128.png"]
            .map { .embedInCode("\(artwork)/\($0)") },
        linkerSettings: [
            // libfido2's pkg-config file names only itself; the tool also calls these two.
            .linkedLibrary("cbor"),
            .linkedLibrary("crypto"),
        ]
    ),
]
#endif

let package = Package(
    name: "phido2",
    // 26.4 is what the macOS prompt was written and tested on.
    platforms: [.macOS("26.4")],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-log", from: "1.6.0"),
    ],
    targets: targets + [
        .testTarget(
            name: "phido2Tests",
            dependencies: ["phido2"],
            path: "Tests",
            swiftSettings: headerSearch
        ),
    ],
    swiftLanguageModes: [.v5]
)
