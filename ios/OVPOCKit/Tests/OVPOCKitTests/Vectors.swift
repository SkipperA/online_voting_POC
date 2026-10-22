/// Reading the repository's conformance vectors, as a second implementation.
///
/// `tests/test_vectors.py` says what this file is for: "the files were
/// generated from this code, so Python here is pinned against its own
/// future self, which is regression evidence rather than interop evidence.
/// The interop half arrives when [another] client reads the same files."
/// This is that half.
///
/// The vectors are read from `tests/vectors/` **in place**, not copied
/// into the package. A copy is a second artefact that can drift, and two
/// files that disagree about what the protocol is would be worse than
/// having only one implementation. The path is derived from `#filePath`,
/// which ties this test to its position in the repository -- deliberately.
import Foundation
import XCTest

enum Vectors {
    /// Matches `SUPPORTED_SCHEMA_VERSIONS` in `tests/test_vectors.py`.
    ///
    /// Refused rather than skipped, for the reason that file gives: a
    /// conformance suite that quietly declines to run is the exact
    /// failure the directory exists to prevent, and a version bump years
    /// from now must be loud on the day it happens.
    static let supportedSchemaVersions: Set<Int> = [1]

    static var directory: URL {
        URL(fileURLWithPath: #filePath)            // …/Tests/OVPOCKitTests/Vectors.swift
            .deletingLastPathComponent()           // …/Tests/OVPOCKitTests
            .deletingLastPathComponent()           // …/Tests
            .deletingLastPathComponent()           // …/OVPOCKit
            .deletingLastPathComponent()           // …/ios
            .deletingLastPathComponent()           // repository root
            .appendingPathComponent("tests")
            .appendingPathComponent("vectors")
    }

    static func load(_ suite: String) throws -> [String: Any] {
        let path = directory.appendingPathComponent("\(suite).json")
        guard let data = try? Data(contentsOf: path) else {
            throw Problem.missing(path.path)
        }
        guard let body = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Problem.notAnObject(suite)
        }
        let version = body["schema_version"] as? Int
        guard let version, supportedSchemaVersions.contains(version) else {
            throw Problem.unsupportedSchema(suite, version)
        }
        return body
    }

    static func cases(_ suite: String) throws -> [(name: String,
                                                   input: [String: Any],
                                                   expected: [String: Any])] {
        let body = try load(suite)
        guard let vectors = body["vectors"] as? [[String: Any]] else {
            throw Problem.notAnObject("\(suite).vectors")
        }
        return try vectors.map {
            guard let name = $0["name"] as? String,
                  let input = $0["input"] as? [String: Any],
                  let expected = $0["expected"] as? [String: Any] else {
                throw Problem.notAnObject("\(suite) vector")
            }
            return (name, input, expected)
        }
    }

    enum Problem: Error, CustomStringConvertible {
        case missing(String)
        case notAnObject(String)
        case unsupportedSchema(String, Int?)

        var description: String {
            switch self {
            case .missing(let path):
                return "missing vector file \(path); run tools/golden_vectors.py"
            case .notAnObject(let what):
                return "\(what) is not shaped as this consumer expects"
            case .unsupportedSchema(let suite, let version):
                return """
                \(suite).json declares schema_version \
                \(version.map(String.init) ?? "nil"), which this consumer does \
                not understand (supported: \(supportedSchemaVersions.sorted())). \
                Refusing rather than skipping.
                """
            }
        }
    }
}
