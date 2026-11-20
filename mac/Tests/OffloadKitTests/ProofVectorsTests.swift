import CryptoKit
import Foundation
import XCTest
@testable import OffloadKit

/// `shared/proof/vectors.json` — made by the independent Python verifier (`verify_proof.py --make-vectors`, written from
/// the format specification): the Merkle roots and canonical JSON this implementation must reproduce byte for byte.
/// Read with JSONSerialization (not the parser under test); found by walking up from this file.
enum ProofVectors {
    struct JcsCase {
        let json: String
        let canonical: String
    }

    static func sharedProof() throws -> String {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("shared/proof")
            if FileManager.default.fileExists(atPath: p.appendingPathComponent("vectors.json").path) { return p.path }
            dir = dir.deletingLastPathComponent()
        }
        throw XCTSkip("shared/proof/vectors.json was not found above \(#filePath)")
    }

    static func all() throws -> [String: Any] {
        let data = try Data(contentsOf: URL(fileURLWithPath: try sharedProof() + "/vectors.json"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    static func cases(_ key: String) throws -> [[String: Any]] {
        try XCTUnwrap(try all()[key] as? [[String: Any]], key)
    }

    static func jcs() throws -> [JcsCase] {
        var out: [JcsCase] = []
        for c in try cases("jcs") {
            out.append(JcsCase(json: try XCTUnwrap(c["json"] as? String), canonical: try XCTUnwrap(c["canonical"] as? String)))
        }
        return out
    }

    static func hex(_ s: String) throws -> [UInt8] { try XCTUnwrap(ProofHex.bytes(s), s) }

    static func int(_ v: Any?) throws -> Int64 { try XCTUnwrap(v as? NSNumber).int64Value }
}

/// Plan 11 (Windows `ProofVectorsTests`): the vectors of the Python verifier, and that verifier accepting what this one
/// seals.
final class ProofVectorsTests: XCTestCase {
    func testMerkleRootsMatchPython() throws {
        let cases = try ProofVectors.cases("merkle")
        XCTAssertEqual(try cases.map { try ProofVectors.int($0["count"]) }, [0, 1, 2, 3, 2001])
        for c in cases {
            let leaves = try XCTUnwrap(c["leaves"] as? [[String: Any]])
            var files: [(sha256: [UInt8], size: Int64)] = []
            for l in leaves {
                let sha = try ProofVectors.hex(try XCTUnwrap(l["sha256"] as? String))
                files.append((sha256: sha, size: try ProofVectors.int(l["size"])))
            }
            XCTAssertEqual(Int64(files.count), try ProofVectors.int(c["count"]))
            XCTAssertEqual(ProofHex.lower(Merkle.root(Merkle.ordered(files))), c["root"] as? String, "\(files.count) leaves")
        }
        // leaf i = SHA-256 of the ASCII decimal i, size i * 1000 + 7
        let last = try XCTUnwrap(cases[4]["leaves"] as? [[String: Any]])[1234]
        XCTAssertEqual(last["sha256"] as? String, ProofHex.lower(Array(SHA256.hash(data: Data("1234".utf8)))))
        XCTAssertEqual(try ProofVectors.int(last["size"]), 1_234_007)
    }

    func testLeafDataIsSha256ThenSizeBigEndian() {
        let sha = Array(SHA256.hash(data: Data("7".utf8)))
        let d = Merkle.leafData(sha256: sha, size: 7007)
        XCTAssertEqual(d.count, 40)
        XCTAssertEqual(Array(d[0..<32]), sha)
        XCTAssertEqual(Array(d[32...]), [0, 0, 0, 0, 0, 0, 0x1B, 0x5F])
    }

    func testCertificateTransparencyRootsMatchPython() throws {
        let cases = try ProofVectors.cases("ct")
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            let data = try XCTUnwrap(c["data"] as? [String]).map { try ProofVectors.hex($0) }
            XCTAssertEqual(Int64(data.count), try ProofVectors.int(c["count"]))
            XCTAssertEqual(ProofHex.lower(Merkle.root(data)), c["root"] as? String, "\(data.count) leaves")
        }
    }

    /// `python3` that runs (3.8 or later), or nil.
    static func python() -> String? {
        for candidate in ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
        where FileManager.default.isExecutableFile(atPath: candidate) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: candidate)
            p.arguments = ["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"]
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            do {
                try p.run()
                p.waitUntilExit()
                if p.terminationStatus == 0 { return candidate }
            } catch {
                continue
            }
        }
        return nil
    }

    /// The other way round (Windows `Python_VerifiesACardFolderMadeByCSharp`): `verify_proof.py` reads a card folder this
    /// version sealed — it recomputes the canonical bytes and the Merkle root and agrees. No `.ots` yet (that is M3):
    /// NOT YET, exit 2.
    func testPythonVerifiesACardFolderSealedBySwift() throws {
        guard let python = ProofVectorsTests.python() else { throw XCTSkip("no python3 here: the vectors above still ran") }
        let script = try ProofVectors.sharedProof() + "/verify_proof.py"
        let dir = tempDir()
        let c1 = dir.sub("d1", "2026-11-20", "A001")
        let c2 = dir.sub("d2", "2026-11-20", "A001")
        var files: [OffloadReport.FileEntry] = []
        let names = ["CLIP/A.mov", "CLIP/\u{17D}lu\u{165}ou\u{10D}k\u{FD}.mov", "CLIP/a\u{308}.wav", "z.bin"]
        for (i, name) in names.enumerated() {
            let size = i == 3 ? 0 : 1000 + i
            let data = TestFS.writeRandom(c1 + "/" + name, size: size, seed: UInt64(i + 1))
            TestFS.writeRandom(c2 + "/" + name, size: size, seed: UInt64(i + 1))
            let sha = ProofHex.lower(Array(SHA256.hash(data: data)))
            files.append(ProofManifestTests.entry(name, Int64(data.count), sha))
        }
        let report = ProofManifestTests.report(c1, c2, files)
        try MHL.write(report: report, cardPath: c1, now: Date(), host: "mac")
        try MHL.write(report: report, cardPath: c2, now: Date(), host: "mac")
        let seal = try XCTUnwrap(ProofSeal.seal(report: report, now: Date(), machine: "Mac"))
        XCTAssertEqual(seal.written.count, 2)

        let target = c1 + "/" + names[1]
        let p = Process()
        p.executableURL = URL(fileURLWithPath: python)
        p.arguments = ["-I", script, target, "--offline"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)

        XCTAssertEqual(p.terminationStatus, 2, text)
        let lines = text.components(separatedBy: "\n")
        let hex = try XCTUnwrap(files.first { $0.path == names[1] }?.sha256)
        XCTAssertTrue(lines.contains { $0.hasPrefix("SHA-256:") && $0.contains(hex) }, text)
        // Python recomputed the Merkle root and the canonical bytes of what Swift sealed, and agrees.
        XCTAssertTrue(lines.contains { $0.contains("Merkle root OK") }, text)
        XCTAssertTrue(lines.contains { $0.hasPrefix("RESULT:    NOT YET") }, text)
        XCTAssertFalse(text.lowercased().contains("authentic"), text)
    }
}
