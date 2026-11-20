import CryptoKit
import Foundation
import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `MerkleTests`): RFC 6962 roots of Certificate Transparency (1–8 leaves), the empty tree, audit
/// paths that verify for every leaf and fail for a changed leaf, root or path, and the leaf order of the manifest.
final class MerkleTests: XCTestCase {
    static let ctLeaves: [String] = [
        "", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f",
    ]

    static let ctRoots: [String] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ]

    func testCertificateTransparencyVectors() throws {
        var data: [[UInt8]] = []
        for leaf in MerkleTests.ctLeaves { data.append(try XCTUnwrap(ProofHex.bytes(leaf))) }
        for n in 1...8 {
            XCTAssertEqual(ProofHex.lower(Merkle.root(Array(data.prefix(n)))), MerkleTests.ctRoots[n - 1], "\(n) leaves")
        }
        XCTAssertEqual(ProofHex.lower(Merkle.root([])), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    /// The recursive MTH of RFC 6962 (split at the largest power of two below n), to check the level-by-level root.
    static func referenceRoot(_ data: [[UInt8]]) -> [UInt8] {
        if data.isEmpty { return Array(SHA256.hash(data: [UInt8]())) }
        if data.count == 1 {
            var leaf: [UInt8] = [0]
            leaf += data[0]
            return Array(SHA256.hash(data: leaf))
        }
        var k = 1
        while k * 2 < data.count { k *= 2 }
        var node: [UInt8] = [1]
        node += referenceRoot(Array(data[0..<k]))
        node += referenceRoot(Array(data[k...]))
        return Array(SHA256.hash(data: node))
    }

    static func leaves(_ n: Int) -> [[UInt8]] {
        (0..<n).map { i in withUnsafeBytes(of: Int64(i * 7919).littleEndian) { Array($0) } }
    }

    func testRootIsTheRecursiveTreeOfRfc6962() {
        for n in 0...70 {
            let data = MerkleTests.leaves(n)
            XCTAssertEqual(Merkle.root(data), MerkleTests.referenceRoot(data), "n=\(n)")
        }
    }

    func testPathVerifiesForEveryLeaf() {
        for n in 1...17 {
            let data = MerkleTests.leaves(n)
            let root = Merkle.root(data)
            for i in 0..<n {
                let path = Merkle.path(data, index: i)
                XCTAssertTrue(Merkle.verifyPath(data[i], index: i, count: n, path: path, root: root), "n=\(n) i=\(i)")

                var bad = data[i]
                bad[0] ^= 1
                XCTAssertFalse(Merkle.verifyPath(bad, index: i, count: n, path: path, root: root))
                XCTAssertFalse(Merkle.verifyPath(data[i], index: i, count: n, path: path, root: Array(SHA256.hash(data: root))))
                XCTAssertFalse(Merkle.verifyPath(data[i], index: n, count: n, path: path, root: root))
                if !path.isEmpty {
                    var flipped = path
                    flipped[flipped.count - 1][5] ^= 0x80
                    XCTAssertFalse(Merkle.verifyPath(data[i], index: i, count: n, path: flipped, root: root))
                    XCTAssertFalse(Merkle.verifyPath(data[i], index: i, count: n, path: path + [root], root: root))
                }
            }
        }
    }

    func testOrderedSortsBySha256ThenSize() {
        let a = [UInt8](repeating: 0, count: 32)
        var b = [UInt8](repeating: 0, count: 32)
        b[0] = 1
        let leaves = Merkle.ordered([(sha256: b, size: 5), (sha256: a, size: 9), (sha256: a, size: 3)])
        let expected: [[UInt8]] = [
            Merkle.leafData(sha256: a, size: 3), Merkle.leafData(sha256: a, size: 9), Merkle.leafData(sha256: b, size: 5),
        ]
        XCTAssertEqual(leaves, expected)
    }

    func testTwentyThousandLeavesUnderOneSecond() {
        let data = MerkleTests.leaves(20_000)
        let start = Date()
        let root = Merkle.root(data)
        let path = Merkle.path(data, index: 12_345)
        let seconds = Date().timeIntervalSince(start)
        XCTAssertTrue(Merkle.verifyPath(data[12_345], index: 12_345, count: 20_000, path: path, root: root))
        XCTAssertLessThan(seconds, 1.0, "\(Int(seconds * 1000)) ms")
    }
}
