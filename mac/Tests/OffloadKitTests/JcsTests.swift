import Foundation
import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `JcsTests`, `ProofVectorsTests.JcsCases_MatchPython`): RFC 8785 canonical JSON of what `ProofJSON`
/// reads. Every JCS vector of `shared/proof/vectors.json` — the two with a lone surrogate too, which Windows skips
/// (System.Text.Json reads `\ud800` as U+FFFD); `ProofJSON` keeps strings as UTF-16 code units, so they survive.
final class JcsTests: XCTestCase {
    func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }

    func canonical(_ json: String) throws -> String {
        String(decoding: Jcs.serialize(try ProofJSON.parse(bytes(json))), as: UTF8.self)
    }

    func testEveryVectorOfThePythonVerifier() throws {
        let cases = try ProofVectors.jcs()
        XCTAssertGreaterThanOrEqual(cases.count, 10)
        var lone = 0
        for c in cases {
            XCTAssertEqual(Jcs.serialize(try ProofJSON.parse(bytes(c.json))), bytes(c.canonical), c.json)
            if c.canonical.range(of: #"\\u[dD][89a-fA-F][0-9a-fA-F]{2}"#, options: .regularExpression) != nil { lone += 1 }
        }
        XCTAssertEqual(lone, 2, "both lone-surrogate vectors ran")
    }

    func testObjectKeysOrderedAndEscaped() throws {
        let v: ProofJSON = .members([
            ("b", .int(2)),
            ("a", .text("\u{20AC}\n\u{1}")),
            ("c", .array([.bool(true), .bool(false), .null])),
            ("\u{20AC}", .int(1)),
            ("\r", .int(0)),
        ])
        XCTAssertEqual(String(decoding: Jcs.serialize(v), as: UTF8.self),
                       "{\"\\r\":0,\"a\":\"\u{20AC}\\n\\u0001\",\"b\":2,\"c\":[true,false,null],\"\u{20AC}\":1}")
    }

    // Review focus 1: U+1F600 is the surrogate pair D83D DE00, which sorts before U+E000 in UTF-16 (RFC 8785 §3.2.3);
    // by Unicode scalars (Swift `<`, UTF-8) U+E000 comes first.
    func testSortsByUtf16CodeUnits() throws {
        let v: ProofJSON = .members([("\u{E000}", .int(1)), ("\u{1F600}", .int(2))])
        let expected = "{\"\u{1F600}\":2,\"\u{E000}\":1}"
        XCTAssertEqual(String(decoding: Jcs.serialize(v), as: UTF8.self), expected)
        XCTAssertEqual(try canonical("{\"\\ue000\":1,\"\\ud83d\\ude00\":2}"), expected)
        XCTAssertTrue(Array("\u{E000}".utf8).lexicographicallyPrecedes(Array("\u{1F600}".utf8)), "UTF-8 order is the other one")
        XCTAssertTrue("\u{E000}".unicodeScalars.first!.value < "\u{1F600}".unicodeScalars.first!.value)
        XCTAssertEqual(try canonical("{\"\\uff5e\":1,\"\\ud83d\\ude00\":2}"), "{\"\u{1F600}\":2,\"\u{FF5E}\":1}")
    }

    // NFC "ä" (U+00E4) and NFD "a" + U+0308 are one name to Swift `==`, two keys to JSON: both stay, in UTF-16 order
    // ("a\u{308}" < "b" < "ä"), each exactly as written.
    func testNfcAndNfdKeysAreTwoKeys() throws {
        let json = "{\"\u{E4}\":1,\"b\":2,\"a\u{308}\":3}"
        let parsed = try ProofJSON.parse(bytes(json))
        XCTAssertEqual(parsed.objectMembers?.count, 3)
        XCTAssertEqual(Jcs.serialize(parsed), bytes("{\"a\u{308}\":3,\"b\":2,\"\u{E4}\":1}"))
        XCTAssertEqual(parsed["a\u{308}"]?.intValue, 3)
        XCTAssertEqual(parsed["\u{E4}"]?.intValue, 1)
    }

    func testRejectsFractionsBigIntegersDuplicateKeys() throws {
        let bad: [String] = [
            "1.5", "1.0", "-0.0", "1e5", "1E5", "1e-2", "[2.50]", "{\"size\":30.0}",
            "9007199254740992", "-9007199254740992", "[18446744073709551616]", "{\"size\":99999999999999999999999}",
            "{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}", "[{\"x\":{\"k\":true,\"k\":false}}]",
        ]
        for text in bad {
            XCTAssertThrowsError(try ProofJSON.parse(bytes(text)), text) { XCTAssertTrue($0 is ProofFormatError, "\($0)") }
        }
        XCTAssertEqual(try ProofJSON.parse(bytes("9007199254740991")), .int(9_007_199_254_740_991))
        XCTAssertEqual(try ProofJSON.parse(bytes("-9007199254740991")), .int(-9_007_199_254_740_991))
        XCTAssertEqual(try ProofJSON.parse(bytes("-0")), .int(0))
        XCTAssertEqual(try canonical("[0,-5,9007199254740991,-9007199254740991]"), "[0,-5,9007199254740991,-9007199254740991]")
        // The member's name is in the reason (the verifier's FAILED line says which field).
        XCTAssertThrowsError(try ProofJSON.parse(bytes("{\"size\":9007199254740992}"))) { e in
            XCTAssertEqual((e as? ProofFormatError)?.reason, "\"size\" is out of range (9007199254740992)")
        }
    }

    func testRejectsWhatIsNotJson() throws {
        var bad: [[UInt8]] = [
            [], bytes(" "), bytes("{"), bytes("[1,]"), bytes("{\"a\":1,}"), bytes("[01]"), bytes("-"), bytes("+1"),
            bytes("tru"), bytes("nul"), bytes("NaN"), bytes("'a'"), bytes("{a:1}"), bytes("[1] 2"), bytes("\"abc"),
            bytes("\"\\x\""), bytes("\"\\u12\""), bytes("\"\\u12g4\""), bytes("{\"a\" 1}"), bytes("[1 2]"),
        ]
        bad.append([0xEF, 0xBB, 0xBF] + bytes("{}"))          // a byte order mark
        bad.append([0x22, 0x61, 0x01, 0x22])                   // a raw control character in a string
        bad.append([0x22, 0xC3, 0x28, 0x22])                   // invalid UTF-8
        bad.append([0x22, 0xC0, 0xAF, 0x22])                   // an overlong form
        bad.append([0x22, 0xED, 0xA0, 0x80, 0x22])             // a surrogate encoded in UTF-8 (CESU-8)
        bad.append([0x22, 0xF4, 0x90, 0x80, 0x80, 0x22])       // past U+10FFFF
        bad.append([0x22, 0xE2, 0x82, 0x22])                   // a truncated sequence
        for b in bad {
            XCTAssertThrowsError(try ProofJSON.parse(b), "\(b)") { XCTAssertTrue($0 is ProofFormatError, "\($0)") }
        }
        // Whitespace around the value is fine (RFC 8259), the DEL character and U+2028 raw too.
        XCTAssertEqual(try ProofJSON.parse(bytes(" \t\r\n{ \"a\" : [ 1 , 2 ] }\n")),
                       .members([("a", .array([.int(1), .int(2)]))]))
        XCTAssertEqual(try ProofJSON.parse(bytes("\"\u{7F}\u{2028}\"")), .text("\u{7F}\u{2028}"))
    }

    func testDepthAndSizeLimits() throws {
        let deep64 = String(repeating: "[", count: 64) + String(repeating: "]", count: 64)
        XCTAssertNoThrow(try ProofJSON.parse(bytes(deep64)))
        let deep65 = String(repeating: "[", count: 65) + String(repeating: "]", count: 65)
        XCTAssertThrowsError(try ProofJSON.parse(bytes(deep65)))
        let deepObjects = String(repeating: "{\"a\":", count: 65) + "1" + String(repeating: "}", count: 65)
        XCTAssertThrowsError(try ProofJSON.parse(bytes(deepObjects)))
        let deepest = String(repeating: "[", count: 10_000)
        XCTAssertThrowsError(try ProofJSON.parse(bytes(deepest)), "deep nesting is an error, never a stack overflow")

        XCTAssertThrowsError(try ProofJSON.parse(bytes("[1,2,3]"), maxBytes: 6))
        XCTAssertNoThrow(try ProofJSON.parse(bytes("[1,2,3]"), maxBytes: 7))
        XCTAssertEqual(ProofJSON.maxBytes, 256 * 1024 * 1024, "the verifiers' manifest cap")
    }

    func testStringsKeepUtf16CodeUnits() throws {
        XCTAssertEqual(try ProofJSON.parse(bytes("\"\\ud800\"")), .string([0xD800]))
        XCTAssertEqual(try ProofJSON.parse(bytes("\"\\uD83D\\uDE00\"")), .string([0xD83D, 0xDE00]))
        XCTAssertEqual(try ProofJSON.parse(bytes("\"\u{1F600}\"")), .string([0xD83D, 0xDE00]))
        XCTAssertEqual(try ProofJSON.parse(bytes("\"\\u00e9\"")), try ProofJSON.parse(bytes("\"\u{E9}\"")))
        XCTAssertNil(ProofJSON.string([0xD800]).stringValue, "no Swift String for a lone surrogate")
        XCTAssertEqual(ProofJSON.string([0xD83D, 0xDE00]).stringValue, "\u{1F600}")
        XCTAssertEqual(try ProofJSON.parse(bytes("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"")), .string([0x22, 0x5C, 0x2F, 8, 12, 10, 13, 9]))
    }

    func testLoneSurrogateIsEscapedPairStaysLiteral() {
        XCTAssertEqual(Jcs.serialize(.string([0xD800])), bytes("\"\\ud800\""))
        XCTAssertEqual(Jcs.serialize(.string([0xDC00, 0x61])), bytes("\"\\udc00a\""))
        XCTAssertEqual(Jcs.serialize(.string([0x61, 0xDBFF])), bytes("\"a\\udbff\""))
        XCTAssertEqual(Jcs.serialize(.text("\u{1F600}")), bytes("\"\u{1F600}\""))
        XCTAssertEqual(Jcs.serialize(.string([0xD83D, 0xDE00, 0xDC00])), bytes("\"\u{1F600}\\udc00\""))
    }

    func testControlCharactersAndEscapes() {
        var units: [UInt16] = Array(0..<0x20)
        units += [0x22, 0x5C, 0x2F, 0x7F, 0x2028]
        let text = String(decoding: Jcs.serialize(.string(units)), as: UTF8.self)
        var expected = "\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f"
        expected += "\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f"
        expected += "\\\"\\\\/\u{7F}\u{2028}\""
        XCTAssertEqual(text, expected)
    }

    func testOutputIsUtf8WithoutBom() {
        let out = Jcs.serialize(.members([("k", .text("\u{161}"))]))
        XCTAssertEqual(out, bytes("{\"k\":\"\u{161}\"}"))
        XCTAssertNotEqual(out.first, 0xEF)
    }
}
