import Foundation

/// Plan 11 (Windows `Jcs`): RFC 8785 (JSON Canonicalization Scheme) for the subset the proof manifest uses — UTF-8
/// without a byte order mark, no spaces, object keys sorted by their UTF-16 code units (not by Swift `<`, which compares
/// Unicode scalars of the canonical equivalent), strings exactly as `ProofJSON` holds them (no normalisation).
/// Strings: `\"` `\\` `\b` `\f` `\n` `\r` `\t`, any other U+0000…U+001F as `\u00xx`, a lone surrogate as `\udxxx` (lower
/// case), everything else (also U+007F, U+2028, emoji) as raw UTF-8. Integers in decimal: `ProofJSON.parse` gives
/// only ±(2^53 − 1), and `ProofManifest.toJSON` writes only checked values.
public enum Jcs {
    public static func serialize(_ value: ProofJSON) -> [UInt8] {
        var out: [UInt8] = []
        write(value, into: &out)
        return out
    }

    static let hexDigits: [UInt8] = Array("0123456789abcdef".utf8)

    static func write(_ value: ProofJSON, into out: inout [UInt8]) {
        switch value {
        case .null:
            out.append(contentsOf: [0x6E, 0x75, 0x6C, 0x6C])
        case let .bool(b):
            if b {
                out.append(contentsOf: [0x74, 0x72, 0x75, 0x65])
            } else {
                out.append(contentsOf: [0x66, 0x61, 0x6C, 0x73, 0x65])
            }
        case let .int(n):
            out.append(contentsOf: Array(String(n).utf8))
        case let .string(units):
            writeString(units, into: &out)
        case let .array(items):
            out.append(0x5B)
            for (i, item) in items.enumerated() {
                if i > 0 { out.append(0x2C) }
                write(item, into: &out)
            }
            out.append(0x5D)
        case let .object(members):
            let sorted = members.sorted { a, b in a.0.lexicographicallyPrecedes(b.0) }
            out.append(0x7B)
            for (i, member) in sorted.enumerated() {
                if i > 0 { out.append(0x2C) }
                writeString(member.0, into: &out)
                out.append(0x3A)
                write(member.1, into: &out)
            }
            out.append(0x7D)
        }
    }

    static func writeEscape(_ unit: UInt16, into out: inout [UInt8]) {
        out.append(0x5C)
        out.append(0x75)
        out.append(hexDigits[Int((unit >> 12) & 0xF)])
        out.append(hexDigits[Int((unit >> 8) & 0xF)])
        out.append(hexDigits[Int((unit >> 4) & 0xF)])
        out.append(hexDigits[Int(unit & 0xF)])
    }

    static func writeScalar(_ scalar: UInt32, into out: inout [UInt8]) {
        if scalar < 0x80 {
            out.append(UInt8(scalar))
        } else if scalar < 0x800 {
            out.append(UInt8(0xC0 | (scalar >> 6)))
            out.append(UInt8(0x80 | (scalar & 0x3F)))
        } else if scalar < 0x10000 {
            out.append(UInt8(0xE0 | (scalar >> 12)))
            out.append(UInt8(0x80 | ((scalar >> 6) & 0x3F)))
            out.append(UInt8(0x80 | (scalar & 0x3F)))
        } else {
            out.append(UInt8(0xF0 | (scalar >> 18)))
            out.append(UInt8(0x80 | ((scalar >> 12) & 0x3F)))
            out.append(UInt8(0x80 | ((scalar >> 6) & 0x3F)))
            out.append(UInt8(0x80 | (scalar & 0x3F)))
        }
    }

    static func isHigh(_ u: UInt16) -> Bool { u >= 0xD800 && u <= 0xDBFF }
    static func isLow(_ u: UInt16) -> Bool { u >= 0xDC00 && u <= 0xDFFF }

    static func writeString(_ units: [UInt16], into out: inout [UInt8]) {
        out.append(0x22)
        var i = 0
        while i < units.count {
            let c = units[i]
            switch c {
            case 0x22: out.append(contentsOf: [0x5C, 0x22])
            case 0x5C: out.append(contentsOf: [0x5C, 0x5C])
            case 0x08: out.append(contentsOf: [0x5C, 0x62])
            case 0x0C: out.append(contentsOf: [0x5C, 0x66])
            case 0x0A: out.append(contentsOf: [0x5C, 0x6E])
            case 0x0D: out.append(contentsOf: [0x5C, 0x72])
            case 0x09: out.append(contentsOf: [0x5C, 0x74])
            default:
                if c < 0x20 {
                    writeEscape(c, into: &out)
                } else if isHigh(c) && i + 1 < units.count && isLow(units[i + 1]) {
                    let high = UInt32(c - 0xD800)
                    let low = UInt32(units[i + 1] - 0xDC00)
                    writeScalar(0x10000 + (high << 10) + low, into: &out)
                    i += 1
                } else if isHigh(c) || isLow(c) {
                    writeEscape(c, into: &out)
                } else {
                    writeScalar(UInt32(c), into: &out)
                }
            }
            i += 1
        }
        out.append(0x22)
    }
}
