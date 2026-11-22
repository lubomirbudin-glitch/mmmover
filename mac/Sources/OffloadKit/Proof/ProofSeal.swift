import CryptoKit
import Foundation

/// A sealed proof: the manifest, its canonical bytes and their SHA-256 (what gets anchored), the manifest files written
/// (or already there with the same bytes) and one line per card folder where it could not be written.
public struct SealResult {
    public let manifest: ProofManifest
    public let bytes: [UInt8]
    public let digest: [UInt8]
    public let written: [String]
    public let errors: [String]

    public init(manifest: ProofManifest, bytes: [UInt8], digest: [UInt8], written: [String], errors: [String]) {
        self.manifest = manifest; self.bytes = bytes; self.digest = digest; self.written = written; self.errors = errors
    }
}

/// Plan 11 (Windows `ProofSeal`): builds the proof manifest of a finished report and writes it into `_REPORT` of every
/// card folder (never the card).
public enum ProofSeal {
    /// nil when no file qualifies (nothing to prove). Never throws for I/O: every problem is a line in `errors`.
    /// A card folder that is not there (its disk is gone) is left out; a manifest of this generation that is there
    /// already counts as written when it has the same bytes and is never replaced when it has others.
    /// `machine`: the computer's name as the ASC MHL writes it (`MHL.write`).
    public static func seal(report: OffloadReport, now: Date, machine: String = ProcessInfo.processInfo.hostName,
                            id: String? = nil) -> SealResult? {
        let generation = report.generationNumber
        var mhl: [ProofMhl] = []
        for (d, dest) in report.destinations.enumerated() {
            if let entry = mhlEntry(cardPath: dest.cardPath, generation: generation, destination: d + 1) {
                mhl.append(entry)
            }
        }
        let manifest = ProofManifest.fromReport(report, mhl: mhl, id: id ?? UUID().uuidString.lowercased(),
                                                created: now, machine: machine)
        if manifest.files.isEmpty { return nil }
        let bytes = manifest.toBytes()
        let digest = Array(SHA256.hash(data: bytes))

        let name = ProofManifest.fileName(generation: generation)
        var written: [String] = []
        var errors: [String] = []
        for dest in report.destinations {
            let reportDir = dest.cardPath + "/" + Layout.reportDirName
            let path = reportDir + "/" + name
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: dest.cardPath, isDirectory: &isDir), isDir.boolValue else { continue }
            do {
                try IO.mkdirs(reportDir)
            } catch {
                errors.append("\(path): \(error)")
                continue
            }
            do {
                try IO.writeFileNew(path, Data(bytes))
                written.append(path)
            } catch {
                guard FileManager.default.fileExists(atPath: path) else {
                    errors.append("\(path): \(error)")
                    continue
                }
                // It is there: the same bytes count as written (a second seal), other bytes are never replaced.
                guard let there = FileManager.default.contents(atPath: path) else {
                    errors.append("\(path): it is there and cannot be read")
                    continue
                }
                if [UInt8](there) == bytes {
                    written.append(path)
                } else {
                    errors.append("\(path): a different proof of generation \(generation) is there already")
                }
            }
        }
        return SealResult(manifest: manifest, bytes: bytes, digest: digest, written: written, errors: errors)
    }

    /// The generation's ASC MHL file of one card folder, from its chain (the file name has the time of the copy, so it
    /// cannot be computed); nil without a chain, without that generation, with a chain path that is no plain file name
    /// or a file that cannot be read.
    static func mhlEntry(cardPath: String, generation: Int, destination: Int) -> ProofMhl? {
        let dir = cardPath + "/" + MHL.dirName
        guard let entry = MHLReader.readChain(ascmhlDir: dir)?.first(where: { $0.seq == generation }) else { return nil }
        if entry.path.isEmpty || entry.path.contains("/") || entry.path.contains("\\") { return nil }
        guard let data = FileManager.default.contents(atPath: dir + "/" + entry.path) else { return nil }
        let hex = ProofHex.lower(Array(SHA256.hash(data: data)))
        return ProofMhl(destination: destination, path: MHL.dirName + "/" + entry.path, sha256Hex: hex)
    }
}
