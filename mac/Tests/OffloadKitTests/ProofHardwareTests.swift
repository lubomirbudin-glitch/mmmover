import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `ProofHardwareTests`, final fix A1, ruling R12): SHA-256 in hardware or not — what the proof's default
/// and the settings' rate note are made from.
final class ProofHardwareTests: XCTestCase {
    // The Mac's own answer, and the test seam over it (restored by the closure it returns).
    func testDetectionDoesNotCrashAndForceOverrides() {
        let detected = ProofHardware.hasShaInstructions
        #if arch(arm64)
        XCTAssertTrue(detected, "every Apple Silicon has the SHA-256 instructions")
        #endif
        XCTAssertEqual(ProofHardware.detect(), detected)

        let restore = ProofHardware.force(hasSha: !detected, mbps: 437)
        XCTAssertEqual(ProofHardware.hasShaInstructions, !detected)
        XCTAssertEqual(ProofHardware.measureSha256MBps(), 437)
        let inner = ProofHardware.force(hasSha: detected)
        XCTAssertEqual(ProofHardware.hasShaInstructions, detected)
        inner()
        XCTAssertEqual(ProofHardware.hasShaInstructions, !detected, "a restore brings back what was forced before it")
        XCTAssertEqual(ProofHardware.measureSha256MBps(), 437)
        restore()
        XCTAssertEqual(ProofHardware.hasShaInstructions, detected)

        // x86_64: the word SHA among the CPUID leaf 7 features (machdep.cpu.leaf7_features).
        XCTAssertTrue(ProofHardware.leaf7HasSha("RDWRFSGS TSC_THREAD_OFFSET BMI1 AVX2 SMEP SHA BMI2 ERMS"))
        XCTAssertTrue(ProofHardware.leaf7HasSha("SHA"))
        XCTAssertFalse(ProofHardware.leaf7HasSha("RDWRFSGS TSC_THREAD_OFFSET SGX BMI1 HLE AVX2 SMEP BMI2 ERMS"))
        XCTAssertFalse(ProofHardware.leaf7HasSha("AVX512F SHA512 AVX2"))
        XCTAssertFalse(ProofHardware.leaf7HasSha(""))
        XCTAssertNil(ProofHardware.sysctlFlag("hw.optional.no.such.key"))
        XCTAssertNil(ProofHardware.sysctlText("machdep.no.such.key"))
    }

    // A positive rate of hashing 64 MB, measured once and then kept — off the main thread, as the app calls it.
    func testMeasureIsPositiveAndCached() {
        let done = expectation(description: "measured")
        var rates: [Double] = []
        DispatchQueue.global().async {
            rates = [ProofHardware.measureSha256MBps(), ProofHardware.measureSha256MBps()]
            done.fulfill()
        }
        wait(for: [done], timeout: 120)
        XCTAssertEqual(rates.count, 2)
        guard rates.count == 2 else { return }
        XCTAssertTrue(rates[0] > 0 && rates[0].isFinite, "\(rates)")
        XCTAssertEqual(rates[0], rates[1], "measured once, then kept")
        let again = ProofHardware.measure()
        XCTAssertTrue(again > 0 && again.isFinite, "\(again)")
    }
}
