import Foundation

/// Represents a file scan result used for system integrity checks.
struct Work {
    /// Indicates whether the file was detected (via any scan method).
    let isValid: Bool

    /// Time interval (in seconds) spent performing the scan.
    let duration: TimeInterval

    /// The time difference (in seconds) between now and the file's last modification date.
    /// Nil if unavailable.
    let lastModifiedDiff: TimeInterval?
}

struct WorkFlow {
    let work: Work
    let expectation: Bool
    let score: Double
}
