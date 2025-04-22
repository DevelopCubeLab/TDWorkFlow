import Foundation

@_silgen_name("fileViewer")
func fileViewer(_ path: UnsafePointer<CChar>, _ timeDiff: UnsafeMutablePointer<Double>) -> Bool

class WorkUtils {
    
    func fileWork(for path: String) -> Work {
        let start = Date()

        // FileManager detection (easily hook, but still provides a perspective)
        let existsByFileManager = FileManager.default.fileExists(atPath: path)

        // Use stat to detect
        var cTimeDiff: Double = 0
        let existsByStat: Bool
        if let cPath = path.cString(using: .utf8) {
            existsByStat = fileViewer(cPath, &cTimeDiff)
        } else {
            existsByStat = false
        }

        let end = Date()
        let duration = end.timeIntervalSince(start)

        return Work(
            isValid: existsByFileManager || existsByStat,
            duration: duration,
            lastModifiedDiff: existsByStat ? cTimeDiff : nil
        )
    }
    
}


