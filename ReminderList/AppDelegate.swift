import UIKit

//@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        getCache() // Check for early injected dylib marker
        
        storeInstallUUID()
        if !validateInstallUUID().isValid {
            storeDetectionSecurely(flowComment: "UUID mismatch - possible app migration or tampering", severity: .low)
//            fatalError("App UUID integrity check failed.")
        }

        // Check if a suspicious dylib has been injected
        let dylibResults = WorkFlowController.performRuntimeIntegrityScan().filter { $0.key.hasPrefix("Runtime/Dylibs/") }
        for (_, flow) in dylibResults where !flow.work.isValid {
            storeDetectionSecurely(flowComment: "Suspicious dylib injection at startup", severity: .high)
            fatalError("Detected malicious injection")
        }
        
        let selfBundleIDResult = WorkFlowController.performRuntimeIntegrityScan().filter { $0.key.hasPrefix("App/BundleID") }
        for (_, flow) in selfBundleIDResult where !flow.work.isValid {
            storeDetectionSecurely(flowComment: "Bundle ID changed", severity: .high)
            fatalError("Bundle ID changed")
        }
        
        // Check for suspicious bundle files at startup
        var bundleFileResults = WorkFlowController.performRuntimeIntegrityScan().filter { $0.key.hasPrefix("Bundle/Unexpected/") || $0.key.hasPrefix("Bundle/Forbidden/") }

#if DEBUG
        bundleFileResults = bundleFileResults.filter {
            !$0.key.contains("__preview.dylib") && !$0.key.contains("ReminderList.debug.dylib")
        }
#else
        bundleFileResults = bundleFileResults.filter {
            !$0.key.contains("SC_Info")
        }
#endif
        
        for (path, flow) in bundleFileResults where !flow.work.isValid {
            storeDetectionSecurely(flowComment: "Suspicious bundle file detected at startup: \(path)", severity: .high)
            fatalError("Detected suspicious bundle file")
        }
        
        let mainVC = MainViewController()
        let nav = UINavigationController(rootViewController: mainVC)
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = nav
        window?.makeKeyAndVisible()
        return true
    }
}


private func getCache() {
    guard let cachePath = NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true).first else {
        return
    }

    let markerPath = (cachePath as NSString).appendingPathComponent(".cache")

    if FileManager.default.fileExists(atPath: markerPath) {
        do {
            let encrypted = try Data(contentsOf: URL(fileURLWithPath: markerPath))

            let k1 = "rohMem5zSjMebNV"
            let k2 = "sinwo3-sikpUz-tahpaw"
            let k3 = "K5sfIni9e6qwwXa"
            let k4 = "JH8ptLTWCoWwdQX"
            let k5 = "Mesbup-vuktaj-rizra2"
            let key = k1 + k2 + k3 + k4 + k5
            
            // Decrypt using XOR
            if let decrypted = processCache(data: encrypted, key: key),
               let plainText = String(data: decrypted, encoding: .utf8) {
                
                let lines = plainText.components(separatedBy: .newlines).filter { !$0.isEmpty }
                for line in lines {
                    let parts = line.components(separatedBy: "|")
                    guard parts.count == 2,
                          let ts = TimeInterval(parts[0]),
                          Date().timeIntervalSince1970 - ts <= 3600 * 12 else {
                        storeDetectionSecurely(flowComment: "Stale or malformed cache timestamp", severity: .medium)
                        continue
                    }
                    let detail = parts[1]
                    storeDetectionSecurely(flowComment: "EarlyScan detected suspicious dylib: \(detail)", severity: .high)
                }
            } else {
                storeDetectionSecurely(flowComment: "Cache file break", severity: .medium)
            }

            try FileManager.default.removeItem(atPath: markerPath)
        } catch {
            storeDetectionSecurely(flowComment: "Cache file break", severity: .medium)
#if DEBUG
            print("[EarlyScan] Failed to process marker file: \(error)")
#endif
        }
    }
}

private func processCache(data: Data, key: String) -> Data? {
    guard !key.isEmpty else { return nil }
    let keyBytes = Array(key.utf8)
    var result = Data()
    for (i, byte) in data.enumerated() {
        result.append(byte ^ keyBytes[i % keyBytes.count])
    }
    return result
}
