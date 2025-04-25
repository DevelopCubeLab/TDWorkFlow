import UIKit

//@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
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
        
        let mainVC = MainViewController()
        let nav = UINavigationController(rootViewController: mainVC)
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = nav
        window?.makeKeyAndVisible()
        return true
    }
}
