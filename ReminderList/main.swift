import Foundation
import UIKit

// Detection dylibs
let dylibResults = WorkFlowController.performRuntimeIntegrityScan()
    .filter { $0.key.hasPrefix("Runtime/Dylibs/") && !$0.value.work.isValid }

if !dylibResults.isEmpty {
    storeDetectionSecurely(flowComment: "Detected dylib injection in main.swift", severity: .high)
    fatalError("Dylib injection detected at earliest stage")
}

UIApplicationMain(
    CommandLine.argc,
    CommandLine.unsafeArgv,
    nil,
    NSStringFromClass(AppDelegate.self)
)
