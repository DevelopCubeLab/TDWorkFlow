import Foundation
import UIKit
import CryptoKit
import MachO

// com.cisc0freak.cardio
// ca.bomberfish.CAPerfHudSwift

class WorkFlowController {
    
    private let workUtils = WorkUtils()
    
    /// Computes a heuristic score for a scan result based on deviation from expectation, duration, and mtime freshness.
    private func calculateScore(for work: Work, expected: Bool, path: String) -> Double {
        var baseScore: Double = 50

        // Positive scoring for expected result
        if work.isValid == expected {
            baseScore += 3
        }

        // Positive scoring for fast detection
        if work.duration < 0.002 {
            baseScore += 2
        }

        // Positive scoring for very old files
        if let diff = work.lastModifiedDiff, diff > 3600 * 24 * 365 {
            baseScore += 2
        }

        // Positive scoring for known safe system paths
        if path.hasPrefix("/bin/") || path.hasPrefix("/usr/libexec/") {
            baseScore += 2
        }

        // Negative scoring for unexpected findings
        if work.isValid != expected {
            if path.contains("var/mobile/Library/Preferences/") ||
                path.contains("var/mobile/Media/") {
                baseScore -= 5
            } else {
                baseScore -= 15
            }
        }

        if work.duration > 0.01 {
            baseScore -= 10
        }

        if let diff = work.lastModifiedDiff, diff < 300 {
            baseScore -= 5
        }

        // Version based scoring
        if #available(iOS 18.0, *) {
            baseScore += 5
        } else if #available(iOS 17.1, *) {
            baseScore += 2
        } else if #available(iOS 17.0, *) {
            baseScore -= 8
        } else if #available(iOS 16.7, *) {
            baseScore += 1
        } else if #available(iOS 16.6, *) {
            baseScore -= 8
        } else if #available(iOS 16.0, *) {
            baseScore -= 15
        } else if #available(iOS 15.0, *) {
            baseScore -= 10
        } else if #available(iOS 14.0, *) {
            baseScore -= 9
        }

        // Noise
        let noise = Double.random(in: -1.0...1.0)
        // Runtime-specific scoring
        if path == "jit" {
            if !work.isValid { baseScore -= 10 } else { baseScore += 5 }
        } else if path == "sandbox" {
            if !work.isValid { baseScore -= 15 } else { baseScore += 4 }
        } else if path == "env" {
            if !work.isValid { baseScore -= 5 } else { baseScore += 2 }
        } else if path == "dylibs" {
            if !work.isValid { baseScore -= 20 } else { baseScore += 2 }
        }
        return max(0, min(100, baseScore + noise))
    }
    
    /// Evaluates multiple file paths against expectations and assigns a weighted score.
    /// - Parameter pathsWithExpectations: A dictionary where the key is the file path and the value is whether it is expected to exist.
    /// - Returns: A mapping from file path to scan evaluation result.
    func scan(pathsWithExpectations: [String: Bool]) -> [String: WorkFlow] {
        var result: [String: WorkFlow] = [:]
        
        for (path, expected) in pathsWithExpectations {
            let work = workUtils.fileWork(for: path)
            let score = calculateScore(for: work, expected: expected, path: path)
            
            result[path] = WorkFlow(work: work, expectation: expected, score: score)
        }
        
        return result
    }
    
    /// Performs a predefined batch scan using common system and jailbreak paths.
    /// - Returns: Mapping of file paths to their scan results.
    static func performDefaultScan() -> [String: WorkFlow] {
        // MARK: Don't worry about the order of the files being checked; this order will be randomly shuffled.
        let defaultPaths: [String: Bool] = [
            // MARK: System paths (expected to exist)
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.apple.Preferences": true,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.apple.camera": true,
            "/private/var/mobile/Library/Saved Application State/com.apple.Preferences.savedState": true,
            "/usr/lib/dyld": true,
            "/System/Library/CoreServices/SystemVersion.plist": true,
 
            // MARK: -------------------- switch status --------------------
            
            // MARK: - Jailbreak indicators (expected not to exist)
            "/var/jb": false,
            "/var/jb/Applications": false,
            "/var/jb/usr/bin": false,
            "/var/jb/private/etc": false,
            "/var/jb/Applications/Sileo.app": false,
            "/var/jb/Applications/Filza.app": false,
            "/Applications/Sileo.app": false,
            "/Applications/Cydia.app": false,
            "/Applications/Filza.app": false,
            "/Applications/Zebra.app": false,
            "/Applications/Flex.app": false,
            "/Applications/Aemulo.app": false,
            "/Applications/iCleaner.app": false,
            "/Library/MobileSubstrate/MobileSubstrate.dylib": false,
            "/etc/apt": false,
            "/private/var/lib/apt": false,
            "/usr/sbin/sshd": false,
            "/usr/bin/ssh": false,
            
            "/Applications/blackra1n.app": false,
            "/Applications/FakeCarrier.app": false,
            "/Applications/Icy.app": false,
            "/Applications/IntelliScreen.app": false,
            "/Applications/MxTube.app": false,
            "/Applications/RockApp.app": false,
            "/Applications/SBSettings.app": false,
            "/Applications/WinterBoard.app": false,
            "/.cydia_no_stash": false,
            "/.installed_unc0ver": false,
            "/.bootstrapped_electra": false,
            "/usr/libexec/cydia/firmware.sh": false,
            "/usr/libexec/ssh-keysign": false,
            "/usr/libexec/sftp-server": false,
            "/usr/bin/sshd": false,
            "/var/lib/cydia": false,
            "/var/lib/dpkg/info/mobilesubstrate.md5sums": false,
            "/var/log/apt": false,
            "/usr/share/jailbreak/injectme.plist": false,
            "/usr/sbin/frida-server": false,
            "/Library/MobileSubstrate/CydiaSubstrate.dylib": false,
            "/Library/TweakInject": false,
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist": false,
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist": false,
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist": false,
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist": false,
            "/private/var/mobile/Library/SBSettings/Themes": false,
            "/private/var/lib/cydia": false,
            "/private/var/tmp/cydia.log": false,
            "/private/var/log/syslog": false,
            "/private/var/cache/apt/": false,
            "/private/var/Users/": false,
            "/private/var/stash": false,
            "/usr/lib/libjailbreak.dylib": false,
            "/usr/lib/libz.dylib": false,
            "/usr/lib/system/introspectionNSZombieEnabled": false,
            "/jb/amfid_payload.dylib": false,
            "/jb/libjailbreak.dylib": false,
            "/jb/jailbreakd.plist": false,
            "/jb/offsets.plist": false,
            "/jb/lzma": false,
            "/hmd_tmp_file": false,
            "/etc/ssh/sshd_config": false,
            "/etc/apt/undecimus/undecimus.list": false,
            "/etc/apt/sources.list.d/sileo.sources": false,
            "/etc/apt/sources.list.d/electra.list": false,
            "/etc/ssl/certs": false,
            "/etc/ssl/cert.pem": false,
            "/bin/sh": false,
            "/bin/bash": false,
            "/private/var/lib/dpkg/": false,
            "/private/var/db/stash/": false,
            "/private/var/containers/Bundle/Application/.jb": false,
            
            "/private/var/mobile/Library/HTTPStorages/org.coolstar.SileoStore": false,
            "/private/var/mobile/Library/HTTPStorages/com.opa334.Dopamine": false,
            
            "/private/var/mobile/Library/varClean": false,
            "/var/mobile/Library/TrollDecrypt": false,
            "/var/mobile/Documents/.misaka": false, // misaka
            
            "/private/var/mobile/IPCCReplacer": false, // com.xiaobovlog.ipcc
            "/private/var/mobile/testrebuild": false,
            "/private/var/mobile/Library/Saved Application State/com.xiaobovlog.ipcc.savedState": false,
            
            "/private/var/mobile/Library/Filza": false, // com.tigisoftware.Filza
            "/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist": false,
            "/var/mobile/Library/Caches/com.tigisoftware.Filza": false,
            "/var/mobile/Library/SplashBoard/Snapshots/com.tigisoftware.Filza": false,
            "/var/mobile/Library/Application Support/Containers/com.tigisoftware.Filza": false,
            "/var/mobile/Library/Saved Application State/com.tigisoftware.Filza.savedState": false,
            "/var/mobile/Library/HTTPStorages/com.tigisoftware.Filza": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.tigisoftware.Filza": false,
            "/private/var/mobile/Library/Saved Application State/com.tigisoftware.Filza.savedState": false,
            
            "/var/mobile/Library/Preferences/com.tigisoftware.ADManager.plist": false, // com.tigisoftware.ADManager
            "/private/var/mobile/Library/ADManager": false, // com.tigisoftware.ADManager
            "/var/mobile/Library/HTTPStorages/com.tigisoftware.ADManager": false,
            "/private/var/mobile/Library/Caches/com.tigisoftware.ADManager": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.tigisoftware.ADManager": false,
            
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.callassist.batteryinfolist": false,
            
            "/var/mobile/Library/Preferences/com.rbtdigital.BatteryLife.plist": false, // com.rbtdigital.BatteryLife
            "/var/mobile/Library/Preferences/com.rbtdigital.BatteryLife.history.plist": false,
            "/var/mobile/Library/HTTPStorages/com.rbtdigital.BatteryLife": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.rbtdigital.BatteryLife": false,
            "/private/var/mobile/Library/Saved Application State/com.rbtdigital.BatteryLife.savedState": false,
            "/private/var/mobile/Library/Caches/com.rbtdigital.BatteryLife": false,
            "/private/var/mobile/Library/WebKit/com.rbtdigital.BatteryLife": false,
            
            "/var/mobile/Library/Preferences/me.tomt000.copylog.plist": false, // me.tomt000.copylog
            "/var/mobile/Library/Preferences/me.tomt000.copylog.other.plist": false,
            
            "/private/var/mobile/Library/HTTPStorages/com.leemin.Cowabunga": false,
            "/private/var/mobile/Library/HTTPStorages/com.leemin.SecondHand": false,
            "/private/var/mobile/Library/Saved Application State/com.leemin.Cowabunga.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.leemin.SecondHand.savedState": false,
            "/private/var/mobile/Library/Caches/com.leemin.Cowabunga": false,
            
            "/private/var/mobile/Library/HTTPStorages/live.cclerc.geranium": false,
            "/private/var/mobile/Library/HTTPStorages/net.sourceloc.AirTroller": false,
            
            "/private/var/mobile/Library/Caches/ru.domo.cocoatop64": false,
            
            "/var/mobile/Library/Preferences/NiceCaller.plist": false, // NiceCaller
            "/var/mobile/Library/Preferences/NiceRecorder-Troll.plist": false,
            
            "/var/mobile/Library/Preferences/wiki.qaq.trapp.plist": false, // wiki.qaq.trapp
            "/var/mobile/Library/Preferences/wiki.qaq.trapp-orbit.plist": false,
            "/var/mobile/Library/Preferences/wiki.qaq.trapp-tweak.plist": false,
            "/var/mobile/Library/Preferences/wiki.qaq.trapp.safe-area.plist": false,
            "/var/mobile/Library/Preferences/wiki.qaq.trapp": false,
            "/var/mobile/Library/Preferences/wiki.qaq.trapp/Preferences": false,
            "/private/var/mobile/Library/HTTPStorages/wiki.qaq.trapp": false,
            "/private/var/mobile/Library/Caches/wiki.qaq.trapp": false,
            "/private/var/mobile/Library/Application Support/bugsnag-shared-wiki.qaq.trapp": false,
            "/private/var/mobile/Media/TrollRecorder": false,
            
            "/var/mobile/Library/Preferences/wiki.qaq.ai.gate": false,
            
            "/var/mobile/Library/Preferences/xc.lzsxcl.Trollo2e.plist": false,
            
            "/var/mobile/Library/Preferences/ca.bomberfish.SwiftTop.plist": false,
            
            "/var/mobile/Library/Preferences/ch.xxtou.hudapp.plist": false,
            
            "/var/mobile/Library/Preferences/chaoge.ChargeLimiter.plist": false, // chaoge.ChargeLimiter
            "/var/mobile/Library/Preferences/chaoge.AlDente.plist": false,
            
            "/var/mobile/Library/Preferences/cn.bswbw.AppsDump.plist": false,
            "/var/mobile/Library/Preferences/cn.gblw.AppsDump.plist": false,
            "/var/mobile/Library/Preferences/com.zlwl.appsdump.plist": false,
            
            "/var/mobile/Library/Preferences/com.82flex.reveil.PinStorage.plist": false,
            
            "/var/mobile/Library/Preferences/com.netskao.downgradeapp.plist": false, // com.netskao.downgradeapp
            "/var/mobile/Library/Preferences/com.netskao.downgradeappsettings.plist": false,
            "/private/var/mobile/Library/HTTPStorages/com.netskao.downgradeapp": false,
            "/private/var/mobile/Library/Caches/com.netskao.downgradeapp": false,
            "/private/var/mobile/Library/Saved Application State/com.netskao.downgradeapp.savedState": false,
            
            "/var/mobile/Library/Preferences/com.serena.santanderfm.plist": false, // com.serena.santanderfm
            
            "/var/mobile/Library/Preferences/com.simloc.app.plist": false, // com.simloc.app
            
            "/var/mobile/Library/Preferences/net.limneos.AudioRecorder.plist": false, // net.limneos.audiorecorder
            "/var/mobile/Library/Preferences/net.limneos.audiorecorder.plist": false,
            
            "/var/mobile/Library/Preferences/com.leemin.helium.plist": false, // com.leemin.helium
            
            "/private/var/mobile/Library/HTTPStorages/com.mika.LocationSimulation": false,
            
            "/private/var/mobile/Library/HTTPStorages/com.gamegod.igg": false,
            "/private/var/mobile/Library/Caches/com.gamegod.igg": false,
            
            "/private/var/mobile/Documents/DumpDecrypter": false,
            "/private/var/mobile/Documents/DumpIpa": false,
            
            "/var/mobile/Library/Preferences/com.DebianArch.ScarletPersonalXYZ.plist": false,
            "/var/mobile/Library/Preferences/com.charlieleung.TrollOpen.plist": false,
            "/var/mobile/Library/Preferences/com.cisc0freak.cardio.plist": false,
            "/var/mobile/Library/Preferences/com.huami.TrollFools.plist": false,
            "/var/mobile/Library/Preferences/com.muyang.ioszhushou.plist": false,
            "/var/mobile/Library/Preferences/com.serena.AppIndex.plist": false,
            "/var/mobile/Library/Preferences/com.susu.cleaner.plist": false,
            
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.amywhile.Aemulo": false, // com.amywhile.Aemulo
            "/private/var/mobile/Library/WebKit/com.amywhile.Aemulo": false,
            "/private/var/mobile/Library/Saved Application State/com.amywhile.Aemulo.savedState": false,
            
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.leemin.Cowabunga": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.netskao.injectwechat": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.niceios.Battery.Battery": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.straight-tamago.Osushi": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.xiaobovlog.FastReboot": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.xiaobovlog.ipcc": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/live.cclerc.geranium": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/wiki.qaq.TrollFools": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/xc.lzsxcl.Trollo2e": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.huami.TrollFools": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.ichitaso.otadisablerts": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/com.ui.speed": false,
            "/private/var/mobile/Library/SplashBoard/Snapshots/ru.domo.cocoatop64": false,
            
            "/private/var/mobile/Library/Saved Application State/ca.bomberfish.SwiftTop.savedState": false,
            "/private/var/mobile/Library/Saved Application State/chaoge.AlDente.savedState": false,
            "/private/var/mobile/Library/Saved Application State/chaoge.ChargeLimiter.savedState": false,
            "/private/var/mobile/Library/Saved Application State/cn.bswbw.AppsDump.savedState": false,
            "/private/var/mobile/Library/Saved Application State/cn.bswbw.DEB.backup.savedState": false,
            "/private/var/mobile/Library/Saved Application State/cn.bswbw.xflw.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.34306.watching.savedState": false,
            
            "/private/var/mobile/Library/Saved Application State/com.avangelista.Appabetical.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.callassist.batteryinfolist.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.callassist.deviceinfolist.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.hqgame.popo2.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.huami.SuperIcons.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.ichitaso.otadisablerts.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.mika.LocationSimulation.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.netskao.injectwechat.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.niceios.Battery.Battery.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.serena.santanderfm.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.straight-tamago.Osushi.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.straight-tamago.uiharux-pro.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.tigisoftware.ADManager.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.xiaobovlog.FastReboot.savedState": false,
            "/private/var/mobile/Library/Saved Application State/live.cclerc.geranium.savedState": false,
            "/private/var/mobile/Library/Saved Application State/net.sourceloc.AirTroller.savedState": false,
            "/private/var/mobile/Library/Saved Application State/net.sourceloc.TrollTools.savedState": false,
            "/private/var/mobile/Library/Saved Application State/org.haxi0.Derootifier.savedState": false,
            "/private/var/mobile/Library/Saved Application State/ru.domo.cocoatop64.savedState": false,
            "/private/var/mobile/Library/Saved Application State/wiki.qaq.TrollFools.savedState": false,
            "/private/var/mobile/Library/Saved Application State/xc.lzsxcl.Trollo2e.savedState": false,
            "/private/var/mobile/Library/Saved Application State/cn.gblw.AppsDump.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.huami.TrollFools.savedState": false,

            "/private/var/mobile/Library/Saved Application State/com.serena.AppIndex.savedState": false,
            "/private/var/mobile/Library/Saved Application State/com.ui.speed.savedState": false,
            
        ]
        
        let controller = WorkFlowController()
        let shuffled = Dictionary(uniqueKeysWithValues: defaultPaths.shuffled()) // random the check list
        return controller.scan(pathsWithExpectations: shuffled)
    }
    
    /// Checks for suspicious URL schemes (e.g., Cydia, Sileo) registered in the app's environment.
    static func checkSuspiciousURLSchemes() -> [String: WorkFlow] {
        let controller = WorkFlowController()
        var result: [String: WorkFlow] = [:]

        let suspiciousURLSchemes = [
            "cydia",
            "sileo",
            "zbra",
            "filza", // com.tigisoftware.Filza
            "adm", // com.tigisoftware.ADManager
            "mterminal", // com.officialscheduler.mterminal
            "trapp", // wiki.qaq.trapp
            "legizmo", // app.legizmo
            "copylog", // me.tomt000.ts.copylog
            "cl", // chaoge.ChargeLimiter
            "trollspeed", // ch.xxtou.hudapp
            "cowabunga", // com.leemin.Cowabunga
            "misaka", // com.straight-tamago.misakaRS
            "helium", // com.leemin.helium
            "Battery-Life_Cydia", // com.rbtdigital.BatteryLife
            "floatingball", // com.mumu.iosshare
            "netfenceapp" // com.foxfort.NetFenceApp
        ]

        let globalStart = Date()

        for scheme in suspiciousURLSchemes {
            let start = Date()
            let isDetected: Bool

            if let url = URL(string: "\(scheme)://"), UIApplication.shared.canOpenURL(url) {
                isDetected = true
            } else {
                isDetected = false
            }

            let duration = Date().timeIntervalSince(start)
            let work = Work(isValid: isDetected, duration: duration, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: work, expected: false, path: "url_scheme_\(scheme)")
            result["URLScheme: \(scheme)"] = WorkFlow(work: work, expectation: false, score: score)
        }

        let totalDuration = (Date().timeIntervalSince(globalStart) * 10000).rounded() / 10000
        let metaWork = Work(isValid: true, duration: totalDuration, lastModifiedDiff: nil)
        let metaScore = controller.calculateScore(for: metaWork, expected: true, path: "url_scheme_total")
        result["URLScheme/TotalDuration"] = WorkFlow(work: metaWork, expectation: true, score: metaScore)

        return result
    }
    
    /// Performs runtime environment checks and returns them as WorkFlow objects for integrity scoring.
    static func performRuntimeIntegrityScan() -> [String: WorkFlow] {
        let start = Date()
        
        let jitEnabled = isJITEnabled()
        let durationJIT = Date().timeIntervalSince(start)
        // JIT is expected to be disabled in production/TestFlight environments; enabled JIT indicates a suspicious condition
        let workJIT = Work(isValid: jitEnabled == false, duration: durationJIT, lastModifiedDiff: nil)
 
        let sandboxEscape = canWriteOutsideSandbox()
        let durationSandbox = Date().timeIntervalSince(start)
        let workSandbox = Work(isValid: !sandboxEscape, duration: durationSandbox, lastModifiedDiff: nil)
 
        let envTampered = hasSuspiciousEnvironmentVariables()
        let durationEnv = Date().timeIntervalSince(start)
        let workEnv = Work(isValid: !envTampered, duration: durationEnv, lastModifiedDiff: nil)

        let forkCapability = canSpawnProcess()
        _ = forkCapability.duration
        let debuggerCheck = isBeingDebugged()
        let symbolCheck = isSymbolHooked()
 
        let controller = WorkFlowController()
        let dylibResults = suspiciousDylibWorkflows(controller: controller)
 
        var result: [String: WorkFlow] = [
            "Runtime/JIT": WorkFlow(work: workJIT, expectation: false, score: controller.calculateScore(for: workJIT, expected: true, path: "jit")),
            "Runtime/Sandbox": WorkFlow(work: workSandbox, expectation: true, score: controller.calculateScore(for: workSandbox, expected: true, path: "sandbox")),
            "Runtime/Environment": WorkFlow(work: workEnv, expectation: true, score: controller.calculateScore(for: workEnv, expected: true, path: "env")),
            "Runtime/Fork": WorkFlow(work: forkCapability, expectation: true, score: controller.calculateScore(for: forkCapability, expected: true, path: "fork")),
            "Runtime/Debugger": WorkFlow(work: debuggerCheck, expectation: true, score: controller.calculateScore(for: debuggerCheck, expected: true, path: "debugger")),
            "Runtime/SymbolCheck": WorkFlow(work: symbolCheck, expectation: true, score: controller.calculateScore(for: symbolCheck, expected: true, path: "symbol"))
        ]
        
        result.merge(dylibResults) { _, new in new }
        var expectedBundleFiles = [ // MARK: Add more bundle files as needed
            "AppIcon60x60@2x.png",
            "AppIcon76x76@2x~ipad.png",
            "Assets.car",
            "Base.lproj",
            "Info.plist",
            "PkgInfo",
            "ReminderList",
            "_CodeSignature",
            "en.lproj",
            "zh-Hans.lproj"
        ]
        
#if DEBUG
        expectedBundleFiles.append("embedded.mobileprovision") // TestFlight and App Store environment not use this file
#else
        expectedBundleFiles.append("SC_Info")
#endif
        
        let bundleResults = checkBundleFiles(expectedCount: expectedBundleFiles.count, expectedFiles: expectedBundleFiles)
        result.merge(bundleResults) { _, new in new }
        let forbiddenPrefixes = ["lib", "tweak", "substrate", "NATHANLR", "dylib", "使用全能签签名", "SignedByEsign"] // Files that should not appear in bundle
        let forbiddenResults = checkUnexpectedBundleFiles(forbiddenPrefixes: forbiddenPrefixes)
        result.merge(forbiddenResults) { _, new in new }
        
        result["Bundle/BinaryHash"] = checkAppBinaryHash()
        return result
    }
    
    /// Checks if JIT is unexpectedly enabled in a non-debug environment.
    private static func isJITEnabled() -> Bool {
        let function: UnsafeMutableRawPointer? = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "dlopen")
        return function != nil
    }
    
    /// Checks if the app can write outside its sandbox (e.g., `/private/`).
    private static func canWriteOutsideSandbox() -> Bool {
        let testPath = "/var/mobile/Library/Preferences/com.test.plist"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
    
    /// Checks for known suspicious environment variables.
    private static func hasSuspiciousEnvironmentVariables() -> Bool {
        let suspiciousKeys = ["DYLD_INSERT_LIBRARIES", "LD_PRELOAD"]
        let debugWhitelist = ["/usr/lib/libViewDebuggerSupport.dylib"]
        
        for key in suspiciousKeys {
            if let raw = getenv(key), let value = String(validatingUTF8: raw), !value.isEmpty {
                // If value is a debugger whitelist, skip. Solve the false alarm problem in iOS 18
                if debugWhitelist.contains(value) {
    #if DEBUG
                    print("[EnvironmentCheck] Whitelisted injected lib: \(value)")
    #endif
                    continue
                }
    #if DEBUG
                print("[EnvironmentCheck] Suspicious key detected: \(key) = \(value)")
    #endif
                return true
            }
        }
        return false
    }

    /// Checks if the app can call fork(), which is generally restricted on iOS.
    private static func canSpawnProcess() -> Work {
        let start = Date()
        var pid: pid_t = 0
        let path = "/bin/ls"
        let args: [UnsafeMutablePointer<CChar>?] = [strdup(path), nil]
        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)

        let result = posix_spawn(&pid, path, &fileActions, nil, args, environ)

        for arg in args where arg != nil {
            free(arg)
        }

        let duration = Date().timeIntervalSince(start)
        let success = (result == 0)

        return Work(isValid: !success, duration: duration, lastModifiedDiff: nil)
    }
    
    /// Returns a mapping of suspicious dylib paths to their corresponding WorkFlow.
    private static func suspiciousDylibWorkflows(controller: WorkFlowController) -> [String: WorkFlow] {
        let suspectKeywords = ["cydia", "substrate", "tweak", "injection", "TweakInject", "Choicy", "Crane", "leftPan", "Flex", "iapstore"]
        
        var result: [String: WorkFlow] = [:]
        let count = _dyld_image_count()
#if DEBUG
        print("dylib count: \(count)")
#endif
        for i in 0..<count {
            if let name = _dyld_get_image_name(i) {
#if DEBUG
                print("\(i) dylib name: \(String(cString: name))")
#endif
                let path = String(cString: name)
                for keyword in suspectKeywords {
                    if path.lowercased().contains(keyword) {
                        let work = Work(isValid: false, duration: 0, lastModifiedDiff: nil)
                        let score = controller.calculateScore(for: work, expected: true, path: "dylibs")
                        result["Runtime/Dylibs/\(path)"] = WorkFlow(work: work, expectation: true, score: score)
                        break
                    }
                }
            }
        }
        
        if result.isEmpty {
            let placeholderWork = Work(isValid: true, duration: 0, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: placeholderWork, expected: true, path: "dylibs")
            result["Runtime-Dylibs/(no suspicious dylib found)"] = WorkFlow(work: placeholderWork, expectation: true, score: score)
        }

        return result
    }
    /// Scans bundle resources and compares them to expected content.
    private static func checkBundleFiles(expectedCount: Int, expectedFiles: [String]) -> [String: WorkFlow] {
        let controller = WorkFlowController()
        var result: [String: WorkFlow] = [:]
        var foundCount = 0

        for path in expectedFiles {
            let fullPath = Bundle.main.bundlePath + "/" + path
            let exists = FileManager.default.fileExists(atPath: fullPath)

            let work = Work(isValid: exists, duration: 0, lastModifiedDiff: nil)

            let score: Double
#if DEBUG
            if path == "embedded.mobileprovision" {
                score = 50
            } else {
                score = controller.calculateScore(for: work, expected: true, path: "bundle")
            }
#else
            score = controller.calculateScore(for: work, expected: true, path: "bundle")
#endif

            if exists { foundCount += 1 }

            result["Bundle/\(path)"] = WorkFlow(work: work, expectation: true, score: score)
        }
 
        // Compare actual count vs expected
        let countCorrect = (foundCount == expectedCount)
        let countWork = Work(isValid: countCorrect, duration: 0, lastModifiedDiff: nil)
        let countScore = controller.calculateScore(for: countWork, expected: true, path: "bundle_count")
        result["Bundle/FileCountComparison(Ensure no files are lost) Expected Count: \(expectedCount) TotalFoundCount: \(foundCount)"] = WorkFlow(work: countWork, expectation: true, score: countScore)
 
        // Compare actual bundle total file count with extra unexpected file listing
        if let allContents = try? FileManager.default.contentsOfDirectory(atPath: Bundle.main.bundlePath) {
            let totalMatch = (allContents.count == expectedCount)
            let totalWork = Work(isValid: totalMatch, duration: 0, lastModifiedDiff: nil)
            let totalScore = controller.calculateScore(for: totalWork, expected: true, path: "bundle_total")
            result["Bundle/TotalFileCountMatch Expected Count: \(expectedCount) TotalFoundCount: \(allContents.count)"] = WorkFlow(work: totalWork, expectation: true, score: totalScore)
 
            if !totalMatch {
                let expectedSet = Set(expectedFiles.map { $0.lowercased() })
                for file in allContents where !expectedSet.contains(file.lowercased()) {
                    let extraWork = Work(isValid: true, duration: 0, lastModifiedDiff: nil)
                    let extraScore = controller.calculateScore(for: extraWork, expected: false, path: "bundle_extra")
                    result["Bundle/Unexpected or Extra - \(file)"] = WorkFlow(work: extraWork, expectation: false, score: extraScore)
                }
            }
        }
 
        return result
    }

    /// Checks for unexpected/injected files in the app bundle.
    private static func checkUnexpectedBundleFiles(forbiddenPrefixes: [String]) -> [String: WorkFlow] {
        let controller = WorkFlowController()
        var result: [String: WorkFlow] = [:]

        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: Bundle.main.bundlePath) else {
            return result
        }

        for item in contents {
            for prefix in forbiddenPrefixes {
                if item.lowercased().hasPrefix(prefix.lowercased()) {
                    let work = Work(isValid: false, duration: 0, lastModifiedDiff: nil)
                    let score = controller.calculateScore(for: work, expected: false, path: "bundle_forbidden")
                    result["Bundle/Unexpected/\(item)"] = WorkFlow(work: work, expectation: false, score: score)
                }
            }
        }

        if result.isEmpty {
            let placeholderWork = Work(isValid: true, duration: 0, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: placeholderWork, expected: true, path: "bundle_forbidden")
            result["Bundle/Unexpected/(no forbidden files)"] = WorkFlow(work: placeholderWork, expectation: true, score: score)
        }

        return result
    }
    
    /// Checks if the process is being debugged using sysctl.
    private static func isBeingDebugged() -> Work {
        let start = Date()
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        let isTraced = (result == 0) && (info.kp_proc.p_flag & P_TRACED != 0)
        let duration = Date().timeIntervalSince(start)

        return Work(isValid: !isTraced, duration: duration, lastModifiedDiff: nil)
    }

    /// Checks if critical symbols (e.g. dlopen, objc_msgSend) are suspiciously relocated, indicating possible hook.
    private static func isSymbolHooked() -> Work {
        let start = Date()
        var suspiciousPath: String? = nil
 
        let symbols: [String] = ["dlopen", "objc_msgSend"]
        let validPrefixes = [
            "/usr/lib/",
            "/usr/lib/system/",
            "/System/Library/",
            "/usr/lib/libSystem.B.dylib"
        ]
 
        for name in symbols {
            if let sym = dlsym(nil, name) {
                var dlinfo = Dl_info()
                if dladdr(sym, &dlinfo) != 0, let dli_fname = dlinfo.dli_fname {
                    let path = String(cString: dli_fname)
#if DEBUG
                    print("[SymbolCheck] Resolved \(name) to \(path)")
#endif
                    let isLegit = validPrefixes.contains { path.hasPrefix($0) }
#if DEBUG
                    print("[SymbolCheck] \(name) is legitimate: \(isLegit)")
#endif
                    if !isLegit {
                        suspiciousPath = path
                        break
                    }
                }
            }
        }
 
        let duration = Date().timeIntervalSince(start)
        let isValid = (suspiciousPath == nil)
        return Work(isValid: isValid, duration: duration, lastModifiedDiff: nil)
    }
    
    private static func checkAppBinaryHash() -> WorkFlow {
        let controller = WorkFlowController()
        let start = Date()

        guard let executablePath = Bundle.main.executablePath,
              let data = try? Data(contentsOf: URL(fileURLWithPath: executablePath)) else {
            let failedWork = Work(isValid: false, duration: 0, lastModifiedDiff: nil)
            let failedScore = controller.calculateScore(for: failedWork, expected: true, path: "binary_hash")
            return WorkFlow(work: failedWork, expectation: true, score: failedScore)
        }

        let hash = sha256(data: data)
    #if DEBUG
        print("[BinaryHash] SHA256: \(hash)")
    #endif

        let duration = Date().timeIntervalSince(start)
        let work = Work(isValid: true, duration: duration, lastModifiedDiff: nil)
        let score = controller.calculateScore(for: work, expected: true, path: "binary_hash")
        return WorkFlow(work: work, expectation: true, score: score)
    }

    private static func sha256(data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
    
}
