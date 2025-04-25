import Foundation
import UIKit
import CryptoKit
import MachO

class WorkFlowController {
    
    private let workUtils = WorkUtils()
    
    /// Computes a heuristic score for a scan result based on deviation from expectation, duration, and mtime freshness.
    private func calculateScore(for work: Work, expected: Bool, path: String) -> Double {
        var baseScore: Double = 50

        // Positive scoring for expected result; negative for unexpected
        if work.isValid == expected {
            baseScore += 3
        } else {
            baseScore -= 10
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
            // JIT is expected to be disabled; work.isValid means JIT is disabled (good)
            if work.isValid { baseScore -= 10 } else { baseScore += 5 }
        } else if path == "sandbox" {
            // Sandbox escape not detected is good (work.isValid == true)
            if work.isValid { baseScore += 4 } else { baseScore -= 15 }
        } else if path == "env" {
            // No suspicious env vars (work.isValid == true) is good
            if work.isValid { baseScore += 2 } else { baseScore -= 5 }
        } else if path == "dylibs" {
            // No suspicious dylibs (work.isValid == true) is good
            if work.isValid { baseScore += 2 } else { baseScore -= 20 }
        }

#if DEBUG
        // Add score deduction if forbidden bundle ID launch is detected
        if path.hasPrefix("BundleIDCheck/Forbidden") && !work.isValid {
            baseScore -= 45
        }
        if path.hasPrefix("BundleIDCheck/HookDetection") && !work.isValid {
            baseScore -= 50
        }
#endif

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
            "/var/mobile/Documents/settings.fzs": false,
            // Filza backup Because if users clean up the var directory every time, then their Filza will lose the configuration file.
            // Therefore, in order to prevent the loss of the configuration file, users need to back up Filza's configuration first, and then we can check Filza backup file path.
            
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
            "santander", // com.serena.santanderfm
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
            "netfenceapp", // com.foxfort.NetFenceApp
            "SuperVip" // com.lenglengyu.supervip
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
        // Files that should not appear in bundle
        let forbiddenPrefixes = ["lib", // This depends on whether your app includes
                                 "tweak",
                                 "substrate",
                                 "Cydia",
                                 "FakeTools", // com.xuuz.faketools.plist
                                 "NATHANLR", // NathanLR mid-jailbreak
                                 "bak", // TrollFools process file
                                 "dylib", // If the app uses dynamic libraries, it needs to be excluded here
                                 "使用全能签签名", // Traces left by the re-signature apps
                                 "SignedByEsign" // Traces left by the re-signature apps
        ]
        let forbiddenResults = checkUnexpectedBundleFiles(forbiddenPrefixes: forbiddenPrefixes, allowedFiles: expectedBundleFiles)
        result.merge(forbiddenResults) { _, new in new }
        
        result["Bundle/BinaryHash"] = checkAppBinaryHash()
        result["App/VersionCheck"] = checkAppVersion(expectedVersion: "1.0")
        
        let versionCheck = checkSystemVersionIntegrity()
        result["Runtime/SystemVersionCheck"] = WorkFlow(
            work: versionCheck,
            expectation: true,
            score: controller.calculateScore(for: versionCheck, expected: true, path: "version_check_runtime")
        )
        
        let sandboxAllowedFiles = ["Library", "Documents", "tmp"]
        let sandboxForbiddenPrefixes = ["cydia", "substrate", "jailbreak", "Troll", "TweakInject", "Tweaks"]

        // Run sandbox file integrity detection
        let sandboxResults = WorkFlowController.checkSandboxIntegrity(
            allowedFiles: sandboxAllowedFiles,
            forbiddenPrefixes: sandboxForbiddenPrefixes
        )

        result.merge(sandboxResults) { _, new in new }
        
        let userDefaultsAllowedKeys = ["AppTheme", "UserSettings", TodoStorageController.todoStorageKey] // add your app need storage key
        
        let userDefaultsForbiddenKeys = [
            "substrate",
            "jailbreak",
            "cydia",
            "troll",
            "DisableSecureTextEntryEnabled",
            ""
        ]
        
        // Run UserDefaults detection
        let userDefaultsResults = WorkFlowController.checkUserDefaultsIntegrity(
            allowedKeys: userDefaultsAllowedKeys,
            forbiddenKeys: userDefaultsForbiddenKeys
        )
        result.merge(userDefaultsResults) { _, new in new }
        
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

                        storeDetectionSecurely(flowComment: "Detected suspicious dylib: \(path)")
#if !FOR_CHECK_WORK_FLOW
                        fatalError("Terminating due to suspicious dylib injection.")
#endif
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
    private static func checkUnexpectedBundleFiles(forbiddenPrefixes: [String], allowedFiles: [String]) -> [String: WorkFlow] {
        let controller = WorkFlowController()
        var result: [String: WorkFlow] = [:]

        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: Bundle.main.bundlePath) else {
            // If there is no sandbox directory, then this is very abnormal and the error will be returned directly
            let failedWork = Work(isValid: false, duration: 0, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: failedWork, expected: true, path: "bundle_directory_access_failed")
            result["Bundle/(Failed to access bundle directory)"] = WorkFlow(work: failedWork, expectation: true, score: score)
            return result
        }

        // Traverse all files within the bundle
        for item in contents {
            var matchedForbidden = false
            
            // Check if on blacklist
            for prefix in forbiddenPrefixes {
                if item.lowercased().hasPrefix(prefix.lowercased()) {
                    let work = Work(isValid: false, duration: 0, lastModifiedDiff: nil)
                    let score = controller.calculateScore(for: work, expected: false, path: "bundle_forbidden/\(item)")
                    result["Bundle/Forbidden/\(item)"] = WorkFlow(work: work, expectation: false, score: score)
                    matchedForbidden = true
                    break
                }
            }

            // If the blacklist is not matched, check the whitelist
            if !matchedForbidden && !allowedFiles.contains(item) {
                let work = Work(isValid: false, duration: 0, lastModifiedDiff: nil)
                let score = controller.calculateScore(for: work, expected: false, path: "bundle_unexpected/\(item)")
                result["Bundle/Unexpected/\(item)"] = WorkFlow(work: work, expectation: false, score: score)
            }
        }

        // If no abnormal files are found, add a clear "No Abnormal Files" mark.
        if result.isEmpty {
            let placeholderWork = Work(isValid: true, duration: 0, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: placeholderWork, expected: true, path: "bundle_clean")
            result["Bundle/Unexpected/(no forbidden or unexpected files)"] = WorkFlow(work: placeholderWork, expectation: true, score: score)
        }

        return result
    }
    
    
    /// Verifies that the app version from Info.plist matches the hardcoded expected version.
    static func checkAppVersion(expectedVersion: String = "1.0") -> WorkFlow {
        let controller = WorkFlowController()
        let start = Date()

        let versionFromPlist = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
        let isValid = (versionFromPlist == expectedVersion)

        let duration = Date().timeIntervalSince(start)
        let work = Work(isValid: isValid, duration: duration, lastModifiedDiff: nil)
        let score = controller.calculateScore(for: work, expected: true, path: "version_check")

#if DEBUG
        print("[VersionCheck] Info.plist version: \(versionFromPlist ?? "nil"), expected: \(expectedVersion), match: \(isValid)")
#endif

        return WorkFlow(work: work, expectation: true, score: score)
    }
    
    /// Version consistency detection
    private static func checkSystemVersionIntegrity() -> Work {
        let start = Date()

        let versionByProcessInfo = ProcessInfo.processInfo.operatingSystemVersion
        let versionString = UIDevice.current.systemVersion
        let components = versionString.split(separator: ".")
        let deviceMajor = Int(components.first ?? "0") ?? 0
        let deviceMinor = components.count > 1 ? Int(components[1]) ?? 0 : 0

        var expectedVersionRange = "Unknown"
        var detected1 = false
        var detected2 = false

        if #available(iOS 18.0, *) {
            expectedVersionRange = ">= 18.0"
            detected1 = versionByProcessInfo.majorVersion == 18
            detected2 = deviceMajor == 18
        } else if #available(iOS 17.1, *) {
            expectedVersionRange = "17.1 - 17.9"
            detected1 = versionByProcessInfo.majorVersion == 17 && versionByProcessInfo.minorVersion >= 1
            detected2 = deviceMajor == 17 && deviceMinor >= 1
        } else if #available(iOS 17.0, *) {
            expectedVersionRange = "17.0 - 17.0.x"
            detected1 = versionByProcessInfo.majorVersion == 17 && versionByProcessInfo.minorVersion == 0
            detected2 = deviceMajor == 17 && deviceMinor == 0
        } else if #available(iOS 16.7, *) {
            expectedVersionRange = "16.7"
            detected1 = versionByProcessInfo.majorVersion == 16 && versionByProcessInfo.minorVersion == 7
            detected2 = deviceMajor == 16 && deviceMinor == 7
        } else if #available(iOS 16.6, *) {
            expectedVersionRange = "16.6"
            detected1 = versionByProcessInfo.majorVersion == 16 && versionByProcessInfo.minorVersion == 6
            detected2 = deviceMajor == 16 && deviceMinor == 6
        } else if #available(iOS 16.0, *) {
            expectedVersionRange = "16.0 - 16.5"
            detected1 = versionByProcessInfo.majorVersion == 16 && versionByProcessInfo.minorVersion <= 5
            detected2 = deviceMajor == 16 && deviceMinor <= 5
        } else if #available(iOS 15.0, *) {
            expectedVersionRange = "15.x"
            detected1 = versionByProcessInfo.majorVersion == 15
            detected2 = deviceMajor == 15
        } else if #available(iOS 14.0, *) {
            expectedVersionRange = "14.x"
            detected1 = versionByProcessInfo.majorVersion == 14
            detected2 = deviceMajor == 14
        }

        let detected = detected1 && detected2
        let processInfoVersionString = "\(versionByProcessInfo.majorVersion).\(versionByProcessInfo.minorVersion)"
        let duration = Date().timeIntervalSince(start)

#if DEBUG
        print("[VersionIntegrityCheck] ProcessInfo: \(processInfoVersionString), UIDevice: \(versionString), Expected Range: \(expectedVersionRange), Match: \(detected)")
#endif

        return Work(isValid: detected, duration: duration, lastModifiedDiff: nil)
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

        // First check if _CodeSignature exists
        let signaturePath = Bundle.main.bundlePath + "/_CodeSignature"
        let signatureExists = FileManager.default.fileExists(atPath: signaturePath)
        if !signatureExists {
            let work = Work(isValid: false, duration: 0, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: work, expected: true, path: "binary_signature")
            return WorkFlow(work: work, expectation: true, score: score)
        }

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
    
    // MARK: - Sandbox File Integrity Check
    static func checkSandboxIntegrity(allowedFiles: [String], forbiddenPrefixes: [String]) -> [String: WorkFlow] {
        let controller = WorkFlowController()
        var results: [String: WorkFlow] = [:]
        let fileManager = FileManager.default
        let sandboxPath = NSHomeDirectory()
        
        let start = Date()
        
        guard let enumerator = fileManager.enumerator(atPath: sandboxPath) else {
            return results
        }
        
        for case let file as String in enumerator {
            let fileURL = URL(fileURLWithPath: sandboxPath).appendingPathComponent(file)
            let fileName = fileURL.lastPathComponent
            
            var matchedForbidden = false
            let fileStart = Date()
            
            // Check forbidden prefixes
            for prefix in forbiddenPrefixes {
                if fileName.lowercased().hasPrefix(prefix.lowercased()) {
                    let duration = Date().timeIntervalSince(fileStart)
                    let work = Work(isValid: false, duration: duration, lastModifiedDiff: nil)
                    let score = controller.calculateScore(for: work, expected: false, path: "sandbox_forbidden/\(file)")
                    results["Sandbox/Forbidden/\(file)"] = WorkFlow(work: work, expectation: false, score: score)
                    matchedForbidden = true
                    break
                }
            }
            
            // Check if file is not explicitly allowed (unexpected)
            if !matchedForbidden && !allowedFiles.contains(fileName) {
                let duration = Date().timeIntervalSince(fileStart)
                let work = Work(isValid: false, duration: duration, lastModifiedDiff: nil)
                let score = controller.calculateScore(for: work, expected: false, path: "sandbox_unexpected/\(file)")
                results["Sandbox/Unexpected/\(file)"] = WorkFlow(work: work, expectation: false, score: score)
            }
        }
        
        // If no suspicious files found
        if results.isEmpty {
            let duration = Date().timeIntervalSince(start)
            let placeholderWork = Work(isValid: true, duration: duration, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: placeholderWork, expected: true, path: "sandbox_clean")
            results["Sandbox/(no suspicious files)"] = WorkFlow(work: placeholderWork, expectation: true, score: score)
        }
        
        return results
    }

    // MARK: - UserDefaults Value Integrity Check
    static func checkUserDefaultsIntegrity(allowedKeys: [String], forbiddenKeys: [String]) -> [String: WorkFlow] {
        let controller = WorkFlowController()
        var results: [String: WorkFlow] = [:]
        let defaults = UserDefaults.standard
        
        let start = Date()
        
        let defaultsDict = defaults.dictionaryRepresentation()
        
        for (key, _) in defaultsDict {
            let keyStart = Date()
            var matchedForbidden = false
            
            // Check forbidden keys
            for forbiddenKey in forbiddenKeys {
                if key.lowercased().hasPrefix(forbiddenKey.lowercased()) {
                    let duration = Date().timeIntervalSince(keyStart)
                    let work = Work(isValid: false, duration: duration, lastModifiedDiff: nil)
                    let score = controller.calculateScore(for: work, expected: false, path: "defaults_forbidden/\(key)")
                    results["UserDefaults/Forbidden/\(key)"] = WorkFlow(work: work, expectation: false, score: score)
                    matchedForbidden = true
                    break
                }
            }
            
            // Check unexpected keys
            if !matchedForbidden && !allowedKeys.contains(key) {
                let duration = Date().timeIntervalSince(keyStart)
                let work = Work(isValid: false, duration: duration, lastModifiedDiff: nil)
                let score = controller.calculateScore(for: work, expected: false, path: "defaults_unexpected/\(key)")
                results["UserDefaults/Unexpected/\(key)"] = WorkFlow(work: work, expectation: false, score: score)
            }
        }
        
        // If no suspicious UserDefaults found
        if results.isEmpty {
            let duration = Date().timeIntervalSince(start)
            let placeholderWork = Work(isValid: true, duration: duration, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: placeholderWork, expected: true, path: "defaults_clean")
            results["UserDefaults/(no suspicious values)"] = WorkFlow(work: placeholderWork, expectation: true, score: score)
        }
        
        return results
    }
    
#if DEBUG
    ///
    /// Performs SpringBoard launch access verification using fixed black/white lists.
    static func checkSpringBoardLaunchAccess() -> [String: WorkFlow] {
        let controller = WorkFlowController()
        var results = [String: WorkFlow]()
        
        let forbiddenBundleIDs = [
            "com.opa334.TrollStore",
            "com.opa334.Dopamine",
            "org.coolstar.SileoStore",
            "xyz.willy.Zebra",
            "com.saurik.Cydia",
            "com.tigisoftware.Filza",
            "com.serena.santanderfm",
            "com.tigisoftware.ADManager",
            "wiki.qaq.TrollFools",
            "com.huami.TrollFools",
            "wiki.qaq.trapp",
            "com.amywhile.Aemulo",
            "cn.bswbw.AppsDump",
            "cn.gblw.AppsDump",
            "com.zlwl.appsdump",
            "ru.domo.cocoatop64",
            "wiki.qaq.ai.gate",
            "com.gamegod.igg",
            "com.callassist.batteryinfolist",
            "com.niceios.Battery.Battery",
            "com.xiaobovlog.ipcc",
            "com.xiaobovlog.FastReboot",
            "com.rbtdigital.BatteryLife",
            "me.tomt000.copylog",
            "com.leemin.Cowabunga",
            "com.leemin.SecondHand",
            "com.netskao.downgradeapp",
            "app.legizmo",
            "xc.lzsxcl.Trollo2e",
            "chaoge.ChargeLimiter",
            "com.developlab.BatteryInfo", // I developed an app myself.
            "com.developlab.iDiskTidy.ClearResidue",
            "ch.xxtou.hudapp",
            "com.leemin.helium",
            "com.leemin.helium",
            "com.mumu.iosshare",
            "com.cisc0freak.cardio",
            "ca.bomberfish.CAPerfHudSwift",
            "com.lenglengyu.supervip"
        ]
        
        let allowedBundleIDs = [
            "com.apple.Preferences",
            "com.apple.MobileSMS",
            "com.apple.mobilephone"
        ]
        
        let globalStart = Date()

        for bundleID in forbiddenBundleIDs {
            let start = Date()
            let status = launchBundleID(bundleID)
            let duration = Date().timeIntervalSince(start)
            let detected = (status == 9)
            let work = Work(isValid: !detected, duration: duration, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: work, expected: false, path: "BundleIDCheck/Forbidden/\(bundleID)")
            results["BundleIDCheck/Forbidden/\(bundleID)"] = WorkFlow(work: work, expectation: false, score: score)
        }

        for bundleID in allowedBundleIDs {
            let start = Date()
            let status = launchBundleID(bundleID)
            let duration = Date().timeIntervalSince(start)
            let detected = (status == 9)
            let work = Work(isValid: detected, duration: duration, lastModifiedDiff: nil)
            let score = controller.calculateScore(for: work, expected: true, path: "BundleIDCheck/Allowed/\(bundleID)")
            results["BundleIDCheck/Allowed/\(bundleID)"] = WorkFlow(work: work, expectation: true, score: score)
        }

        // Hook check
        let hookStart = Date()
        let isHooked = isSBSLaunchFunctionHooked()
        let hookDuration = Date().timeIntervalSince(hookStart)
        let hookWork = Work(isValid: !isHooked, duration: hookDuration, lastModifiedDiff: nil)
        let hookScore = controller.calculateScore(for: hookWork, expected: true, path: "BundleIDCheck/HookDetection")
        results["BundleIDCheck/HookDetection"] = WorkFlow(work: hookWork, expectation: false, score: hookScore)

        // Meta total duration
        let totalDuration = Date().timeIntervalSince(globalStart)
        let metaWork = Work(isValid: true, duration: totalDuration, lastModifiedDiff: nil)
        let metaScore = controller.calculateScore(for: metaWork, expected: true, path: "BundleIDCheck/TotalDuration")
        results["BundleIDCheck/TotalDuration"] = WorkFlow(work: metaWork, expectation: true, score: metaScore)

        return results
    }

    private static func launchBundleID(_ bundleIdentifier: String) -> Int32 {
        guard let handle = dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW) else {
            return -1
        }
        defer { dlclose(handle) }

        typealias SBSFunc = @convention(c) (NSString, NSURL?, NSDictionary?, NSDictionary?, Bool) -> Int32
        guard let sym = dlsym(handle, "SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions") else {
            return -2
        }

        let function = unsafeBitCast(sym, to: SBSFunc.self)
        return function(bundleIdentifier as NSString, nil, nil, nil, false)
    }

    private static func isSBSLaunchFunctionHooked() -> Bool {
        guard let handle = dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW),
              let sym = dlsym(handle, "SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions") else {
            return true
        }
        defer { dlclose(handle) }

        let ptr = UnsafeRawPointer(sym).assumingMemoryBound(to: UInt8.self)
        return ptr.pointee == 0xFF && ptr.advanced(by: 1).pointee == 0x25
    }
#endif
    
    
}

// MARK: - Secure Detection Record Handler

enum Severity: String, Codable {
    case low
    case medium
    case high
}

struct WorkRecordPayload: Codable { // DetectionPayload
    struct Record: Codable {
        let worktime: String // timestamp
        let flowComment: String // reason
        let severity: Severity
    }

    var records: [Record]
    var countLow: Int
    var countMedium: Int
    var countHigh: Int
}

/// Encrypts and signs the payload data, returns Base64 encoded string
func encryptAndSign(data: Data) -> String? {
    let baseKey = "supersecretkeyforaesandhmac"
    let hashed = SHA256.hash(data: baseKey.data(using: .utf8)!)
    let symmetricKey = SymmetricKey(data: Data(hashed))

    do {
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
        let combinedData = sealedBox.combined!

        let hmac = HMAC<SHA256>.authenticationCode(for: combinedData, using: symmetricKey)
        var finalData = combinedData
        finalData.append(contentsOf: hmac)

        return finalData.base64EncodedString()
    } catch {
        print("[SecureStore] Encryption failed: \(error)")
        return nil
    }
}

/// Records detection result to both UserDefaults and Keychain in obfuscated form.
/// The value is encrypted and signed. Key name is disguised to avoid easy reverse engineering.
func storeDetectionSecurely(flowComment: String, severity: Severity = .high) {
    let formatter = ISO8601DateFormatter()
    var existingPayload = WorkRecordPayload(records: [], countLow: 0, countMedium: 0, countHigh: 0)

    if let encodedData = loadFromKeychain("WorkStatus"),
       let decodedData = Data(base64Encoded: encodedData),
       decodedData.count > 32 {
        let sealedLength = decodedData.count - 32
        let combined = decodedData.prefix(sealedLength)
        let baseKey = "supersecretkeyforaesandhmac"
        let hashed = SHA256.hash(data: baseKey.data(using: .utf8)!)
        let symmetricKey = SymmetricKey(data: Data(hashed))

        if let sealedBox = try? AES.GCM.SealedBox(combined: combined),
           let decrypted = try? AES.GCM.open(sealedBox, using: symmetricKey),
           let previous = try? JSONDecoder().decode(WorkRecordPayload.self, from: decrypted) {
            existingPayload = previous
        }
    }

    // 插入新记录到开头，保留最多10条
    let newRecord = WorkRecordPayload.Record(worktime: formatter.string(from: Date()), flowComment: flowComment, severity: severity)
    existingPayload.records.insert(newRecord, at: 0)
    if existingPayload.records.count > 10 {
        existingPayload.records.removeLast()
    }

    // 累加次数
    switch severity {
    case .low: existingPayload.countLow += 1
    case .medium: existingPayload.countMedium += 1
    case .high: existingPayload.countHigh += 1
    }

    // 加密存储
    guard let jsonData = try? JSONEncoder().encode(existingPayload),
          let encoded = encryptAndSign(data: jsonData) else {
        print("[SecureStore] Failed to encode and encrypt detection payload.")
        return
    }

    UserDefaults.standard.set(encoded, forKey: "WorkStatus")

    if let encodedData = encoded.data(using: .utf8) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "WorkStatus",
            kSecValueData as String: encodedData
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
}

/// Stores an installation UUID to both UserDefaults and Keychain (with backup/no-backup variants).
func storeInstallUUID() {
    let uuid = UUID().uuidString

    // Save to UserDefaults
    UserDefaults.standard.set(uuid, forKey: "WorkInstallUUID")

    // Save to Keychain (backupable)
    storeToKeychain(key: "WorkInstallUUID_Backup", value: uuid, withBackup: true)

    // Save to Keychain (non-backup)
    storeToKeychain(key: "WorkInstallUUID_NoBackup", value: uuid, withBackup: false)
}

/// Validates UUID across UserDefaults and both Keychain variants.
/// Returns a Work object with validity and timing.
func validateInstallUUID() -> Work {
    let start = Date()
    let uuidUserDefaults = UserDefaults.standard.string(forKey: "WorkInstallUUID")
    let uuidBackup = loadFromKeychain("WorkInstallUUID_Backup")
    let uuidNoBackup = loadFromKeychain("WorkInstallUUID_NoBackup")

    let valid = (uuidUserDefaults != nil && uuidBackup != nil && uuidNoBackup != nil) &&
                (uuidUserDefaults == uuidBackup && uuidBackup == uuidNoBackup)
    let duration = Date().timeIntervalSince(start)

    return Work(isValid: valid, duration: duration, lastModifiedDiff: nil)
}

private func storeToKeychain(key: String, value: String, withBackup: Bool) {
    guard let data = value.data(using: .utf8) else { return }

    let accessibility: CFString = withBackup ? kSecAttrAccessibleAfterFirstUnlock : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: accessibility
    ]

    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
}

private func loadFromKeychain(_ key: String) -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess,
          let data = result as? Data,
          let string = String(data: data, encoding: .utf8) else {
        return nil
    }
    return string
}
