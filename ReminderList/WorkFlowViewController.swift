#if DEBUG || TESTFLIGHT
import Foundation
import UIKit
import CryptoKit

class WorkFlowViewController: UITableViewController {

    private var results: [String: WorkFlow] = [:]
    private var sortedPaths: [String] = []
    private var unexpectedPaths: [String] = []
    private var runtimePaths: [String] = []
    private var urlSchemePaths: [String] = []
    private var springboardPaths: [String] = []
    private var mainScore = ""
    
    private let searchController = UISearchController(searchResultsController: nil)
    private var isSearching: Bool {
        return !(searchController.searchBar.text?.isEmpty ?? true)
    }
    private var filteredPaths: [String] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Scan Results"
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")
        loadScanData()
        
        searchController.searchResultsUpdater = self
        searchController.obscuresBackgroundDuringPresentation = false
        searchController.searchBar.placeholder = "Search items"
        navigationItem.searchController = searchController
        definesPresentationContext = true
    }

    private func loadScanData() {
        let defaultResults = WorkFlowController.performDefaultScan()
        let runtimeResults = WorkFlowController.performRuntimeIntegrityScan()
        let urlSchemeResults = WorkFlowController.checkSuspiciousURLSchemes()
        results = defaultResults
            .merging(runtimeResults) { _, new in new }
            .merging(urlSchemeResults) { _, new in new }
        runtimePaths = Array(runtimeResults.keys).sorted()
        urlSchemePaths = Array(urlSchemeResults.keys).sorted()
        sortedPaths = defaultResults.keys.sorted()
        unexpectedPaths = results.filter { $0.value.work.isValid != $0.value.expectation }.map { $0.key }.sorted()
        // Add main score result
        WorkFlowController().executeIfSafe(scopes: [.all]) { level, score in
            print("Risk level: \(level.rawValue), score: \(score)")
            self.mainScore = "Risk level: \(level.rawValue)\nScore: \(score)"
        } action: {}
#if DEBUG
        let bundleIDResults = WorkFlowController.checkSpringBoardLaunchAccess()
        results.merge(bundleIDResults) { _, new in new }
        let bundleIDPaths = Array(bundleIDResults.keys).sorted()
        springboardPaths = bundleIDPaths
#else
        let sbPaths: [String] = []
        springboardPaths = []
#endif
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        return 7
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch section {
        case 0:
            return 1
        case 1:
            return 1
        case 2:
            return isSearching ? filteredPaths.filter { unexpectedPaths.contains($0) }.count : unexpectedPaths.count
        case 3:
            return isSearching ? filteredPaths.filter { runtimePaths.contains($0) }.count : runtimePaths.count
        case 4:
            return isSearching ? filteredPaths.filter { urlSchemePaths.contains($0) }.count : urlSchemePaths.count
        case 5:
            return isSearching ? filteredPaths.count : sortedPaths.count
        case 6:
            return isSearching ? filteredPaths.filter { springboardPaths.contains($0) }.count : springboardPaths.count
        default:
            return 0
        }
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch section {
        case 0:
            return "Info"
        case 1:
            return "Detection Records"
        case 2:
            return "Mismatched Results (\(unexpectedPaths.count))"
        case 3:
            return "Runtime Checks (\(runtimePaths.count))"
        case 4:
            return "URL Scheme Checks (\(urlSchemePaths.count))"
        case 5:
            return "All File Results (\(sortedPaths.count))"
        case 6:
            return "Bundle ID Checks (\(springboardPaths.count))"
        default:
            return nil
        }
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
        cell.selectionStyle = .none
        
        switch indexPath.section {
        case 0:
            let total = results.map { $0.value.score }.reduce(0, +)
            let average = total / Double(results.count)

            let version = UIDevice.current.systemVersion
            let screenSize = UIScreen.main.bounds.size
            let sceneCount = UIApplication.shared.connectedScenes.count
            cell.textLabel?.numberOfLines = 0
            cell.textLabel?.text = """
            System Version: \(version)
            Total Test Rule Count: \(urlSchemePaths.count + sortedPaths.count + springboardPaths.count + 11)
            Mismatched Count: \(unexpectedPaths.count)
            Total Score: \(String(format: "%.2f", total))
            Average Score: \(String(format: "%.2f", average))
            Scene Count: \(sceneCount) Screen Size: \(screenSize.width)x\(screenSize.height)
            Main score: \(String(format: "%.3f", Double(mainScore.components(separatedBy: "Score: ").last ?? "0") ?? 0))
            The final release version will not include this page.
            """ // Total Test Rule Count Fixed add 11 is runtime rule count, consistent across environments
        case 1:
            cell.textLabel?.numberOfLines = 0
            cell.textLabel?.text = displayStoredDetectionInfo()
            cell.selectionStyle = .default
        case 2:
            let groupPaths = unexpectedPaths
            let path = isSearching ? (filteredPaths.filter { groupPaths.contains($0) })[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText = result.work.isValid ? "✅" : "❌"
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Result: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                let indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                cell.textLabel?.text? += " \(indicator)"
            }
        case 3:
            let groupPaths = runtimePaths
            let path = isSearching ? (filteredPaths.filter { groupPaths.contains($0) })[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText = result.work.isValid ? "✅" : "❌"
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Result: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                let indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                cell.textLabel?.text? += " \(indicator)"
            }
        case 4:
            let groupPaths = urlSchemePaths
            let path = isSearching ? (filteredPaths.filter { groupPaths.contains($0) })[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText = result.work.isValid ? "✅" : "❌"
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Detected: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                let indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                cell.textLabel?.text? += " \(indicator)"
            }
        case 5:
            let groupPaths = sortedPaths
            let path = isSearching ? (filteredPaths)[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText = result.work.isValid ? "✅" : "❌"
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Exists: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                let indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                cell.textLabel?.text? += " \(indicator)"
            }
        case 6:
            let groupPaths = springboardPaths
            let path = isSearching ? (filteredPaths.filter { groupPaths.contains($0) })[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText: String
                if path.contains("Allowed") {
                    validText = result.work.isValid ? "✅" : "❌"
                } else {
                    validText = result.work.isValid ? "❌" : "✅"
                }
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Detected: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                var indicator: String
                if path.contains("Allowed") {
                    // This is a whitelist path, it should be detected (isValid == true) to be expected (expectation == true)
                    indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                } else {
                    // This is a blacklist path, it should NOT be detected (isValid == false) to be expected (expectation == false)
                    indicator = (result.work.isValid == result.expectation) ? "⚠️" : "☑️"
                }
                cell.textLabel?.text? += " \(indicator)"
            }
        default:
            break
        }

        return cell
    }

    // Allow reset for detection records
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        guard indexPath.section == 1 else { return }

        let alert = UIAlertController(title: "Reset Records", message: "Are you sure you want to clear detection logs?", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Confirm", style: .destructive) { _ in
            UserDefaults.standard.removeObject(forKey: "WorkStatus")
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "WorkStatus"
            ]
            SecItemDelete(query as CFDictionary)
            tableView.reloadData()
        })
        present(alert, animated: true)
    }
    
    // MARK: - Display stored detection info from Keychain and UserDefaults (multi-record, with severity)
    private func displayStoredDetectionInfo() -> String {
        var output = ""

        // Helper function to format a WorkRecordPayload
        func formatRecords(_ source: String, payload: WorkRecordPayload) -> String {
            var text = "[\(source)]\n"
            text += "Low Risk Attempts: \(payload.countLow), Medium: \(payload.countMedium), High: \(payload.countHigh)\n"
            let maxRecords = min(10, payload.records.count)
            for (index, record) in payload.records.prefix(maxRecords).enumerated() {
                text += "\(index + 1). [\(record.severity.rawValue.uppercased())] \(record.worktime): \(record.flowComment)\n"
            }
            return text + "\n"
        }

        let baseKey = "supersecretkeyforaesandhmac"
        let hashed = SHA256.hash(data: baseKey.data(using: .utf8)!)
        let symmetricKey = SymmetricKey(data: Data(hashed))

        // Decode from UserDefaults
        if let encodedData = UserDefaults.standard.string(forKey: "WorkStatus"),
           let decodedData = Data(base64Encoded: encodedData),
           decodedData.count > 32 {
            let sealedLength = decodedData.count - 32
            let combined = decodedData.prefix(sealedLength)
            if let sealedBox = try? AES.GCM.SealedBox(combined: combined),
               let decrypted = try? AES.GCM.open(sealedBox, using: symmetricKey),
               let payload = try? JSONDecoder().decode(WorkRecordPayload.self, from: decrypted) {
                output += formatRecords("UserDefaults Record", payload: payload)
            } else {
                output += "[UserDefaults Record] Failed to decode.\n"
            }
        } else {
            output += "[UserDefaults Record] No detection records found.\n"
        }

        // Decode from Keychain
        if let encodedData = loadFromKeychain("WorkStatus"),
           let decodedData = Data(base64Encoded: encodedData),
           decodedData.count > 32 {
            let sealedLength = decodedData.count - 32
            let combined = decodedData.prefix(sealedLength)
            if let sealedBox = try? AES.GCM.SealedBox(combined: combined),
               let decrypted = try? AES.GCM.open(sealedBox, using: symmetricKey),
               let payload = try? JSONDecoder().decode(WorkRecordPayload.self, from: decrypted) {
                output += formatRecords("Keychain Record", payload: payload)
            } else {
                output += "[Keychain Record] Failed to decode.\n"
            }
        } else {
            output += "[Keychain Record] No detection records found.\n"
        }

        return output
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
}

extension WorkFlowViewController: UISearchResultsUpdating {
    func updateSearchResults(for searchController: UISearchController) {
        let query = searchController.searchBar.text?.lowercased() ?? ""
        if query.isEmpty {
            filteredPaths = []
        } else {
            filteredPaths = results.keys.filter { $0.lowercased().contains(query) }.sorted()
        }
        tableView.reloadData()
    }
}
#endif
